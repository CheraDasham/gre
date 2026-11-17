#!/bin/bash
#
# Legendary GRE Tunnel Manager  (v1.1.3)
# IRAN <-> FOREIGN GRE tunnel with REAL CLIENT IP preservation.
#
# Copyright (C) 2026 Legendary
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Design notes:
#   * No catch-all DNAT. A blanket PREROUTING DNAT sends EVERY inbound packet
#     to the peer, which cuts SSH the moment the far side is not ready.
#     which cut SSH the moment the far side was not ready.
#   * No catch-all MASQUERADE. That rule is exactly why ip_limit on the
#     foreign side only ever saw the tunnel IP: it rewrote every client's
#     source address. Here the IRAN side does DNAT only, and the FOREIGN side
#     marks tunnel-originated connections (CONNMARK) and sends their replies
#     back through the tunnel via a policy route, so the real client IP
#     survives end to end.
#   * No blanket "DROP icmp". It broke ping through the tunnel for no gain.
#   * Everything is re-applied from one state file by one systemd unit, so a
#     reboot restores the tunnel, sysctls, routing and port-forwards together.
#     No dependency on iptables-persistent.
#   * Every rule carries a comment tag, so removal is exact and complete.
#
set -Eeuo pipefail

VERSION="1.1.3"

trap 'rc=$?; echo; echo "[!] ERROR (exit $rc) at line $LINENO: $BASH_COMMAND" >&2' ERR

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

if [ ! -t 0 ]; then
    echo "This script is interactive and needs a terminal."
    echo "Use:  bash <(curl -sSL <url>)   -- not:  curl ... | bash"
    exit 1
fi

BASE_DIR="/etc/legendary-gre"
STATE_FILE="$BASE_DIR/state"
PF_DB="$BASE_DIR/portforwards.db"

UP_SCRIPT="/usr/local/sbin/legendary-gre-up.sh"
DOWN_SCRIPT="/usr/local/sbin/legendary-gre-down.sh"
SERVICE_NAME="legendary-gre.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"

TAG_PREFIX="LEGENDARY_GRE_"
SYS_TAG="${TAG_PREFIX}SYS"
PF_TAG="${TAG_PREFIX}PF"

# Stamped into the generated helper scripts so a newer legendary-gre.sh can
# tell that the ones on disk were written by an older version. Without this,
# upgrading the script leaves stale helpers in /usr/local/sbin that keep
# running the old logic -- and the symptoms show up far from the cause.
HELPER_STAMP="# LEGENDARY_GRE_HELPER_VERSION=$VERSION"

DEFAULT_TUN_NAME="legend0"
DEFAULT_TUN_NET="10.10.10.0/30"
DEFAULT_MTU="1476"

mkdir -p "$BASE_DIR"
chmod 700 "$BASE_DIR"
touch "$PF_DB"
chmod 600 "$PF_DB"

# ---------------------------------------------------------------- helpers ---

pause() { echo; read -rp "Press Enter to continue..." _ || true; }

# Menu input, cleaned up before it is matched. A stray carriage return (some
# SSH clients and pastes send CRLF) or a leading/trailing space makes an
# otherwise valid "1" fall through to the invalid branch, which looks like the
# menu ignoring a correct answer.
read_choice() {
    local prompt="$1" __var="$2" ans
    if ! read -rp "$prompt" ans; then
        echo
        echo "No more input - exiting."
        exit 0
    fi
    ans="${ans//$'\r'/}"
    ans="${ans//$'\t'/}"
    ans="${ans## }"; ans="${ans%% }"
    ans="${ans#"${ans%%[![:space:]]*}"}"
    ans="${ans%"${ans##*[![:space:]]}"}"
    printf -v "$__var" '%s' "$ans"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

install_if_missing() {
    local pkg="$1" cmd="$2"
    have_cmd "$cmd" && return 0
    echo "[+] Installing $pkg..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    if ! apt-get install -y "$pkg" >/dev/null; then
        echo "[!] Could not install $pkg. Install it manually and retry."
        return 1
    fi
    return 0
}

load_state() {
    # Clear first. Sourcing only sets what the file contains, so without this
    # the values from a previous load survive after the state file is deleted
    # -- the menu then keeps advertising a tunnel that no longer exists, and
    # functions that gate on "$SIDE" or "$TUN_NAME" act on a removed setup.
    SIDE=""; TUN_NAME=""; LOCAL_IP=""; REMOTE_IP=""
    TUN_LOCAL_IP=""; TUN_PEER_IP=""; TUN_LOCAL_CIDR=""
    MTU=""; EXTRA_PUBLIC_IPS=""

    if [ -f "$STATE_FILE" ]; then
        # shellcheck disable=SC1090
        . "$STATE_FILE"
    fi
    return 0
}

valid_ip() {
    local ip="${1:-}" part
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra part <<< "$ip"
    for p in "${part[@]}"; do
        [ "$p" -le 255 ] || return 1
    done
    return 0
}

valid_port() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

detect_local_ip() {
    ip route get 8.8.8.8 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true
}

ip_is_local() {
    ip -4 -o addr show 2>/dev/null | awk '{split($4,a,"/"); print a[1]}' | grep -qx "$1"
}

# The public entry-point addresses of this server: the addresses on whichever
# interface carries the default route, plus anything in EXTRA_PUBLIC_IPS. That
# excludes docker bridges, other tunnels and private ranges by construction.
#
# This has to exist here as well as inside the generated up-script. The two
# must agree, because this one builds the list the operator picks from and
# that one builds the rules from the picked value.
public_ips() {
    local wan
    wan="$(ip route show default 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    {
        if [ -n "$wan" ]; then
            ip -4 -o addr show dev "$wan" scope global 2>/dev/null | \
                awk '{split($4,a,"/"); print a[1]}'
        fi
        if [ -n "${EXTRA_PUBLIC_IPS:-}" ]; then
            printf '%s\n' $EXTRA_PUBLIC_IPS
        fi
    } | awk 'NF && !seen[$0]++'
    return 0
}

# Remove every iptables rule whose comment starts with the given tag.
# Parsed per table so the -D lands in the right table, and eval'd so the
# quoting around the comment value survives (an unquoted expansion here
# passes the quote characters through literally and matches nothing).
remove_tagged_rules() {
    local tag="$1" table rules
    for table in filter nat mangle raw; do
        # Collected first, on purpose. Piping straight into the loop makes the
        # whole pipeline fail (pipefail) on any table with no matching rules,
        # which under "set -e" would abort before the later tables are reached.
        rules="$( ( iptables-save -t "$table" 2>/dev/null || true ) \
                  | grep -- "--comment \"$tag" \
                  | sed -e 's/^-A /-D /' || true )"
        [ -n "$rules" ] || continue
        while IFS= read -r rule; do
            [ -n "$rule" ] || continue
            # eval, so the quoting around the comment value is parsed by the
            # shell instead of being passed through as literal characters
            # (that is why a plain "iptables $rule" never matches anything).
            eval "iptables -t $table $rule" 2>/dev/null || true
        done <<< "$rules"
    done
    return 0
}

# ------------------------------------------------------------- up script ---

write_up_script() {
    # Shebang first, then the version stamp, then the body. The stamp is what
    # lets a newer legendary-gre.sh notice that the helper on disk is stale.
    cat > "$UP_SCRIPT" <<UPSTAMP
#!/bin/bash
$HELPER_STAMP
UPSTAMP
    cat >> "$UP_SCRIPT" <<'UPEOF'
# Applied at boot and after every config change by legendary-gre.sh.
# Fully idempotent: safe to run any number of times.
# Deliberately NOT "set -e" -- one failing rule must not skip the rest.
set -uo pipefail

BASE_DIR="/etc/legendary-gre"
STATE_FILE="$BASE_DIR/state"
PF_DB="$BASE_DIR/portforwards.db"
SYS_TAG="LEGENDARY_GRE_SYS"
PF_TAG="LEGENDARY_GRE_PF"
MARK="0x1"
RT_TABLE="100"

[ -f "$STATE_FILE" ] || { echo "[legendary-gre] no state file, nothing to do"; exit 0; }
# shellcheck disable=SC1090
. "$STATE_FILE"

log() { echo "[legendary-gre] $*"; }

# idempotent append:  ipt <table> <chain> <rule...>
ipt() {
    local table="$1"; shift
    local chain="$1"; shift
    iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -A "$chain" "$@"
}

set_proc() { [ -w "$1" ] && echo "$2" > "$1"; return 0; }

# Public entry-point addresses of this box = addresses on the default-route
# interface. Never docker0, never another tunnel, never a private range that
# clients cannot reach.
public_ips() {
    local wan
    wan="$(ip route show default 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    {
        if [ -n "$wan" ]; then
            ip -4 -o addr show dev "$wan" scope global 2>/dev/null | \
                awk '{split($4,a,"/"); print a[1]}'
        fi
        if [ -n "${EXTRA_PUBLIC_IPS:-}" ]; then
            printf '%s\n' $EXTRA_PUBLIC_IPS
        fi
    } | awk 'NF && !seen[$0]++'
    return 0
}

modprobe ip_gre 2>/dev/null || true

# ------------------------------------------------------------------ tunnel --
if ip link show "$TUN_NAME" >/dev/null 2>&1; then
    # change in place so the interface (and anything using it) is not torn down
    ip tunnel change "$TUN_NAME" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255 2>/dev/null || {
        ip tunnel del "$TUN_NAME" 2>/dev/null
        ip tunnel add "$TUN_NAME" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
    }
else
    ip tunnel add "$TUN_NAME" mode gre local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255
fi

# The kernel keys GRE tunnels on (local, remote, key) -- NOT on the interface
# name. If another GRE tunnel already uses this exact pair of endpoints, the
# add fails with EEXIST and, confusingly, reports the fallback device "gre0"
# rather than the name that was asked for. Everything after that would fail
# with "Cannot find device", so stop here instead of claiming success.
if ! ip link show "$TUN_NAME" >/dev/null 2>&1; then
    echo "[legendary-gre] ERROR: interface $TUN_NAME was not created." >&2
    echo >&2
    echo "  Most likely another GRE tunnel already uses the same endpoints" >&2
    echo "  ($LOCAL_IP -> $REMOTE_IP). The kernel allows only one GRE tunnel" >&2
    echo "  per local/remote pair, whatever the interface is called." >&2
    echo >&2
    echo "  Existing GRE tunnels on this server:" >&2
    ip -d tunnel show 2>/dev/null | grep -i 'gre' | sed 's/^/    /' >&2 || true
    echo >&2
    echo "  Delete the conflicting one, then run this again:" >&2
    echo "    ip tunnel del <name>" >&2
    exit 1
fi

ip link set "$TUN_NAME" mtu "$MTU" 2>/dev/null || true
ip link set "$TUN_NAME" txqueuelen 2000 2>/dev/null || true
ip link set "$TUN_NAME" up
ip addr replace "$TUN_LOCAL_CIDR" dev "$TUN_NAME"

# ------------------------------------------------------------------ sysctl --
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
# Loose reverse-path (2), not 0: still filters spoofing, but does not drop the
# real client source addresses arriving on the tunnel.
set_proc /proc/sys/net/ipv4/conf/all/rp_filter 2
set_proc /proc/sys/net/ipv4/conf/default/rp_filter 2
set_proc "/proc/sys/net/ipv4/conf/$TUN_NAME/rp_filter" 2
WAN_IF="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[ -n "$WAN_IF" ] && set_proc "/proc/sys/net/ipv4/conf/$WAN_IF/rp_filter" 2

# ------------------------------------------------------------- base rules --
# GRE (IP protocol 47) from the peer only.
ipt filter INPUT -p gre -s "$REMOTE_IP" -m comment --comment "$SYS_TAG" -j ACCEPT

# Clamp MSS so forwarded TCP fits the tunnel MTU without fragmenting.
ipt mangle FORWARD -o "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN \
    -m comment --comment "$SYS_TAG" -j TCPMSS --clamp-mss-to-pmtu
ipt mangle FORWARD -i "$TUN_NAME" -p tcp --tcp-flags SYN,RST SYN \
    -m comment --comment "$SYS_TAG" -j TCPMSS --clamp-mss-to-pmtu

# ------------------------------------------------- FOREIGN: return routing --
if [ "${SIDE:-}" = "FOREIGN" ]; then
    # Traffic arrives over the tunnel carrying the REAL client source IP.
    # Without this, replies would leave via the default route straight to the
    # client and be dropped as unsolicited. Mark the connection on arrival,
    # restore the mark on the reply, and policy-route it back into the tunnel.
    # Masked marks (0x1/0x1) leave other users of fwmark (WireGuard) alone.
    ipt mangle PREROUTING -i "$TUN_NAME" -m conntrack --ctstate NEW \
        -m comment --comment "$SYS_TAG" -j CONNMARK --set-mark "$MARK/$MARK"
    ipt mangle PREROUTING -m comment --comment "$SYS_TAG" \
        -j CONNMARK --restore-mark --nfmask "$MARK" --ctmask "$MARK"
    ipt mangle OUTPUT -m comment --comment "$SYS_TAG" \
        -j CONNMARK --restore-mark --nfmask "$MARK" --ctmask "$MARK"

    ip rule show 2>/dev/null | grep -q "fwmark $MARK.*lookup $RT_TABLE" \
        || ip rule add fwmark "$MARK/$MARK" lookup "$RT_TABLE"
    ip route replace default via "$TUN_PEER_IP" dev "$TUN_NAME" table "$RT_TABLE"

    log "FOREIGN side ready: $TUN_NAME up, return routing via table $RT_TABLE"
fi

# ------------------------------------------------- IRAN: port forwarding ----
if [ "${SIDE:-}" = "IRAN" ]; then
    if [ -s "$PF_DB" ]; then
        # Record format: proto|public_port|target_port|bind_ip
        # bind_ip empty  -> publish on every public address of this server
        # bind_ip set    -> publish ONLY on that address
        # Entries written by older versions have three fields; bind_ip then
        # reads as empty, which is the old "all addresses" behaviour.
        while IFS='|' read -r proto lport tport bindip; do
            [ -n "${proto:-}" ] || continue
            bindip="${bindip:-}"
            marker="${PF_TAG}:${proto}:${lport}:${tport}:${bindip:-all}"

            if [ -n "$bindip" ]; then
                ip_list="$bindip"
            else
                ip_list="$(public_ips)"
            fi

            while IFS= read -r pubip; do
                [ -n "$pubip" ] || continue
                # DNAT only. No SNAT/MASQUERADE here -- that is what keeps the
                # client's real source address intact for the foreign server.
                ipt nat PREROUTING -d "$pubip" -p "$proto" --dport "$lport" \
                    -m comment --comment "$marker" \
                    -j DNAT --to-destination "${TUN_PEER_IP}:${tport}"
            done <<< "$ip_list"

            ipt filter FORWARD -o "$TUN_NAME" -p "$proto" -d "$TUN_PEER_IP" --dport "$tport" \
                -m conntrack --ctstate NEW,ESTABLISHED,RELATED \
                -m comment --comment "$marker" -j ACCEPT
            ipt filter FORWARD -i "$TUN_NAME" -p "$proto" -s "$TUN_PEER_IP" \
                -m conntrack --ctstate ESTABLISHED,RELATED \
                -m comment --comment "$marker" -j ACCEPT
        done < "$PF_DB"
    fi
    log "IRAN side ready: $TUN_NAME up, $(wc -l < "$PF_DB") port-forward entries"
fi

exit 0
UPEOF
    chmod 700 "$UP_SCRIPT"
}

write_down_script() {
    cat > "$DOWN_SCRIPT" <<DOWNSTAMP
#!/bin/bash
$HELPER_STAMP
DOWNSTAMP
    cat >> "$DOWN_SCRIPT" <<'DOWNEOF'
# Tears the tunnel down. Run by "systemctl stop legendary-gre".
set -uo pipefail

BASE_DIR="/etc/legendary-gre"
STATE_FILE="$BASE_DIR/state"
RT_TABLE="100"
MARK="0x1"

[ -f "$STATE_FILE" ] || exit 0
# shellcheck disable=SC1090
. "$STATE_FILE"

for table in filter nat mangle raw; do
    ( iptables-save -t "$table" 2>/dev/null || true ) \
    | grep -- '--comment "LEGENDARY_GRE_' \
    | sed -e 's/^-A /-D /' \
    | while IFS= read -r rule; do
        eval "iptables -t $table $rule" 2>/dev/null || true
      done
done

# Bounded on purpose. An unbounded "while grep; do del; done" spins forever if
# the delete ever reports success without removing what the grep matched --
# which is a real risk on a box where something else (WireGuard) also uses
# fwmark rules.
for _ in 1 2 3 4 5 6 7 8; do
    ip rule show 2>/dev/null | grep -q "fwmark $MARK.*lookup $RT_TABLE" || break
    ip rule del fwmark "$MARK/$MARK" lookup "$RT_TABLE" 2>/dev/null || break
done
ip route flush table "$RT_TABLE" 2>/dev/null || true

ip tunnel del "$TUN_NAME" 2>/dev/null || ip link del "$TUN_NAME" 2>/dev/null || true
exit 0
DOWNEOF
    chmod 700 "$DOWN_SCRIPT"
}

write_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Legendary GRE Tunnel (real client IP preserving)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$UP_SCRIPT
ExecStop=-$DOWN_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

save_state() {
    cat > "$STATE_FILE" <<EOF
SIDE="$SIDE"
TUN_NAME="$TUN_NAME"
LOCAL_IP="$LOCAL_IP"
REMOTE_IP="$REMOTE_IP"
TUN_LOCAL_IP="$TUN_LOCAL_IP"
TUN_PEER_IP="$TUN_PEER_IP"
TUN_LOCAL_CIDR="$TUN_LOCAL_IP/30"
MTU="$MTU"
EXTRA_PUBLIC_IPS="${EXTRA_PUBLIC_IPS:-}"
EOF
    chmod 600 "$STATE_FILE"
}

# ------------------------------------------------------------ create flow ---

create_tunnel() {
    local detected role iran_ip foreign_ip tun_net base o1 o2 o3 o4 mtu_in extra

    echo
    echo "================================================"
    echo "            Create / Reconfigure"
    echo "================================================"
    echo "1) IRAN server    (clients connect here)"
    echo "2) FOREIGN server (traffic exits here)"
    read_choice "Select server role [1/2]: " role
    case "$role" in
        1) SIDE="IRAN" ;;
        2) SIDE="FOREIGN" ;;
        *) echo "Invalid role."; return 0 ;;
    esac

    detected="$(detect_local_ip)"
    echo
    [ -n "$detected" ] && echo "Detected public IP of this server: $detected"

    read_choice "Enter IRAN server public IP: " iran_ip
    valid_ip "$iran_ip" || { echo "Invalid IP."; return 0; }
    read_choice "Enter FOREIGN server public IP: " foreign_ip
    valid_ip "$foreign_ip" || { echo "Invalid IP."; return 0; }

    if [ "$SIDE" = "IRAN" ]; then
        LOCAL_IP="$iran_ip"; REMOTE_IP="$foreign_ip"
    else
        LOCAL_IP="$foreign_ip"; REMOTE_IP="$iran_ip"
    fi

    # Catches the classic typo: an address that is not actually on this box
    # produces a tunnel that comes up fine and never passes a packet.
    if ! ip_is_local "$LOCAL_IP"; then
        echo
        echo "[!] $LOCAL_IP is NOT configured on any interface of this server."
        [ -n "$detected" ] && echo "    This server appears to be $detected."
        read_choice "Continue anyway? [y/N]: " yn
        [[ "${yn:-N}" =~ ^[Yy]$ ]] || { echo "Aborted."; return 0; }
    fi

    echo
    read_choice "Tunnel subnet [$DEFAULT_TUN_NET]: " tun_net
    tun_net="${tun_net:-$DEFAULT_TUN_NET}"
    base="${tun_net%%/*}"
    valid_ip "$base" || { echo "Invalid subnet."; return 0; }
    IFS='.' read -r o1 o2 o3 o4 <<< "$base"
    if [ "$o4" != "0" ]; then
        echo "Give the network address of a /30, e.g. 10.10.10.0/30"
        return 0
    fi
    # FOREIGN takes .1 and IRAN takes .2 (same convention as the original).
    if [ "$SIDE" = "IRAN" ]; then
        TUN_LOCAL_IP="$o1.$o2.$o3.2"; TUN_PEER_IP="$o1.$o2.$o3.1"
    else
        TUN_LOCAL_IP="$o1.$o2.$o3.1"; TUN_PEER_IP="$o1.$o2.$o3.2"
    fi

    read_choice "Tunnel interface name [$DEFAULT_TUN_NAME]: " TUN_NAME
    TUN_NAME="${TUN_NAME:-$DEFAULT_TUN_NAME}"

    read_choice "Tunnel MTU [$DEFAULT_MTU]: " mtu_in
    MTU="${mtu_in:-$DEFAULT_MTU}"
    [[ "$MTU" =~ ^[0-9]+$ ]] && [ "$MTU" -ge 576 ] && [ "$MTU" -le 9000 ] \
        || { echo "Invalid MTU."; return 0; }

    EXTRA_PUBLIC_IPS=""
    if [ "$SIDE" = "IRAN" ]; then
        echo
        echo "Port-forwards are published on every address of the default-route"
        echo "interface. Add extra addresses here only if this server has a routed"
        echo "IP that does not show up in 'ip addr' (space separated, or leave empty)."
        read_choice "Extra public IPs []: " extra
        EXTRA_PUBLIC_IPS="$extra"
    fi

    # A GRE tunnel is identified by its endpoints, not its name. Another tunnel
    # on the same local/remote pair -- typically one left over from a different
    # script -- makes the kernel refuse this one with EEXIST. Catch it here,
    # while it is still cheap to fix.
    local conflict yn2
    conflict="$(ip -d tunnel show 2>/dev/null \
        | grep -i 'gre' \
        | grep -F "remote $REMOTE_IP" \
        | grep -F "local $LOCAL_IP" \
        | grep -v "^${TUN_NAME}:" || true)"
    if [ -n "$conflict" ]; then
        echo
        echo "[!] Another GRE tunnel already uses these endpoints:"
        printf '      %s\n' "$conflict"
        echo "    The kernel allows only one GRE tunnel per local/remote pair,"
        echo "    so this one cannot be created until that one is gone."
        echo
        read_choice "Delete the conflicting tunnel now? [y/N]: " yn2
        if [[ "${yn2:-N}" =~ ^[Yy]$ ]]; then
            printf '%s\n' "$conflict" | awk -F: '{print $1}' | while read -r old; do
                [ -n "$old" ] || continue
                echo "    removing $old"
                ip tunnel del "$old" 2>/dev/null || ip link del "$old" 2>/dev/null || true
            done
        else
            echo "Aborted. Remove it yourself with:  ip tunnel del <name>"
            return 0
        fi
    fi

    save_state
    write_up_script
    write_down_script
    write_service

    echo
    if "$UP_SCRIPT"; then
        systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
        # Mark the unit active without re-running it, so state matches reality.
        systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
        echo
        echo "================================================"
        echo "                   Configured"
        echo "================================================"
        echo "Role        : $SIDE"
        echo "Interface   : $TUN_NAME  (MTU $MTU)"
        echo "Local  WAN  : $LOCAL_IP"
        echo "Remote WAN  : $REMOTE_IP"
        echo "Tunnel IP   : $TUN_LOCAL_IP   peer: $TUN_PEER_IP"
        echo "Persistence : enabled ($SERVICE_NAME)"
        echo "Real IP     : $([ "$SIDE" = "FOREIGN" ] && echo "return routing active" || echo "no SNAT, client IP preserved")"
        echo
        echo "Run the same script on the other server with the other role."
        echo "Then test:  ping -c4 $TUN_PEER_IP"
    else
        echo "[!] Setup script failed. Nothing was enabled. See the error above."
    fi
}

# ---------------------------------------------------------------- status ---

show_status() {
    load_state
    echo
    echo "================ Tunnel ==========================="
    if [ -n "${TUN_NAME:-}" ] && ip link show "$TUN_NAME" >/dev/null 2>&1; then
        ip -d link show "$TUN_NAME" | sed -n '1,3p'
        ip -br addr show "$TUN_NAME"
    else
        echo "No managed tunnel interface is up."
    fi

    echo
    echo "================ Saved config ====================="
    [ -f "$STATE_FILE" ] && cat "$STATE_FILE" || echo "No saved state."

    echo
    echo "================ Service =========================="
    if [ -f "$SERVICE_FILE" ]; then
        echo "enabled : $(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo no)"
        echo "active  : $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo no)"
        echo "(oneshot units correctly report 'active (exited)')"
    else
        echo "Not installed."
    fi

    echo
    echo "================ Managed rules ===================="
    ( iptables-save 2>/dev/null || true ) | grep -- "--comment \"$TAG_PREFIX" \
        || echo "No managed rules."

    if [ "${SIDE:-}" = "FOREIGN" ]; then
        echo
        echo "================ Return routing ==================="
        ip rule show 2>/dev/null | grep "lookup 100" || echo "No fwmark rule."
        ip route show table 100 2>/dev/null || echo "Table 100 empty."
    fi
}

# -------------------------------------------------------------- diagnose ---

diagnose() {
    load_state
    local ok="  [ OK ]" bad="  [FAIL]" warn="  [WARN]"

    if [ -z "${TUN_NAME:-}" ]; then
        echo "No saved state. Run option 1 first."
        return 0
    fi

    echo
    echo "================ Diagnostics ======================"

    if ip link show "$TUN_NAME" >/dev/null 2>&1; then
        echo "$ok tunnel interface $TUN_NAME exists"
        ip -d link show "$TUN_NAME" | grep -q "remote $REMOTE_IP" \
            && echo "$ok remote endpoint is $REMOTE_IP" \
            || echo "$bad remote endpoint does NOT match $REMOTE_IP"
        ip -4 -o addr show "$TUN_NAME" | grep -q "$TUN_LOCAL_IP" \
            && echo "$ok tunnel address $TUN_LOCAL_IP assigned" \
            || echo "$bad tunnel address $TUN_LOCAL_IP missing"
    else
        echo "$bad tunnel interface $TUN_NAME does not exist"
    fi

    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
        echo "$ok ip_forward enabled"
    else
        echo "$bad ip_forward disabled"
    fi

    local rpf
    rpf="$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo ?)"
    [ "$rpf" = "1" ] \
        && echo "$warn rp_filter=1 (strict) -- can drop real client IPs; 2 is wanted" \
        || echo "$ok rp_filter=$rpf on all"

    # The two rules that historically broke things.
    if ( iptables-save -t nat 2>/dev/null || true ) | grep -q '^-A POSTROUTING -j MASQUERADE$'; then
        echo "$bad catch-all MASQUERADE present -- this REWRITES every client IP"
        echo "       remove with: iptables -t nat -D POSTROUTING -j MASQUERADE"
    else
        echo "$ok no catch-all MASQUERADE"
    fi
    if ( iptables-save -t nat 2>/dev/null || true ) | grep -qE '^-A PREROUTING -j DNAT'; then
        echo "$bad catch-all DNAT present -- redirects ALL inbound traffic (can cut SSH)"
    else
        echo "$ok no catch-all DNAT"
    fi
    if ( iptables-save -t filter 2>/dev/null || true ) | grep -qE '^-A INPUT -p icmp -j DROP$'; then
        echo "$warn blanket 'DROP icmp' present -- ping through the tunnel will fail"
    fi

    if [ "${SIDE:-}" = "FOREIGN" ]; then
        ip rule show 2>/dev/null | grep -q "lookup 100" \
            && echo "$ok fwmark policy rule present" \
            || echo "$bad fwmark policy rule MISSING -- replies will not return via tunnel"
        ip route show table 100 2>/dev/null | grep -q "default" \
            && echo "$ok route table 100 has a default via the tunnel" \
            || echo "$bad route table 100 has no default route"
        ( iptables-save -t mangle 2>/dev/null || true ) | grep -q "CONNMARK --set-xmark\|CONNMARK --save-mark\|--set-mark" \
            && echo "$ok CONNMARK marking rules present" \
            || echo "$bad CONNMARK rules missing"
    fi

    if [ "${SIDE:-}" = "IRAN" ]; then
        local n
        # note the space after $( : "$((" would start an arithmetic expansion
        n="$( ( iptables-save -t nat 2>/dev/null || true ) | grep -c "\"$PF_TAG" || true )"
        echo "$ok $n port-forward DNAT rules installed"
    fi

    echo
    echo "---- peer reachability ----"
    if ping -c 2 -W 2 "$TUN_PEER_IP" >/dev/null 2>&1; then
        echo "$ok peer $TUN_PEER_IP answers ping"
    else
        echo "$warn peer $TUN_PEER_IP does not answer ping"
        echo "       Either the other side is not configured yet, or GRE"
        echo "       (IP protocol 47) is blocked by the provider firewall,"
        echo "       or the peer drops ICMP. Try a TCP test instead:"
        echo "         nc -zv $TUN_PEER_IP 22"
    fi

    echo
    echo "---- load ----"
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
        echo "conntrack: $(cat /proc/sys/net/netfilter/nf_conntrack_count)/$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
    fi
}

# ---------------------------------------------------------- port forwards ---

list_port_forwards() {
    load_state
    echo
    echo "================ Saved port forwards =============="
    if [ -s "$PF_DB" ]; then
        printf "%-4s %-8s %-14s %-14s %s\n" "#" "Proto" "Public port" "Target port" "Bound to"
        local i=0
        while IFS='|' read -r proto lport tport bindip; do
            [ -n "${proto:-}" ] || continue
            i=$((i + 1))
            printf "%-4s %-8s %-14s %-14s %s\n" \
                "$i" "$proto" "$lport" "$tport" "${bindip:-all public IPs}"
        done < "$PF_DB"
    else
        echo "None."
    fi
    echo
    echo "================ Active rules ====================="
    ( iptables-save 2>/dev/null || true ) | grep -- "--comment \"$PF_TAG" \
        || echo "None active."
}

add_port_forward() {
    load_state
    if [ "${SIDE:-}" != "IRAN" ]; then
        echo "Port forwards are configured on the IRAN server."
        return 0
    fi
    if ! ip link show "${TUN_NAME:-none}" >/dev/null 2>&1; then
        echo "Tunnel is not up."
        return 0
    fi

    local lport tport proto_sel bindip ip_sel n
    echo
    read_choice "Public port on the IRAN server: " lport
    valid_port "$lport" || { echo "Invalid port."; return 0; }

    if [ "$lport" = "22" ]; then
        echo "[!] Forwarding port 22 will send your SSH to the other server."
        read_choice "    Really do that? [y/N]: " yn
        [[ "${yn:-N}" =~ ^[Yy]$ ]] || return 0
    fi

    read_choice "Destination port on the FOREIGN server [$lport]: " tport
    tport="${tport:-$lport}"
    valid_port "$tport" || { echo "Invalid port."; return 0; }

    echo
    echo "1) TCP    2) UDP    3) TCP + UDP"
    read_choice "Protocol [1-3]: " proto_sel

    local -a protos=()
    case "$proto_sel" in
        1) protos=(tcp) ;;
        2) protos=(udp) ;;
        3) protos=(tcp udp) ;;
        *) echo "Invalid selection."; return 0 ;;
    esac

    # Which address should answer on this port. With several addresses on the
    # server you usually want the forward on exactly one of them, so the others
    # stay free for whatever else is listening there.
    local -a ips=()
    while IFS= read -r line; do
        [ -n "$line" ] && ips+=("$line")
    done < <(public_ips)

    bindip=""
    if [ "${#ips[@]}" -eq 0 ]; then
        echo
        echo "[!] Could not read this server's public addresses, so there is"
        echo "    nothing to choose from. The forward will be published on"
        echo "    every public address. Check 'ip route show default'."
    elif [ "${#ips[@]}" -gt 1 ]; then
        echo
        echo "This server has more than one public address."
        echo "  0) all of them"
        n=0
        for a in "${ips[@]}"; do
            n=$((n + 1))
            echo "  $n) $a"
        done
        read_choice "Publish this forward on [0-$n, default 0]: " ip_sel
        ip_sel="${ip_sel:-0}"
        if [ "$ip_sel" != "0" ]; then
            if [[ "$ip_sel" =~ ^[0-9]+$ ]] && [ "$ip_sel" -ge 1 ] && [ "$ip_sel" -le "$n" ]; then
                bindip="${ips[$((ip_sel - 1))]}"
            else
                echo "Invalid selection."
                return 0
            fi
        fi
    fi

    local p
    for p in "${protos[@]}"; do
        grep -Fxq "${p}|${lport}|${tport}|${bindip}" "$PF_DB" \
            || echo "${p}|${lport}|${tport}|${bindip}" >> "$PF_DB"
    done

    "$UP_SCRIPT" >/dev/null
    echo
    echo "[+] Forwarding ${protos[*]} ${lport} -> ${TUN_PEER_IP}:${tport}"
    if [ -n "$bindip" ]; then
        echo "[i] Published on $bindip only. Other addresses of this server are untouched."
    else
        echo "[i] Published on every public address of this server."
    fi
    echo "[i] No SNAT is applied, so the foreign server sees the real client IP."
    echo "[i] Make sure the FOREIGN server is listening on port ${tport}."
}

delete_port_forward() {
    load_state
    list_port_forwards
    echo
    local sel tmp total
    total="$(grep -c . "$PF_DB" 2>/dev/null || echo 0)"
    if [ "$total" -eq 0 ]; then
        echo "Nothing to remove."
        return 0
    fi

    # Deleting by line number, not by port: the same port can now be published
    # on two different addresses, so a port alone is no longer unique.
    read_choice "Entry number to remove [1-$total]: " sel
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "$total" ]; then
        echo "Invalid entry number."
        return 0
    fi

    tmp="$(mktemp)"
    awk -v n="$sel" 'NF { c++ } c != n || !NF' "$PF_DB" > "$tmp"
    mv "$tmp" "$PF_DB"
    chmod 600 "$PF_DB"

    # Drop every managed forward rule, then re-apply what remains.
    remove_tagged_rules "$PF_TAG"
    "$UP_SCRIPT" >/dev/null
    echo "[+] Removed entry $sel."
}

remove_all_port_forwards() {
    remove_tagged_rules "$PF_TAG"
    : > "$PF_DB"
    echo "[+] All port forwards removed."
}

port_forward_menu() {
    while true; do
        echo
        echo "================================================"
        echo "              Port Forward Manager"
        echo "================================================"
        echo "1) Add port forward"
        echo "2) List"
        echo "3) Delete one"
        echo "4) Remove all"
        echo "0) Back"
        echo
        read_choice "Select [0-4]: " sel
        case "$sel" in
            1) add_port_forward || true; pause ;;
            2) list_port_forwards || true; pause ;;
            3) delete_port_forward || true; pause ;;
            4) remove_all_port_forwards || true; pause ;;
            0) return 0 ;;
            "") echo "Nothing entered." ;;
            *) printf 'Invalid selection: %q\n' "$sel" ;;
        esac
    done
}

# ------------------------------------------------------------ mtu / speed ---

tools_menu() {
    load_state
    if [ -z "${TUN_NAME:-}" ] || ! ip link show "$TUN_NAME" >/dev/null 2>&1; then
        echo "Tunnel is not up."
        return 0
    fi

    echo
    echo "1) Set MTU manually"
    echo "2) Auto MTU scan"
    echo "3) Start iperf3 server (run this on the peer first)"
    echo "4) Speed test to peer"
    read_choice "Select [1-4]: " sel

    case "$sel" in
        1)
            local m
            read_choice "New MTU: " m
            [[ "$m" =~ ^[0-9]+$ ]] && [ "$m" -ge 576 ] && [ "$m" -le 9000 ] \
                || { echo "Invalid MTU."; return 0; }
            ip link set "$TUN_NAME" mtu "$m"
            sed -i "s/^MTU=.*/MTU=\"$m\"/" "$STATE_FILE"
            echo "[+] MTU set to $m and saved."
            ;;
        2)
            install_if_missing iputils-ping ping || return 0
            local best="" payload
            echo
            printf "%-8s %s\n" "MTU" "Result"
            for m in 1476 1460 1440 1420 1400 1380 1360 1320 1280; do
                ip link set "$TUN_NAME" mtu "$m" 2>/dev/null || continue
                payload=$((m - 28))
                if ping -I "$TUN_NAME" -M do -c 3 -W 1 -s "$payload" "$TUN_PEER_IP" >/dev/null 2>&1; then
                    printf "%-8s %s\n" "$m" "OK"
                    [ -z "$best" ] && best="$m"
                else
                    printf "%-8s %s\n" "$m" "fail"
                fi
            done
            if [ -n "$best" ]; then
                ip link set "$TUN_NAME" mtu "$best"
                sed -i "s/^MTU=.*/MTU=\"$best\"/" "$STATE_FILE"
                echo
                echo "[+] Best MTU: $best (applied and saved)"
            else
                echo
                echo "[!] No MTU passed. Is the peer up?"
                ip link set "$TUN_NAME" mtu "${MTU:-1476}" 2>/dev/null || true
            fi
            ;;
        3)
            install_if_missing iperf3 iperf3 || return 0
            pkill -x iperf3 >/dev/null 2>&1 || true
            iperf3 -s -D -B "$TUN_LOCAL_IP"
            echo "[+] iperf3 listening on $TUN_LOCAL_IP:5201"
            ;;
        4)
            install_if_missing iperf3 iperf3 || return 0
            echo "The peer must be running option 3 first."
            echo
            echo "---- forward ----"
            iperf3 -c "$TUN_PEER_IP" -t 10 -P 4 || true
            echo
            echo "---- reverse ----"
            iperf3 -c "$TUN_PEER_IP" -t 10 -P 4 -R || true
            ;;
        *) echo "Invalid selection." ;;
    esac
}

# ----------------------------------------------------------------- remove ---

remove_everything() {
    echo
    read_choice "Remove the tunnel, all rules and the service? [y/N]: " yn
    [[ "${yn:-N}" =~ ^[Yy]$ ]] || { echo "Cancelled."; return 0; }

    load_state

    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl reset-failed >/dev/null 2>&1 || true

    remove_tagged_rules "$TAG_PREFIX"

    # bounded, same reasoning as in the down script
    for _ in 1 2 3 4 5 6 7 8; do
        ip rule show 2>/dev/null | grep -q "fwmark 0x1.*lookup 100" || break
        ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null || break
    done
    ip route flush table 100 2>/dev/null || true

    if [ -n "${TUN_NAME:-}" ]; then
        ip tunnel del "$TUN_NAME" 2>/dev/null || ip link del "$TUN_NAME" 2>/dev/null || true
    fi

    rm -f "$UP_SCRIPT" "$DOWN_SCRIPT" "$STATE_FILE"
    : > "$PF_DB"

    echo "[+] Removed."
    echo "[i] ip_forward and rp_filter were left as they are; other services may need them."
}

# ------------------------------------------------------------------- menu ---

main_menu() {
    while true; do
        echo
        echo "================================================"
        echo "      Legendary GRE Tunnel Manager  v$VERSION"
        echo "      (real client IP preserving)"
        echo "================================================"
        load_state
        if [ -n "${SIDE:-}" ]; then
            echo "  role: $SIDE   iface: ${TUN_NAME:-?}   peer: ${TUN_PEER_IP:-?}"
            echo "------------------------------------------------"
        fi
        echo "1) Create / Reconfigure tunnel"
        echo "2) Show status"
        echo "3) Diagnose"
        echo "4) Port forward manager"
        echo "5) MTU / speed tools"
        echo "6) Remove everything"
        echo "0) Exit"
        echo
        read_choice "Select [0-6]: " sel
        case "$sel" in
            1) create_tunnel || true; pause ;;
            2) show_status || true; pause ;;
            3) diagnose || true; pause ;;
            4) port_forward_menu || true ;;
            5) tools_menu || true; pause ;;
            6) remove_everything || true; pause ;;
            0) exit 0 ;;
            "") echo "Nothing entered." ;;
            *) printf 'Invalid selection: %q\n' "$sel" ;;
        esac
    done
}

# An upgrade only replaces this file. The helper scripts it generated live in
# /usr/local/sbin and keep whatever logic the old version wrote, so a new
# feature here would silently run against old logic there. Refresh them before
# the menu opens if their stamp does not match this version.
ensure_helpers_current() {
    [ -f "$STATE_FILE" ] || return 0

    local stale=0
    grep -qxF "$HELPER_STAMP" "$UP_SCRIPT" 2>/dev/null || stale=1
    grep -qxF "$HELPER_STAMP" "$DOWN_SCRIPT" 2>/dev/null || stale=1
    [ "$stale" -eq 1 ] || return 0

    echo "[i] Helper scripts on disk are from an older version - regenerating for v$VERSION."
    write_up_script
    write_down_script
    write_service
    systemctl daemon-reload >/dev/null 2>&1 || true
    if "$UP_SCRIPT" >/dev/null 2>&1; then
        echo "[i] Done. Existing tunnel and port-forwards re-applied."
    else
        echo "[!] Regenerated, but re-applying failed. Run option 3 (Diagnose)."
    fi
    echo
}

ensure_helpers_current
main_menu
