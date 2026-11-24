# Legendary GRE Tunnel Manager

A menu-driven GRE tunnel manager for **Iran ⇄ Foreign** servers that **preserves the real client IP** end to end, and lets one foreign server terminate tunnels from several Iran servers at once.

Most GRE tunnel scripts masquerade all traffic on the Iran side, so the foreign server only ever sees a single tunnel address. Anything that depends on the client IP — IP limiting, per-user connection counts, abuse tracking, geo logic — becomes useless. This script solves that.

```
client 1.2.3.4  ──►  IRAN-1  ══ GRE ══╗
                                      ╠══►  FOREIGN
client 5.6.7.8  ──►  IRAN-2  ══ GRE ══╝     sees 1.2.3.4 and 5.6.7.8,
                     (DNAT only)            not the tunnel IPs
```

---

## Why this exists

| Common script behaviour | What it breaks | What this does instead |
|---|---|---|
| `iptables -t nat -A POSTROUTING -j MASQUERADE` | Rewrites every client's source IP. The foreign server sees only the tunnel IP. | No SNAT at all. Iran does DNAT only; the foreign side returns replies through a policy route. |
| `iptables -t nat -A PREROUTING -j DNAT ...` (no port match) | Redirects *every* inbound packet to the peer — including your SSH session. | Only the ports you explicitly add are forwarded. |
| `iptables -A INPUT -p icmp -j DROP` | Kills ping through the tunnel, making diagnosis impossible. | Not applied. |
| Manual `ip tunnel` + `iptables-persistent` + sysctl, applied separately | Some parts survive a reboot, others don't. Half-configured tunnel. | One state file per tunnel, one systemd unit. Tunnels, sysctls, routing and port-forwards are restored together. |
| One hardcoded fwmark and routing table | A second tunnel on the same server overwrites the first one's return route, so its clients' replies go out the wrong tunnel. | Each tunnel gets its own interface, subnet, mark and routing table, allocated automatically. |

---

## Features

- **Real client IP preservation** — CONNMARK + fwmark policy routing on the foreign side, no SNAT on the Iran side.
- **Several tunnels per server** — up to 8. One foreign server can terminate tunnels from many Iran servers simultaneously; each gets its own interface, `/30`, firewall mark and routing table, so return traffic can never leave through the wrong tunnel. A server can even be the Iran side of one tunnel and the foreign side of another.
- **Survives reboot** — a single `oneshot` systemd unit re-applies every tunnel from `/etc/legendary-gre/tunnels/`. No `iptables-persistent` dependency.
- **Idempotent** — every rule is added with a `-C` check first. Run it as many times as you like; nothing duplicates.
- **Exact, complete removal** — every rule carries a `LEGENDARY_GRE_` comment tag naming its tunnel, so one tunnel can be removed without disturbing another, and a full teardown removes what this script created and nothing else. Your Docker, WireGuard and SSH rules are untouched.
- **Built-in diagnostics** — detects the three classic landmines above on an already-configured server and tells you how to remove them.
- **Port forward manager** — add, list and remove forwards; saved to disk and restored on boot.
- **Per-IP binding** — on a server with several public addresses, a forward can be published on exactly one of them, leaving the others free.
- **MTU scan and iperf3 speed test** over the tunnel.

---

## Requirements

- Two Linux servers (Debian/Ubuntu oriented), `root` access on both.
- `iproute2`, `iptables`, `systemd` — present on any standard install.
- The `ip_gre` kernel module (loaded automatically).
- **GRE (IP protocol 47) must be open between the two servers.**

That last point is the single most common reason a tunnel comes up but passes no traffic. GRE is not TCP or UDP — it is its own IP protocol. If your provider has a cloud firewall or security group, you must allow protocol `47`, not a port. In an OpenStack/Horizon-style panel this is the **"Different protocol"** rule type, with protocol number `47`, on **both** servers.

---

## Install

On **both** servers:

```bash
wget https://raw.githubusercontent.com/CheraDasham/gre/main/legendary-gre.sh
sed -i 's/\r$//' legendary-gre.sh      # only needed if the file was touched on Windows
chmod +x legendary-gre.sh
sudo ./legendary-gre.sh
```

> The script is interactive and refuses to run from a pipe. Use `bash <(curl -sSL ...)`, not `curl ... | bash`.

---

## Usage

### 1. Create a tunnel

Run option **`1) Add / reconfigure a tunnel`** on each server.

| Prompt | Iran server | Foreign server |
|---|---|---|
| Server role | `1` | `2` |
| Iran public IP | *same value on both* | *same value on both* |
| Foreign public IP | *same value on both* | *same value on both* |
| MTU | `1476` (default) | same |

Both servers get the **same** pair of public IPs — only the *role* differs. The script warns you if the address you picked for this server isn't actually configured on any of its interfaces, which catches the most common typo.

Everything that has to be unique is allocated from the tunnel's slot, so there is nothing to choose and nothing to collide:

| Slot | Interface | Subnet | Foreign side | Iran side | Mark | Table |
|---|---|---|---|---|---|---|
| 0 | `legend0` | `10.10.10.0/30` | `10.10.10.1` | `10.10.10.2` | `0x1` | 100 |
| 1 | `legend1` | `10.10.11.0/30` | `10.10.11.1` | `10.10.11.2` | `0x2` | 101 |
| 2 | `legend2` | `10.10.12.0/30` | `10.10.12.1` | `10.10.12.2` | `0x3` | 102 |

### 2. Several Iran servers into one foreign server

Run option `1` once per tunnel on the foreign server, and once on each Iran server:

| | Foreign server | IRAN-1 | IRAN-2 |
|---|---|---|---|
| first run | role `2`, peer = IRAN-1 → `legend0` | role `1`, peer = foreign → `legend0` | |
| second run | role `2`, peer = IRAN-2 → `legend1` | | role `1`, peer = foreign → `legend0` |

Each Iran server only ever has its own single tunnel, so it always lands in slot 0 — the slots only stack up on the foreign server. Every tunnel there keeps its own routing table, so a reply to an IRAN-2 client can never go back out the IRAN-1 tunnel.

The same works for a relay: a server can be the Iran side of one tunnel and the foreign side of another at the same time.

### 3. Verify

From the Iran server:

```bash
ping -c4 10.10.10.1
```

Then run option **`3) Diagnose`** on both sides. It checks each tunnel's interface, endpoints, `ip_forward`, `rp_filter`, mark and routing table, and flags any leftover legacy rules.

### 4. Forward ports

On the **Iran** server, option **`4) Port forward manager`** → **`1) Add port forward`**.

If the server has more than one tunnel, it asks which tunnel to forward into first. Then give it the public port on this server, the destination port on the foreign server, and the protocol (TCP / UDP / both).

**Choosing which address answers.** If the Iran server has more than one public IP, the script asks which one this forward should be published on:

```
This server has more than one public address.
  0) all of them
  1) 164.37.106.218
  2) 164.37.106.219
Publish this forward on [0-2, default 0]:
```

Pick `1` and only `164.37.106.218` gets a DNAT rule — `164.37.106.219` keeps that port free for whatever else is listening there. Pick `0` (the default, and what happens automatically on a single-IP server) and the forward is published on every address of the default-route interface. Docker bridges, other tunnels and private ranges are excluded either way.

Because the same port can now be published on two different addresses, forwards are listed with a number and removed by that number rather than by port:

```
#    Tunnel     Proto    Public port    Target port    Bound to
1    legend0    tcp      8080           8080           164.37.106.218
2    legend0    tcp      443            443            all public IPs
```

Forwards are stored in `/etc/legendary-gre/portforwards.db` and re-applied on every boot.

> Forwarding port `22` sends your own SSH to the other server. The script asks for confirmation before doing that.

---

## How real IP preservation works

**Iran side** — DNAT only. The packet keeps its original source address as it enters the tunnel:

```
PREROUTING  -d <public ip> -p tcp --dport 443  -j DNAT --to 10.10.10.1:443
```

There is deliberately **no** `SNAT` or `MASQUERADE`. That is the whole point.

**Foreign side** — the packet now arrives carrying a public source address that does not belong to the tunnel subnet. Left alone, the reply would leave via the default route straight at the client and be dropped as unsolicited. So:

1. `CONNMARK --set-mark <mark>` on every new connection arriving on a tunnel interface — a different mark per tunnel.
2. `CONNMARK --restore-mark` in `PREROUTING` and `OUTPUT`, so the reply carries the same mark. One shared pair of rules serves every tunnel, because the mark itself says which table to use.
3. `ip rule add fwmark <mark> lookup <table>` per tunnel, each table holding a default route back through its own tunnel.

With two tunnels that is mark `0x1` → table 100 and mark `0x2` → table 101, so a reply to an IRAN-2 client cannot be sent out the IRAN-1 tunnel.

`rp_filter` is set to `2` (loose) rather than `0` — strict mode would drop the real client addresses arriving on the tunnel, while `0` disables the check entirely. Loose keeps anti-spoofing protection without breaking the tunnel.

All the mark rules are masked, and the mask is only as wide as the number of tunnels needs (`0x1` for one, `0x3` for two or three, `0x7` for four to seven). That keeps the high bits — where WireGuard and friends keep their own marks — completely untouched, and the mask narrows again when a tunnel is removed.

---

## Menu reference

```
1) Add / reconfigure a tunnel      add a new tunnel, or change an existing one
2) Show status                     every tunnel, service state, rule count, return routing
3) Diagnose                        per-tunnel health checks + known-bad legacy rules
4) Port forward manager            add / list / delete / remove all
5) MTU / speed tools               set MTU, auto MTU scan, iperf3 server, speed test
6) Remove one tunnel               removes just that tunnel; the others keep working
7) Remove everything               full teardown
0) Exit
```

Actions that work on a single tunnel (port forwards, MTU tools, removing one) ask which tunnel when there is more than one, and pick it silently when there is only one.

---

## Files it creates

| Path | Purpose |
|---|---|
| `/etc/legendary-gre/tunnels/legend<N>.conf` | One file per tunnel |
| `/etc/legendary-gre/portforwards.db` | Persistent port forwards, one tunnel per row |
| `/usr/local/sbin/legendary-gre-up.sh` | Applies everything; idempotent |
| `/usr/local/sbin/legendary-gre-down.sh` | Teardown |
| `/etc/systemd/system/legendary-gre.service` | Re-applies on boot |

---

## Uninstall

Option **`6) Remove one tunnel`** removes a single tunnel, its rules, its policy route and its port forwards, leaving the others running. When the last tunnel goes, the systemd unit is removed too.

Option **`7) Remove everything`** removes every tunnel, all tagged rules, the policy routes and the systemd unit.

`ip_forward` and `rp_filter` are deliberately left as they are — other services on the box may depend on them.

---

## Troubleshooting

**`add tunnel "gre0" failed: File exists`, then `Cannot find device`.**
Another GRE tunnel already uses the same pair of endpoints. The kernel identifies a GRE tunnel by its `(local, remote)` addresses, **not** by its interface name, so only one tunnel can exist per endpoint pair — and the error confusingly names the kernel's `gre0` fallback device instead of the interface you asked for. List what exists and remove the conflicting one:

```bash
ip -d tunnel show | grep -i gre
ip tunnel del <name>
```

`gre0` itself (`remote any local any`) is the harmless fallback device — leave it alone. If the old tunnel was created by another script with its own systemd unit, disable that unit too, or it will come back on the next boot. Option `1) Create / Reconfigure tunnel` detects this conflict up front and offers to clear it.

**Tunnel is up but nothing passes.**
GRE (protocol 47) is blocked somewhere. Confirm with `tcpdump` on both ends simultaneously:

```bash
sudo tcpdump -ni any proto gre
```

If packets leave the Iran server but never arrive at the foreign one, it is a firewall between them — almost always a cloud security group.

**Ping fails but the tunnel works.**
Check for a leftover `iptables -A INPUT -p icmp -j DROP`. Test with TCP instead:

```bash
nc -zv 10.10.10.1 22
```

**Foreign server still sees the tunnel IP.**
A `MASQUERADE` rule survived on the Iran side. Option `3) Diagnose` detects it and prints the exact removal command.

**A second tunnel refuses to come up on the same server.**
Check that the two tunnels do not share a pair of endpoints — the kernel allows only one GRE tunnel per `(local, remote)` pair. Two tunnels from *different* Iran servers to the same foreign server are fine, because the remote address differs.

**Clients of one Iran server work, clients of the other do not.**
Run option `3) Diagnose` on the foreign server. Each foreign-side tunnel must show its own fwmark rule and its own routing table with a default route. If two tunnels report the same table, they were not created through option `1` and are sharing a return path.

**A port is forwarded on an address it should not be.**
The forward was added with `0) all of them`. Remove that entry by its number and re-add it, picking the single address you want.

**Service shows `active (exited)`.**
That is correct for a `oneshot` unit — it means the work completed successfully.

**`set: pipefail: invalid option name`**
The file has Windows line endings. Fix with `sed -i 's/\r$//' legendary-gre.sh`.

---

## راهنمای فارسی (خلاصه)

این اسکریپت یه تانل GRE بین سرور ایران و خارج می‌سازه که **IP واقعی کاربر رو حفظ می‌کنه**. توی اکثر اسکریپت‌های مشابه، رول `MASQUERADE` سمت ایران باعث می‌شه سرور خارج فقط IP تانل رو ببینه و ip_limit از کار بیفته. این‌جا هیچ SNAT ای اعمال نمی‌شه.

**نصب** (روی هر دو سرور):

```bash
chmod +x legendary-gre.sh
sudo ./legendary-gre.sh
```

**مراحل:**

1. گزینه‌ی `1` رو بزن. سمت ایران نقش `1`، سمت خارج نقش `2`. IPهای عمومی روی **هر دو سرور یکسان** وارد می‌شن، فقط نقش فرق می‌کنه.
2. با `ping -c4 10.10.10.1` از سمت ایران تست کن.
3. گزینه‌ی `3` (Diagnose) رو روی هر دو بزن — خودش رول‌های قدیمی مشکل‌ساز رو پیدا می‌کنه و دستور حذفشون رو می‌ده.
4. برای فوروارد پورت، گزینه‌ی `4` **فقط روی سرور ایران**.

**اگه سرور ایران چند تا IP عمومی داره،** موقع اضافه کردن فوروارد ازت می‌پرسه روی کدوم IP اعمال بشه. مثلاً `1` رو بزنی فقط روی `164.37.106.218` رول ساخته می‌شه و `164.37.106.219` دست‌نخورده می‌مونه. `0` یعنی روی همه‌ی IPها. چون یه پورت می‌تونه روی دو تا IP جدا باشه، حذف فورواردها با **شماره‌ی ردیف** انجام می‌شه نه با شماره‌ی پورت.

**نکته‌ی مهم:** پروتکل GRE شماره‌ی `47` باید روی فایروال/Security Group **هر دو سرور** باز باشه. این پورت نیست، پروتکل IP جداست — توی پنل‌های ابری معمولاً گزینه‌ی «Different protocol» با شماره‌ی `47`. رایج‌ترین دلیل اینکه تانل بالا میاد ولی ترافیک رد نمی‌شه همینه.

**اگه خطای `add tunnel "gre0" failed: File exists` گرفتی:** یه تانل GRE دیگه با همون جفت IP از قبل وجود داره. کرنل تانل GRE رو با جفت (local, remote) می‌شناسه نه با اسم اینترفیس، پس فقط یکی می‌تونه وجود داشته باشه. با `ip -d tunnel show | grep -i gre` پیداش کن و `ip tunnel del <name>` بزن. خودِ `gre0` دستگاه fallback کرنله و بی‌ضرره، کاری باهاش نداشته باش.

همه‌چیز بعد ریبوت خودکار برمی‌گرده؛ نیازی به `iptables-persistent` نیست.

---

## Changelog

**v1.2.0**
- Multiple tunnels per server, up to 8. One foreign server can now terminate tunnels from several Iran servers at once. Each tunnel gets its own interface, `/30`, firewall mark and routing table, allocated from its slot, so return traffic can never leave through the wrong tunnel.
- State moved from a single `/etc/legendary-gre/state` to one file per tunnel under `/etc/legendary-gre/tunnels/`. Existing v1.1.x installs are migrated automatically on first run, port forwards included.
- Rule tags now name their tunnel, so `6) Remove one tunnel` removes exactly one without disturbing the others.
- The shared mark mask is sized to the tunnel count and narrows again when a tunnel is removed, instead of leaving a wider stale rule behind that would clobber other tools' marks.
- A server can be the Iran side of one tunnel and the foreign side of another.

**v1.1.3**
- `Remove everything` left the deleted tunnel's values in the menu header and in the variables other actions gate on. `load_state` now clears them when the state file is gone.
- Every prompt now strips carriage returns and surrounding whitespace before matching. A terminal or paste that sends CRLF made a valid `1` or `y` fall through to the invalid branch, which looked like the menu ignoring a correct answer.
- An invalid entry now prints what was actually received, and end-of-input exits cleanly instead of looping.

**v1.1.2**
- Generated helper scripts in `/usr/local/sbin` are now version-stamped and refreshed automatically when `legendary-gre.sh` is newer. Upgrading the script used to leave the old helpers in place, so new features ran against old logic — a four-field port-forward record fed to a three-field parser produced `iptables: Garbage after port value`.

**v1.1.1**
- Fixed `public_ips: command not found` when adding a port forward. The helper existed only inside the generated up-script, so the menu never showed the address picker and every forward silently landed on all addresses.
- Warn instead of silently defaulting to "all" when the address list cannot be read.

**v1.1**
- Port forwards can be bound to a single public IP on a multi-IP server; `0) all of them` keeps the previous behaviour.
- Forwards are listed with an index and removed by index, since a port is no longer unique on its own.
- Tunnel creation is now verified. Previously, if `ip tunnel add` failed the script still reported "ready" and everything after it failed with `Cannot find device`.
- Conflicting GRE tunnels on the same endpoint pair are detected before setup and can be removed from the prompt.
- Bounded the `ip rule` cleanup loop so teardown cannot spin forever on a box where something else uses fwmark.
- Existing three-field `portforwards.db` entries are read unchanged — no migration needed.

**v1.0**
- Initial release.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

Copyright (C) 2026 Legendary
