# Legendary GRE Tunnel Manager

A menu-driven GRE tunnel manager for an **Iran ⇄ Foreign** server pair that **preserves the real client IP** end to end.

Most GRE tunnel scripts masquerade all traffic on the Iran side, so the foreign server only ever sees a single tunnel address. Anything that depends on the client IP — IP limiting, per-user connection counts, abuse tracking, geo logic — becomes useless. This script solves that.

```
client 1.2.3.4  ──►  IRAN server  ══ GRE ══►  FOREIGN server
                      (DNAT only)              sees 1.2.3.4, not the tunnel IP
```

---

## Why this exists

| Common script behaviour | What it breaks | What this does instead |
|---|---|---|
| `iptables -t nat -A POSTROUTING -j MASQUERADE` | Rewrites every client's source IP. The foreign server sees only the tunnel IP. | No SNAT at all. Iran does DNAT only; the foreign side returns replies through a policy route. |
| `iptables -t nat -A PREROUTING -j DNAT ...` (no port match) | Redirects *every* inbound packet to the peer — including your SSH session. | Only the ports you explicitly add are forwarded. |
| `iptables -A INPUT -p icmp -j DROP` | Kills ping through the tunnel, making diagnosis impossible. | Not applied. |
| Manual `ip tunnel` + `iptables-persistent` + sysctl, applied separately | Some parts survive a reboot, others don't. Half-configured tunnel. | One state file, one systemd unit. Tunnel, sysctls, routing and port-forwards are restored together. |

---

## Features

- **Real client IP preservation** — CONNMARK + fwmark policy routing on the foreign side, no SNAT on the Iran side.
- **Survives reboot** — a single `oneshot` systemd unit re-applies everything from `/etc/legendary-gre/state`. No `iptables-persistent` dependency.
- **Idempotent** — every rule is added with a `-C` check first. Run it as many times as you like; nothing duplicates.
- **Exact, complete removal** — every rule carries a `LEGENDARY_GRE_` comment tag, so teardown removes what this script created and nothing else. Your Docker, WireGuard and SSH rules are untouched.
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

### 1. Create the tunnel

Run option **`1) Create / Reconfigure tunnel`** on each server.

| Prompt | Iran server | Foreign server |
|---|---|---|
| Server role | `1` | `2` |
| Iran public IP | *same value on both* | *same value on both* |
| Foreign public IP | *same value on both* | *same value on both* |
| Tunnel subnet | `10.10.10.0/30` (default) | same |
| Interface name | `legend0` (default) | same |
| MTU | `1476` (default) | same |

Both servers get the **same** pair of public IPs — only the *role* differs. The script warns you if the address you picked for this server isn't actually configured on any of its interfaces, which catches the most common typo.

Addressing follows a fixed convention:

- Foreign side → `10.10.10.1`
- Iran side → `10.10.10.2`

### 2. Verify

From the Iran server:

```bash
ping -c4 10.10.10.1
```

Then run option **`3) Diagnose`** on both sides. It checks the interface, endpoints, `ip_forward`, `rp_filter`, the return-routing rules, and flags any leftover legacy rules.

### 3. Forward ports

On the **Iran** server, option **`4) Port forward manager`** → **`1) Add port forward`**.

Give it the public port on Iran, the destination port on the foreign server, and the protocol (TCP / UDP / both).

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
#    Proto    Public port    Target port    Bound to
1    tcp      8080           8080           164.37.106.218
2    tcp      443            443            all public IPs
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

1. `CONNMARK --set-mark 0x1/0x1` on every new connection arriving on the tunnel interface.
2. `CONNMARK --restore-mark` in `PREROUTING` and `OUTPUT`, so the reply carries the same mark.
3. `ip rule add fwmark 0x1/0x1 lookup 100` + a default route in table `100` pointing back through the tunnel.

`rp_filter` is set to `2` (loose) rather than `0` — strict mode would drop the real client addresses arriving on the tunnel, while `0` disables the check entirely. Loose keeps anti-spoofing protection without breaking the tunnel.

The masked mark (`0x1/0x1`) means other users of `fwmark` on the same box — WireGuard, for example — are left alone.

---

## Menu reference

```
1) Create / Reconfigure tunnel     build or rebuild the tunnel and enable persistence
2) Show status                     interface, saved config, service state, managed rules
3) Diagnose                        health checks + detection of known-bad legacy rules
4) Port forward manager            add / list / delete / remove all
5) MTU / speed tools               set MTU, auto MTU scan, iperf3 server, speed test
6) Remove everything               full teardown
0) Exit
```

---

## Files it creates

| Path | Purpose |
|---|---|
| `/etc/legendary-gre/state` | Saved configuration |
| `/etc/legendary-gre/portforwards.db` | Persistent port forwards |
| `/usr/local/sbin/legendary-gre-up.sh` | Applies everything; idempotent |
| `/usr/local/sbin/legendary-gre-down.sh` | Teardown |
| `/etc/systemd/system/legendary-gre.service` | Re-applies on boot |

---

## Uninstall

Option **`6) Remove everything`** removes the tunnel, all tagged rules, the policy route and the systemd unit.

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
