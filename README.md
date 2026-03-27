<div align="center">

```
██████╗ ██████╗ ██╗██████╗ 
██╔══██╗██╔══██╗██║██╔══██╗
██║  ██║██████╔╝██║██████╔╝
██║  ██║██╔══██╗██║██╔═══╝ 
██████╔╝██║  ██║██║██║     
╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝     
```

**The world's only all-in-one proxychains wrapper with live geo visualization, DNS-safe browser mode, intelligent proxy rotation, country blacklisting, and VPN integration for raw-socket tools — in a single Python file.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![proxychains4](https://img.shields.io/badge/proxychains4-required-red?style=for-the-badge)](https://github.com/haad/proxychains)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux)](https://github.com/kishwordulal1234/drip)
[![Made in Nepal](https://img.shields.io/badge/Made%20in-Nepal-blue?style=for-the-badge)]()

[**Quick Start**](#-quick-start) · [**TCP Tools**](#-tcp-tools-use-drip) · [**Raw Socket Tools**](#-raw-socket-tools-use-protonvpn) · [**Browser Mode**](#-browser-mode) · [**Config**](#-configuration) · [**Version History**](#-version-history--honest-comparison) · [**Resources**](#-resources--credits)

</div>

---

## What is drip?

`drip` is a **single-file Python proxychains wrapper** that turns the raw, silent `proxychains4` binary into a full anonymity toolkit. Born from 3+ months of development and 380+ deleted prototypes.

```bash
cat proxies.txt | python3 drip_alpha.py sqlmap -u "http://target.com?id=1"
cat proxies.txt | python3 drip_alpha.py nmap -sT target.com
cat proxies.txt | python3 drip_alpha.py --browser
python3 drip_alpha.py curl https://example.com   # auto-Tor fallback
```

---

## Quick Start

### Install Dependencies

```bash
# Ubuntu / Debian / Kali
sudo apt install proxychains4 python3 python3-pip curl tor firefox-esr

# Arch / Manjaro
sudo pacman -S proxychains-ng python python-pip curl tor firefox

# macOS
brew install proxychains-ng python3 curl tor
```

### Clone and Run

```bash
git clone https://github.com/kishwordulal1234/drip
cd drip
# rich, requests, pyyaml auto-install on first run
# drip_alpha.py is the current version
cat proxies.txt | python3 drip_alpha.py curl https://ipinfo.io
```

> **Note:** `drip_alpha.py` is the current version. `drip.py` is the original v1.

### Get Proxies

```
Best free SOCKS5 list:  https://spys.one/en/socks-proxy-list/
Free public VPN/proxy:  https://www.vpngate.net/en/
```

---

## TCP vs Raw Socket — Which to Use

This is the most important concept for using drip correctly:

```
Does the tool use TCP?          YES → use drip_alpha.py
Does it use raw sockets/ICMP?   YES → use ProtonVPN + drip on top
```

| Tool | Protocol | drip works? | Need VPN? |
|---|---|:---:|:---:|
| nmap -sT | TCP | YES (auto-patched) | optional |
| nmap -sS (SYN scan) | Raw socket | NO | YES |
| nmap -sU (UDP scan) | UDP/raw | NO | YES |
| nmap -O (OS detect) | Raw socket | NO | YES |
| ping | ICMP | NO | YES |
| traceroute | UDP/ICMP | NO | YES |
| arping | ARP | NO | YES |
| hping3 | Raw socket | NO | YES |
| sqlmap | TCP/HTTP | YES | optional |
| ghauri | TCP/HTTP | YES | optional |
| nikto | TCP/HTTP | YES | optional |
| ffuf / gobuster | TCP/HTTP | YES | optional |
| curl / wget | TCP | YES | optional |
| Firefox browser | TCP | YES (--browser) | optional |

drip detects raw-socket tools automatically and warns you. It also detects if a VPN is already active.

---

## TCP Tools — Use drip

```bash
# nmap TCP scan (auto-injects -sT -Pn)
cat proxies.txt | python3 drip_alpha.py nmap -sV -p 80,443 target.com

# sqlmap (auto-injects --batch --random-agent)
cat proxies.txt | python3 drip_alpha.py sqlmap -u "http://target.com?id=1"

# ghauri
cat proxies.txt | python3 drip_alpha.py ghauri -u "http://target.com?id=1" --dbs

# nikto (auto-injects -timeout 15)
cat proxies.txt | python3 drip_alpha.py nikto -h http://target.com

# ffuf (auto-injects -timeout 20)
cat proxies.txt | python3 drip_alpha.py ffuf -w wordlist.txt -u http://target.com/FUZZ

# gobuster (auto-injects --timeout 20s)
cat proxies.txt | python3 drip_alpha.py gobuster dir -u http://target.com -w wordlist.txt

# curl / wget
cat proxies.txt | python3 drip_alpha.py curl -s https://ipinfo.io/json

# Tor auto-mode (no proxies = auto-Tor)
python3 drip_alpha.py curl https://check.torproject.org
```

---

## Raw Socket Tools — Use ProtonVPN

Tools using **raw sockets, ICMP, UDP, or ARP** bypass proxychains at the kernel level. No software wrapper can fix this — it is a fundamental networking constraint. The only solution is a **VPN that creates a real network interface** (tun0 or wg0) that all kernel traffic is forced through.

### Why ProtonVPN

ProtonVPN is the recommended VPN for drip users. This is not a sponsorship — it is a practical choice based on specific reasons:

**Switzerland jurisdiction.** Swiss law has strong privacy protections and Switzerland is outside the 5/9/14 Eyes intelligence alliances. Courts there have confirmed ProtonVPN had nothing to give when subpoenaed.

**Verified no-logs.** Independently audited by SEC Consult and Securitum. Real-world proof: multiple law enforcement requests confirmed there were no logs to hand over.

**Available on every major platform.** Linux, Windows, macOS, Android, iOS — all officially supported with native apps. If you switch between machines you use one account everywhere. Most other privacy VPNs are Linux-only or have poor mobile support.

**Free tier exists.** You can use ProtonVPN without paying. Limited servers, but full WireGuard encryption. No ads, no data selling.

**WireGuard + OpenVPN both supported.** WireGuard for speed, OpenVPN for compatibility with older systems. drip's config (added in v3) supports both.

**Kill switch built in.** If the VPN drops, traffic stops. No accidental exposure window.

**Easy CLI on Linux.** `sudo protonvpn-cli connect --fastest` — one command, works in headless servers.

### Setup

```bash
# Install ProtonVPN on Debian/Ubuntu/Kali
wget https://repo.protonvpn.com/debian/dists/stable/main/binary-amd64/protonvpn-stable-release_1.0.3-3_all.deb
sudo dpkg -i protonvpn-stable-release_1.0.3-3_all.deb
sudo apt update && sudo apt install protonvpn-cli

# Connect
sudo protonvpn-cli connect --fastest      # fastest available server
sudo protonvpn-cli connect --p2p          # P2P-optimized
sudo protonvpn-cli connect CH             # Switzerland specifically
sudo protonvpn-cli status                 # verify connection
```

```bash
# Arch / Manjaro
yay -S protonvpn-cli

# Fedora / RHEL
sudo dnf install protonvpn-cli
```

### Verify Protection

```bash
# Before VPN — this is your real IP visible to the target:
ping -c1 8.8.8.8      # ICMP exits your real interface
traceroute google.com  # your real route exposed

# After connecting ProtonVPN:
sudo protonvpn-cli connect --fastest
ping -c1 8.8.8.8      # now exits through Switzerland
traceroute google.com  # routes through VPN

# Check the tun0 interface was created:
ip addr show tun0    # WireGuard creates wg0 instead
```

### Maximum Anonymity — Stack drip on top of ProtonVPN

The most anonymous setup for TCP tools connects ProtonVPN first, then uses drip on top:

```
YOUR MACHINE
    |
    v  (WireGuard/OpenVPN tunnel — ALL traffic, including ICMP/UDP/raw sockets)
PROTONVPN SERVER (Switzerland)
    |
    v  (proxychains SOCKS5 chain — TCP tools only)
PROXY 1 (Germany)
    |
    v
PROXY 2 (Japan)
    |
    v
PROXY 3 (USA)
    |
    v
TARGET — sees only the last proxy IP, not ProtonVPN, not you
```

```bash
# Step 1: Connect ProtonVPN
sudo protonvpn-cli connect --fastest

# Step 2: Run drip on top
# Now even proxy operators see only ProtonVPN's Switzerland IP, not your real IP
cat proxies.txt | python3 drip_alpha.py nmap -sT target.com
cat proxies.txt | python3 drip_alpha.py sqlmap -u "http://target.com?id=1"

# Step 3: Raw socket tools are also covered by ProtonVPN now
sudo nmap -sS target.com   # SYN scan — exits through ProtonVPN
ping target.com            # ICMP — exits through ProtonVPN
```

drip detects active VPN interfaces (tun0, wg0, ppp0) automatically and shows VPN status in the banner.

### Free Alternative — VPNGate OpenVPN

If you cannot use ProtonVPN, free public OpenVPN configs are available from VPNGate:

```bash
sudo apt install openvpn
# Download a .ovpn file from https://www.vpngate.net/en/
sudo openvpn --config vpngate_server.ovpn

# drip.yml supports this (vpn_config was added in v3):
# vpn_config: /path/to/vpngate_server.ovpn
# use_openvpn: T
```

---

## Browser Mode — Full DNS Safety

```bash
cat proxies.txt | python3 drip_alpha.py --browser
python3 drip_alpha.py --browser   # Tor auto-mode
```

drip's `--browser` mode starts a local SOCKS5 forwarder and patches your actual Firefox profiles:

1. Starts local SOCKS5 server (auto port) with built-in proxy rotation
2. Patches `prefs.js` + `user.js` in all discovered Firefox profiles:
   - `socks_remote_dns = true` — DNS queries go through proxy, not your ISP
   - `trr.mode = 5` — disables DNS-over-HTTPS (DoH) which bypasses the proxy
   - `media.peerconnection.enabled = false` — kills WebRTC (the #1 IP leak)
   - `no_proxies_on = ""` — removes localhost bypass
   - DNS prefetch disabled
3. Backups created, originals restored on exit

**Why only Firefox?** Firefox is the only major browser that actually routes DNS through SOCKS5 when `socks_remote_dns = true`. Chrome, Brave, and Edge have their own DNS resolvers that ignore the proxy setting. WebRTC also leaks your real IP in Chrome regardless of what proxy is configured.

### Verify Anonymity

After launching `--browser`, check these sites:

| Site | Tests |
|---|---|
| [dnsleaktest.com](https://www.dnsleaktest.com/) | DNS leaks |
| [ipinfo.io](https://ipinfo.io/) | Your visible IP and location |
| [croxyproxy.com](https://www.croxyproxy.com/) | Cloud browser — 3 layers deep |
| [proxyium.com](https://proxyium.com/) | Another cloud browser layer |

**Pro tip:** After `--browser`, visit [croxyproxy.com](https://www.croxyproxy.com/) or [proxyium.com](https://proxyium.com/). These are cloud browser services — the website itself runs a browser on a remote server. You are now: your proxies → Firefox → cloud browser server → internet. DNS, WebRTC, and any tracking are completely blocked at each layer.

---

## Live Output

```
╔════════════════════════════════════════════════════════╗
║              DRIP — PROXYCHAINS WRAPPER                ║
╠════════════════════════════════════════════════════════╣
║  chain mode    DYNAMIC                                 ║
║  source        47 proxies  (>3000ms skipped)           ║
║  blacklist     CN, HK                                  ║
║  rotation      ON  (after 3 full connection fails)     ║
║  backend       /usr/bin/proxychains4                   ║
║  timeout       8s  (tcp: 8000ms)                       ║
║  command       sqlmap -u http://target.com?id=1        ║
╚════════════════════════════════════════════════════════╝

  probing 134 proxies (3000ms cutoff, 50 threads)...
  47/134 passed

  ╔════════════════════════════════╗
  ║           IP FLOW              ║
  ╠════════════════════════════════╣
  ║  YOUR MACHINE                  ║
  ║    IP  : [hidden]              ║
  ║          |                     ║
  ║          v (entry)             ║
  ║  ENTRY PROXY                   ║
  ║    IP  : 45.33.32.156:1080     ║
  ║    LOC : DE Germany, Berlin    ║
  ║    TYPE: SOCKS5                ║
  ║          |                     ║
  ║          v (2 more hops)       ║
  ║          |                     ║
  ║          v (exit)              ║
  ║  EXIT IP (what target sees)    ║
  ║    IP  : 103.245.11.44         ║
  ║    LOC : JP Japan, Tokyo       ║
  ╚════════════════════════════════╝

  #0001 14:32:01 OK   DE 45.33.32.156:1080 → target.com:80
  #0002 14:32:02 OK   DE 45.33.32.156:1080 → target.com:80
  #0003 14:32:04 X    DE 45.33.32.156:1080 → target.com:443 (timeout)
  ROTATED chain #1 (conn_fails: 3)  45.33.32.156 -> 91.108.4.1
  #0004 14:32:05 OK   NL 91.108.4.1:1080  → target.com:80
```

---

## Configuration

drip auto-creates `drip.yml` on first run:

```yaml
# drip.yml — full reference

# ── Chain mode (exactly ONE should be T) ──────────────────────────
strict_chain:   F   # All proxies must work — fails if any dead
dynamic_chain:  T   # Skips dead proxies — recommended for free lists
random_chain:   F   # Random subset each connection

# ── Chain settings ────────────────────────────────────────────────
chain_len:      3
timeout:        8
quick_timeout:  3000    # ms — drop proxy from pool if no response
proxy_type:     socks5
proxy_dns:      T       # CRITICAL — routes DNS through proxy
tcp_read_time:  15000
tcp_conn_time:  8000

# ── Geo / Country ─────────────────────────────────────────────────
country_lookup:     T
country_blacklist: "CN, HK"   # Comma-separated country codes to drop

# ── Browser mode ──────────────────────────────────────────────────
browser_chain_len:  1
socks_only:         F   # T = use only SOCKS proxies in browser mode

# ── Proxy rotation ────────────────────────────────────────────────
rotation:           T
rotation_interval:  0       # 0 = rotate only on failure, not on timer
max_conn_fails:     3       # full connection failures before rotating
rotate_pool_size:   10      # how many proxies to keep in rotation pool

# ── Privacy ───────────────────────────────────────────────────────
show_real_ip:       F       # show your real IP in the IP flow diagram
preflight_ip_check: F       # fetch real IP for before/after comparison

# ── Process rename (stealth in ps output) ─────────────────────────
process_rename:     F
process_name:      "drip-worker"

# ── VPN for raw socket tools (added in v3) ────────────────────────
# use_openvpn: T = use an OpenVPN .ovpn file
# use_openvpn: F = use ProtonVPN CLI
use_openvpn:   T
vpn_config:    vpngate_server.ovpn   # path to your .ovpn file
proton_user:                         # ProtonVPN OpenVPN username
proton_pass:                         # ProtonVPN OpenVPN password
```

---

## Proxy Rotation Engine (drip_alpha)

The rotation engine in drip_alpha is smarter than naive time-based rotation. The key insight: in `dynamic_chain` mode, **individual hop failures are normal** — proxychains skips dead hops automatically. Only a **complete failure to reach the target** should trigger rotation.

```
                    ┌──────────────────────────────────┐
                    │         ProxyRotator             │
                    │                                  │
  Full conn fail ──>│  consec_fails++                  │
  (target unreachable) if fails >= max_conn_fails:     │──> new chain written
                    │    rotate_locked()               │    config reloaded
                    │    consec_fails = 0              │
                    │                                  │
  Individual hop ──>│  hop_fail++ only                 │
  failure           │  does NOT trigger rotation       │
  (normal in dyn)   │                                  │
                    │                                  │
  Full conn OK  ──>│  consec_fails = 0                │
                    └──────────────────────────────────┘
```

Every version before drip_alpha (v1–v6) had no rotation at all. The `ProxyRotator` class with correct `conn_ok` / `conn_fail` / `hop_fail` separation first appears in `drip_alpha.py`.

---

## Version History — Honest Comparison

I read every version's source code before writing this section. Here is what actually changed between each one.

---

### drip.py — v1 · 1,484 lines · 68 KB

First published version. Already had: rich UI, async SOCKS5 detection, pproxy-based SOCKS5 forwarder, Firefox profile patching, Tor auto-mode, IP flow diagram, proxy type warning.

**Real bugs found reading the source:**

- `_HTTP_PROXY_PORTS` defined **twice** in the file — second set literal silently overwrites the first
- `parse_proxies()` uses `line.split(":")` with no limit — passwords with colons get silently truncated
- `fast_filter()` uses **150 workers** — hits OS file descriptor limits on many systems
- No latency sorting — proxies returned in random order after filtering
- No geo cache — calls `ip-api.com` on every run, leaking your real IP to a third party
- Temp proxychains config has **no permission hardening** — world-readable, credentials exposed
- Process rename **always on**, bare `except: pass` — failure silently ignored, cannot disable
- Tor Browser wrapper writes to **hardcoded `/tmp/drip_torbrowser.sh`** — race condition if two instances run simultaneously
- No `atexit` cleanup of the wrapper script — leaked temp file on crash
- `LEAKY_BROWSERS` dict has `"brave"` — should be `"brave-browser"`, wrong match
- Real IP lookup uses **hostnames** (`http://api.ipify.org`) — DNS resolution happens on your real interface, not the proxy

**Rating: 6/10** — Functional proof of concept with serious privacy and stability bugs

---

### drip_v2.py — v2 · 2,086 lines · 94 KB

Major fix release. Nearly every v1 bug addressed.

**What actually changed (read from the code, not guessed):**

- `_probe_and_time()` — **single TCP connection** that simultaneously measures latency AND detects proxy protocol by sending a SOCKS5 greeting. v1 did two separate network rounds for these.
- Workers reduced **150 → 50** — safe for standard Linux systems
- **Geo cache** added: `~/.cache/drip/geo.json`, 24h TTL. Only uncached IPs looked up each run.
- `via_proxy` parameter in `lookup_countries()` — geo lookup itself routed through the proxy chain so ip-api.com never sees your real IP
- **Latency sort** — `fast_filter()` now returns proxies sorted fastest-first
- Fixed `_HTTP_PROXY_PORTS` duplicate — single `frozenset` definition
- Fixed password colon split: `line.split(":", 3)` — passwords with colons now work
- Fixed temp config permissions: `os.chmod(tmp.name, stat.S_IRUSR | stat.S_IWUSR)` = 600
- Fixed process rename: `_RENAME_OK` flag, proper exception handling, result logged
- Fixed Tor wrapper: `tempfile.NamedTemporaryFile` + `atexit.register` cleanup
- Fixed `LEAKY_BROWSERS` dict: `"brave-browser"` not `"brave"`
- Fixed chain failure display: `-denied` and `-timeout` now reported separately
- `_make_kv_table()` helper — eliminates duplicate table code between banner and footer
- `chain_len` parameter in `_build_ip_flow()` — fixes "19 more hops" display bug (was showing pool size, not actual hop count)
- Real IP lookup switched to **direct IPs** via curl — no DNS leak during IP check
- `_GEO_USER_AGENT` set on all outbound geo requests
- Config default still `strict_chain: T`

**Rating: 8/10** — Most critical privacy and stability bugs fixed

---

### drip_v3.py — v3 · 2,029 lines · 90.5 KB

Slightly smaller than v2 (dead code removed). Main new feature: VPN integration in the config.

**What actually changed:**

- **VPN config keys added to drip.yml** — `use_openvpn`, `vpn_config`, `proton_user`, `proton_pass` all appear here for the first time. This is where ProtonVPN and OpenVPN support was deliberately designed into the config system.
- Default chain mode changed to `dynamic_chain: T` — better default for free proxy lists where many will be dead
- Config comment parser fixed — passwords with `#` character no longer accidentally truncated
- All v2 fixes inherited

**Rating: 8/10** — Solid, adds VPN scaffold

---

### drip_v4.py — v4

Browser mode rebuilt. The embedded SOCKS5 forwarder process got its own per-proxy rotation logic (fail counter + random selection within the forwarder). TX/RX byte logging added to the browser connection log. The `socks_only` filter made strict — HTTP proxies fully excluded when enabled, with fallback to full pool if no SOCKS available.

**Rating: 8.5/10**

---

### drip_v5.py — v5

Security hardening. `fcntl.flock` file locking added to geo cache writes — multiple drip instances running simultaneously can no longer corrupt the cache. VPN detection logic (`ip addr show` parsing for tun0/wg0/ppp0) made more robust with full regex matching. Early country blacklist implementation.

**Rating: 8.5/10**

---

### drip_v6.py — v6

Pre-alpha preparation. Signal handlers for `SIGTERM` and `SIGHUP` added — child processes and temp files cleaned up on kill signals. Cleanup registry pattern (`_CLEANUP_CALLBACKS` list). IPv6 proxy format support (`[::1]:1080`). Host and port input sanitization against injection characters (`\n`, `\r`, `\x00`, path separators).

**Rating: 9/10**

---

### drip_alpha.py — CURRENT v · The Full Build

Everything from v1–v6, plus:

- **`ProxyRotator` class** — thread-safe, connection-fail-based rotation. The first version with real rotation. Correctly separates `conn_ok` / `conn_fail` / `hop_ok` / `hop_fail`.
- **`_classify_chain_line()`** — correctly identifies full connection results vs intermediate hop results from proxychains output. This distinction is what makes the rotation engine work — previous versions would have triggered rotation on normal dynamic-chain hop failures.
- **Country blacklist with stats panel** — shows how many proxies dropped per country (CN: 12, HK: 4, etc.)
- **`preflight_ip_check`** — opt-in real IP fetch for before/after comparison
- **Process rename fully opt-in** — `process_rename: F` by default
- **Dependency installer hardened** — tries `--break-system-packages`, falls back to `--user`, fails with clear error message instead of silent crash
- **`_TEMP_FILES` registry** — all temp files tracked and deleted on exit, even on crash
- **`FileLock`** using `fcntl.flock` on geo cache
- **Full signal handler coverage** — `SIGTERM`, `SIGHUP` both handled
- **Rotation stats in footer** — total rotations, hop ok/fail counts
- **`find_proxychains()` ownership check** — warns if binary not owned by root or current user
- **Separate quiet/verbose proxychains configs** — tool output clean, drip metrics logged separately

**Rating: 9.5/10** — Most complete and secure version

---

## What No Other Tool Does

| Feature | drip | mubeng | ProxyBroker2 | NyxProxy | bare proxychains |
|---|:---:|:---:|:---:|:---:|:---:|
| `cat proxies.txt \| python3 drip.py tool args` | YES | NO | NO | NO | NO |
| Live timestamped connection log with country flags | YES | NO | NO | NO | NO |
| IP flow diagram (your IP / entry / exit / target) | YES | NO | NO | NO | NO |
| `--browser` mode (patches Firefox, kills WebRTC/DNS leak) | YES | NO | NO | NO | NO |
| Country blacklist with per-country drop stats | YES | NO | NO | partial | NO |
| Auto SOCKS5 probe (detects HTTP proxies mislabeled as SOCKS5) | YES | partial | partial | NO | NO |
| Smart rotation (conn-fail only, not on every hop failure) | YES | naive | naive | NO | NO |
| ProtonVPN / OpenVPN integration in config | YES | NO | NO | NO | NO |
| Tor auto-fallback when no proxies provided | YES | NO | NO | NO | NO |
| VPN detection for raw-socket tools | YES | NO | NO | NO | NO |
| Auto-patches nmap / sqlmap / ffuf / nikto / gobuster | YES | NO | NO | NO | NO |
| Geo cache (24h TTL, no repeated API calls) | YES | NO | NO | NO | NO |
| Secure temp files (600 perms + full cleanup registry) | YES | N/A | N/A | N/A | NO |
| Single Python file, auto-installs dependencies | YES | NO | NO | NO | N/A |

**mubeng** (2.1k stars, Go) — fast checker and rotator, no UI, no geo, no browser mode, no chain visualization. Good at what it does but it is a rotating proxy server, not a tool wrapper.

**ProxyBroker2** — finds, validates, and serves proxies with async Python. No proxychains integration, no live logging, no browser mode.

**NyxProxy** — closest conceptually but built for V2Ray and Xray, not free SOCKS5 lists.

---

## Repository Structure

```
drip/
├── drip_alpha.py        <- CURRENT — use this
├── drip.yml             <- auto-created config (edit this)
├── proxies.txt          <- sample proxy list
├── successful_socks5.txt<- verified working SOCKS5 proxies
├── clean.txt            <- cleaned/deduplicated proxy list
│
├── drip.py              <- v1 — first release (has known bugs, see history)
├── drip_v2.py           <- v2 — major bug fix release
├── drip_v3.py           <- v3 — VPN config, dynamic_chain default
├── drip_v4.py           <- v4 — browser mode rebuild, TX/RX logging
├── drip_v5.py           <- v5 — file locking, VPN detection hardening
├── drip_v6.py           <- v6 — signal handlers, IPv6, input sanitization
└── README.md            <- you are here
```

---

## Development Roadmap

- [ ] `proxy_checker.py` standalone — async validator that outputs `successful_socks5.txt`
- [ ] Chain integrity verification — confirm actual multi-hop path
- [ ] `--export` flag — save proxies that succeeded during a run
- [ ] Proxy scoring — weight by success rate, not just initial latency
- [ ] `--stats` summary — per-proxy success/fail count after run
- [ ] ProtonVPN auto-connect — detect raw-socket tool, auto-connect VPN if needed
- [ ] Live curses/textual dashboard — live proxy health table while running

---

## How This Was Built

3+ months, 380+ deleted prototypes. 60% written manually especially the networking code, chain line classification, and rotation engine. AI used as a specialist tool:

| AI | Used For |
|---|---|
| Claude (Anthropic) | Networking fixes, chain line classification, rotation engine architecture |
| ChatGPT (OpenAI) | Compiling and comparing reports from other AI models |
| DeepSeek | Additional networking references |
| Qwen (Alibaba) | Building proxy_checker.py, validating working proxies |
| z.ai | UI/UX, console output formatting |

Thanks to all of them. And to proxychains4 for existing.

---

## Resources and Credits

### Core Dependencies

| Tool | Link | Role |
|---|---|---|
| proxychains4 | [github.com/haad/proxychains](https://github.com/haad/proxychains) | The proxy tunneling engine drip wraps |
| Tor | [torproject.org](https://www.torproject.org/) | Auto-fallback anonymity network |
| ProtonVPN | [protonvpn.com](https://protonvpn.com/) | Recommended VPN for raw socket tools |

### Free Proxy Sources

| Source | Link | Notes |
|---|---|---|
| spys.one | [spys.one/en/socks-proxy-list/](https://spys.one/en/socks-proxy-list/) | Best free SOCKS5 list |
| VPNGate | [vpngate.net/en/](https://www.vpngate.net/en/) | Free OpenVPN configs and proxy servers |

### Verification Tools

| Tool | Link | Tests |
|---|---|---|
| DNS Leak Test | [dnsleaktest.com](https://www.dnsleaktest.com/) | DNS leaks |
| IPInfo | [ipinfo.io](https://ipinfo.io/) | IP, ASN, geolocation |
| CroxyProxy | [croxyproxy.com](https://www.croxyproxy.com/) | Cloud browser (triple-layer anonymity) |
| Proxyium | [proxyium.com](https://proxyium.com/) | Another cloud browser layer |
| ProtonVPN | [protonvpn.com](https://protonvpn.com/) | VPN baseline reference |

### Development References

| Tool | Link |
|---|---|
| Arena.ai AI comparison | [arena.ai](https://arena.ai/c/019d1b22-e703-76a0-a099-dda62f14d4b9) |

---

## Legal Disclaimer

drip is for authorized security testing, privacy research, and network education. You are responsible for ensuring you have explicit permission before testing any system you do not own. The author is not responsible for misuse.

---

<div align="center">

**Built with love in Nepal**

*3 months. 380 deleted versions. One working tool.*

[kishwordulal1234](https://github.com/kishwordulal1234) · [Report Bug](https://github.com/kishwordulal1234/drip/issues) · [Request Feature](https://github.com/kishwordulal1234/drip/issues)

[![Star this repo](https://img.shields.io/github/stars/kishwordulal1234/drip?style=social)](https://github.com/kishwordulal1234/drip/stargazers)

</div>
