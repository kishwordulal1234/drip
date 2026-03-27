#!/usr/bin/env python3
"""
drip.py — proxychains wrapper with elite UI
usage: cat proxies.txt | python3 drip.py <tool> [args]
       python3 drip.py <tool> [args]   ← tor auto
"""

import sys, os, subprocess, socket, time, threading, random, tempfile, signal
import shutil, stat, atexit, concurrent.futures, textwrap
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

def _ensure(pkg, imp=None):
    try: __import__(imp or pkg)
    except ImportError:
        subprocess.run([sys.executable,"-m","pip","install",pkg,
                        "--break-system-packages","-q"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

_ensure("rich"); _ensure("requests"); _ensure("pyyaml","yaml")

import yaml
import requests as _req
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.rule    import Rule
from rich.align   import Align
from rich.live    import Live
from rich         import box

console = Console(stderr=True)

# ── process rename ──────────────────────────────────────────────────
_RENAME_OK = False
try:
    import ctypes
    _ret = ctypes.CDLL("libc.so.6").prctl(15, b"kworker/2:1H\x00", 0, 0, 0)
    _RENAME_OK = (_ret == 0)
except Exception:
    pass

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
SCRIPT_DIR  = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "drip.yml"

GEO_CACHE_PATH = Path.home() / ".cache" / "drip" / "geo.json"
GEO_CACHE_TTL  = 86400  # 24 hours

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFAULT_CONFIG = """# drip.yml — proxychains wrapper config

# ── Chain mode (ONE = T) ───────────────────────────────
strict_chain:   F   # Strict mode fails if one proxy is dead
dynamic_chain:  T   # Dynamic mode skips dead proxies automatically
random_chain:   F   # random proxies each connection

# ── Options ───────────────────────────────────────────
chain_len:      3       # proxies in chain
timeout:        8       # connect timeout per proxy (seconds)
quick_timeout:  3000    # ms — drop proxy if no response in 3000ms
proxy_type:     socks5  # socks5 | socks4 | http (auto-detected per proxy)
proxy_dns:      T       # resolve DNS through proxy — prevents DNS leaks
tcp_read_time:  15000   # proxychains TCP read timeout ms
tcp_conn_time:  8000    # proxychains TCP connect timeout ms
country_lookup: T       # show country flags in proxy table

# ── Country blacklist ─────────────────────────────────
# Comma-separated ISO country codes to AUTO-DROP.
# Chinese/HK proxies have government firewalls that block
# most western sites (Google, YouTube, Reddit, etc.)
# These proxies look alive but silently drop your traffic.
country_blacklist: CN, HK

# ── Browser mode ───────────────────────────────────
browser_chain_len: 1    # hops for browser mode
socks_only:     F       # T = use only SOCKS proxies (drop HTTP)

# ── VPN ──────────────────────────────────────────────────
# drip does NOT auto-connect VPN.
# Connect any VPN BEFORE running drip for full anonymity.
# drip auto-detects: ProtonVPN (proton0), OpenVPN (tun0), WireGuard (wg0)
#
# For raw-socket tools (ping/nslookup/nmap -sS/traceroute):
#   these bypass proxychains without a VPN.
#   drip warns you if no VPN detected.
#
# Recommended workflow:
#   1. Open ProtonVPN → Quick Connect
#   2. cat proxies.txt | python3 drip.py <tool> [args]
"""
def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(DEFAULT_CONFIG)
    lines = []
    for line in CONFIG_PATH.read_text().splitlines():
        s = line.strip()
        if s.startswith("#"):
            lines.append("")
        elif " #" in line:
            lines.append(line[:line.index(" #")].rstrip())
        elif "\t#" in line:
            lines.append(line[:line.index("\t#")].rstrip())
        else:
            lines.append(line)
    cfg = yaml.safe_load("\n".join(lines)) or {}
    def b(k, d=False):
        v = cfg.get(k, d)
        return str(v).strip().upper() in ("T","TRUE","YES","1") if not isinstance(v, bool) else v

    # ── parse country_blacklist ──
    raw_bl = cfg.get("country_blacklist", "CN, HK")
    if isinstance(raw_bl, str):
        blacklist = {c.strip().upper() for c in raw_bl.split(",") if c.strip()}
    elif isinstance(raw_bl, list):
        blacklist = {str(c).strip().upper() for c in raw_bl if str(c).strip()}
    else:
        blacklist = set()

    return {
        "strict":      b("strict_chain", True),
        "dynamic":     b("dynamic_chain"),
        "random":      b("random_chain"),
        "chain_len":   max(1, int(cfg.get("chain_len", 3))),
        "browser_len": max(1, int(cfg.get("browser_chain_len", 3))),
        "timeout":     max(1.0, float(cfg.get("timeout", 8))),
        "quick_ms":    max(50, int(cfg.get("quick_timeout", 3000))),
        "ptype":       str(cfg.get("proxy_type", "socks5")).lower().strip(),
        "proxy_dns":   b("proxy_dns", True),
        "tcp_read":    int(cfg.get("tcp_read_time", 15000)),
        "tcp_conn":    int(cfg.get("tcp_conn_time", 8000)),
        "country":     b("country_lookup", True),
        "socks_only":  b("socks_only"),
        "country_blacklist": blacklist,
    }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FLAGS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_FLAGS_CACHE = None

def _get_flags():
    global _FLAGS_CACHE
    if _FLAGS_CACHE is None:
        _FLAGS_CACHE = {
            "AD":"🇦🇩","AE":"🇦🇪","AF":"🇦🇫","AL":"🇦🇱","AM":"🇦🇲","AO":"🇦🇴","AR":"🇦🇷",
            "AT":"🇦🇹","AU":"🇦🇺","AZ":"🇦🇿","BA":"🇧🇦","BD":"🇧🇩","BE":"🇧🇪","BG":"🇧🇬",
            "BH":"🇧🇭","BJ":"🇧🇯","BN":"🇧🇳","BO":"🇧🇴","BR":"🇧🇷","BT":"🇧🇹","BW":"🇧🇼",
            "BY":"🇧🇾","BZ":"🇧🇿","CA":"🇨🇦","CD":"🇨🇩","CF":"🇨🇫","CG":"🇨🇬","CH":"🇨🇭",
            "CI":"🇨🇮","CL":"🇨🇱","CM":"🇨🇲","CN":"🇨🇳","CO":"🇨🇴","CR":"🇨🇷","CU":"🇨🇺",
            "CY":"🇨🇾","CZ":"🇨🇿","DE":"🇩🇪","DJ":"🇩🇯","DK":"🇩🇰","DO":"🇩🇴","DZ":"🇩🇿",
            "EC":"🇪🇨","EE":"🇪🇪","EG":"🇪🇬","ES":"🇪🇸","ET":"🇪🇹","FI":"🇫🇮","FJ":"🇫🇯",
            "FR":"🇫🇷","GA":"🇬🇦","GB":"🇬🇧","GE":"🇬🇪","GH":"🇬🇭","GM":"🇬🇲","GN":"🇬🇳",
            "GR":"🇬🇷","GT":"🇬🇹","GY":"🇬🇾","HK":"🇭🇰","HN":"🇭🇳","HR":"🇭🇷","HT":"🇭🇹",
            "HU":"🇭🇺","ID":"🇮🇩","IE":"🇮🇪","IL":"🇮🇱","IN":"🇮🇳","IQ":"🇮🇶","IR":"🇮🇷",
            "IS":"🇮🇸","IT":"🇮🇹","JM":"🇯🇲","JO":"🇯🇴","JP":"🇯🇵","KE":"🇰🇪","KG":"🇰🇬",
            "KH":"🇰🇭","KP":"🇰🇵","KR":"🇰🇷","KW":"🇰🇼","KZ":"🇰🇿","LA":"🇱🇦","LB":"🇱🇧",
            "LI":"🇱🇮","LK":"🇱🇰","LR":"🇱🇷","LT":"🇱🇹","LU":"🇱🇺","LV":"🇱🇻","LY":"🇱🇾",
            "MA":"🇲🇦","MC":"🇲🇨","MD":"🇲🇩","ME":"🇲🇪","MG":"🇲🇬","MK":"🇲🇰","ML":"🇲🇱",
            "MM":"🇲🇲","MN":"🇲🇳","MR":"🇲🇷","MT":"🇲🇹","MU":"🇲🇺","MV":"🇲🇻","MW":"🇲🇼",
            "MX":"🇲🇽","MY":"🇲🇾","MZ":"🇲🇿","NA":"🇳🇦","NE":"🇳🇪","NG":"🇳🇬","NI":"🇳🇮",
            "NL":"🇳🇱","NO":"🇳🇴","NP":"🇳🇵","NZ":"🇳🇿","OM":"🇴🇲","PA":"🇵🇦","PE":"🇵🇪",
            "PG":"🇵🇬","PH":"🇵🇭","PK":"🇵🇰","PL":"🇵🇱","PT":"🇵🇹","PY":"🇵🇾","QA":"🇶🇦",
            "RO":"🇷🇴","RS":"🇷🇸","RU":"🇷🇺","RW":"🇷🇼","SA":"🇸🇦","SB":"🇸🇧","SC":"🇸🇨",
            "SD":"🇸🇩","SE":"🇸🇪","SG":"🇸🇬","SI":"🇸🇮","SK":"🇸🇰","SL":"🇸🇱","SN":"🇸🇳",
            "SO":"🇸🇴","SR":"🇸🇷","SS":"🇸🇸","SV":"🇸🇻","SY":"🇸🇾","TD":"🇹🇩","TG":"🇹🇬",
            "TH":"🇹🇭","TJ":"🇹🇯","TM":"🇹🇲","TN":"🇹🇳","TO":"🇹🇴","TR":"🇹🇷","TT":"🇹🇹",
            "TW":"🇹🇼","TZ":"🇹🇿","UA":"🇺🇦","UG":"🇺🇬","US":"🇺🇸","UY":"🇺🇾","UZ":"🇺🇿",
            "VE":"🇻🇪","VN":"🇻🇳","YE":"🇾🇪","ZA":"🇿🇦","ZM":"🇿🇲","ZW":"🇿🇼",
        }
    return _FLAGS_CACHE

def _flag(cc):
    return _get_flags().get((cc or "").upper(), "🌐")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  GEO CACHE HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _load_geo_cache():
    import json
    try:
        if GEO_CACHE_PATH.exists():
            data = json.loads(GEO_CACHE_PATH.read_text())
            if time.time() - data.get("_ts", 0) < GEO_CACHE_TTL:
                return data.get("entries", {})
    except Exception:
        pass
    return {}

def _save_geo_cache(entries):
    import json
    try:
        GEO_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        GEO_CACHE_PATH.write_text(json.dumps({"_ts": time.time(), "entries": entries}))
    except Exception:
        pass

def lookup_countries(ips, via_proxy=None):
    cache   = _load_geo_cache()
    needed  = [ip for ip in ips if ip not in cache]
    result  = {ip: cache[ip] for ip in ips if ip in cache}

    if not needed:
        return result

    proxies_dict = None
    if via_proxy:
        ptype = via_proxy.get("type", "socks5")
        addr  = f"{via_proxy['host']}:{via_proxy['port']}"
        proxies_dict = {
            "http":  f"{ptype}h://{addr}",
            "https": f"{ptype}h://{addr}",
        }

    s = _req.Session()
    s.trust_env = False
    if proxies_dict:
        s.proxies = proxies_dict

    for i in range(0, len(needed), 100):
        batch = needed[i:i+100]
        try:
            r = s.post(
                "http://ip-api.com/batch?fields=query,countryCode,country,city",
                json=[{"query": ip} for ip in batch], timeout=8
            )
            for e in r.json():
                ip = e.get("query", ""); cc = e.get("countryCode", "??")
                result[ip] = {
                    "code": cc, "country": e.get("country", "?"),
                    "city": e.get("city", ""), "flag": _flag(cc)
                }
        except Exception:
            for ip in batch:
                result[ip] = {"code": "??", "country": "?", "city": "", "flag": "🌐"}

    cache.update(result)
    _save_geo_cache(cache)
    return result

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COUNTRY BLACKLIST FILTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def filter_blacklisted_countries(proxies, countries, blacklist, lats=None):
    """
    Remove proxies whose country code is in the blacklist set.
    Returns (kept, dropped_count, dropped_details).
    dropped_details is a dict: {country_code: count}
    """
    if not blacklist:
        return proxies, 0, {}

    kept    = []
    dropped = {}

    for px in proxies:
        ci = countries.get(px["host"], {})
        cc = ci.get("code", "??").upper()

        if cc in blacklist:
            dropped[cc] = dropped.get(cc, 0) + 1
        else:
            kept.append(px)

    total_dropped = sum(dropped.values())
    return kept, total_dropped, dropped

def show_blacklist_results(total_before, total_dropped, dropped_details, blacklist):
    """Show a panel summarizing what got dropped."""
    if not blacklist:
        return
    if total_dropped == 0 and dropped_details:
        return

    lines = []
    if total_dropped > 0:
        lines.append(f"[bold #FF0000]🚫 COUNTRY BLACKLIST — {total_dropped} proxies dropped[/bold #FF0000]")
        lines.append("")
        for cc in sorted(dropped_details.keys()):
            fl = _flag(cc)
            cnt = dropped_details[cc]
            lines.append(f"  {fl} [bold #FF0000]{cc}[/bold #FF0000]  →  [bold white]{cnt}[/bold white] dropped")
        lines.append("")
        lines.append(f"  [dim]{total_before} total → {total_before - total_dropped} kept[/dim]")
        lines.append(f"  [dim]blacklist: {', '.join(sorted(blacklist))}[/dim]")
        lines.append(f"  [dim]edit drip.yml → country_blacklist to change[/dim]")
    else:
        lines.append(f"[dim]🚫 blacklist active ({', '.join(sorted(blacklist))}) — 0 dropped (none matched)[/dim]")

    if total_dropped > 0:
        console.print(Panel(
            "\n".join(lines),
            title="[bold #FF0000]🚫 BLACKLISTED COUNTRIES[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)
        ))
    else:
        console.print("  " + lines[0])
    console.print()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PORT SETS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_HTTP_PROXY_PORTS  = frozenset({80, 81, 443, 3128, 3129, 8008, 8080,
                                 8118, 8123, 8181, 8888, 6588, 3333})
_SOCKS_PROXY_PORTS = frozenset({1080, 1081, 1082, 1083, 9050, 9150})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY PARSING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_proxies(text, ptype="socks5"):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split(":", 3)
        try:
            if len(p) == 2:
                out.append({"host": p[0], "port": int(p[1]),
                            "user": None, "pwd": None, "type": ptype})
            elif len(p) >= 4:
                out.append({"host": p[0], "port": int(p[1]),
                            "user": p[2], "pwd": p[3], "type": ptype})
        except Exception:
            pass
    return out

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIFIED PROXY TYPE CLASSIFIER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _classify_type(declared_type, port):
    if port in _HTTP_PROXY_PORTS:
        return "http"
    if port in _SOCKS_PROXY_PORTS:
        pt = (declared_type or "socks5").lower()
        return pt if pt.startswith("socks") else "socks5"
    pt = (declared_type or "socks5").lower()
    if pt in ("socks5", "socks5h"):  return "socks5"
    if pt in ("socks4", "socks4a"):  return "socks4"
    if pt in ("http", "https"):      return "http"
    return "socks5"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FAST FILTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _probe_and_time(px, ms):
    t0 = time.perf_counter()
    try:
        s = socket.socket()
        s.settimeout(ms / 1000.0)
        s.connect((px["host"], px["port"]))
        lat = int((time.perf_counter() - t0) * 1000)

        s.settimeout(1.5)
        try:
            s.sendall(bytes([5, 1, 0]))
            data = s.recv(2)
            if data and data[0] == 5:
                detected = "socks5"
            elif data and data[0] == 4:
                detected = "socks4"
            else:
                detected = "http"
        except Exception:
            detected = _classify_type(px.get("type"), px["port"])
        finally:
            s.close()
        return lat, detected
    except Exception:
        return None, None

def fast_filter(proxies, ms, workers=50):
    fast = []; lats = {}
    console.print(
        f"  [dim]probing {len(proxies)} proxies "
        f"(latency + protocol, {ms}ms cutoff)...[/dim]", end=" "
    )
    with ThreadPoolExecutor(max_workers=min(workers, len(proxies))) as ex:
        futs = {ex.submit(_probe_and_time, px, ms): px for px in proxies}
        for f in as_completed(futs):
            px = futs[f]
            lat, detected = f.result()
            if lat is not None:
                px = {**px, "type": detected}
                fast.append(px)
                lats[(px["host"], px["port"])] = lat

    fast.sort(key=lambda p: lats.get((p["host"], p["port"]), 9999))
    console.print(f"[bold #FF0000]{len(fast)}/{len(proxies)} passed[/]")
    return fast, lats

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY TYPE ANALYSIS + WARNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def analyze_proxy_types(proxies):
    counts = {"socks5": 0, "socks4": 0, "http": 0}
    typed  = []
    for p in proxies:
        t = _classify_type(p.get("type"), p.get("port", 0))
        if t not in counts:
            t = "socks5"
        counts[t] += 1
        typed.append({**p, "type": t})
    return typed, counts

def show_proxy_type_warning(counts, socks_only=False):
    socks_count = counts["socks5"] + counts["socks4"]
    http_count  = counts["http"]
    if http_count == 0:
        return
    lines = []
    if socks_count > 0 and http_count > 0:
        lines.append("[bold #FF0000]⚠️  MIXED PROXY TYPES DETECTED![/bold #FF0000]")
        lines.append("")
        if counts["socks5"]: lines.append(f"  [bold #FF0000]{counts['socks5']}[/bold #FF0000] SOCKS5")
        if counts["socks4"]: lines.append(f"  [bold #FF0000]{counts['socks4']}[/bold #FF0000] SOCKS4")
        if counts["http"]:   lines.append(f"  [bold #0055FF]{counts['http']}[/bold #0055FF]  HTTP")
        lines.append("")
        if socks_only:
            lines.append(f"  [bold #FF0000]HTTP proxies SKIPPED[/bold #FF0000] (socks_only=T)")
        else:
            lines.append("  [dim]All types used via pproxy auto-detection[/dim]")
    elif http_count > 0 and socks_count == 0:
        lines.append("[bold #FF0000]⚠️  ALL PROXIES ARE HTTP[/bold #FF0000]")
        lines.append("  [dim]Multi-hop tunneling is unreliable over HTTP proxies[/dim]")
        lines.append("  [dim]Use SOCKS4/SOCKS5 for better results[/dim]")
    if lines:
        console.print(Panel(
            "\n".join(lines),
            title="[bold #FF0000]PROXY TYPE WARNING[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)
        ))
        console.print()

def select_browser_chain(proxies_typed, cfg, lats=None):
    blen      = cfg.get("browser_len", 3)
    socks_only = cfg.get("socks_only", False)

    pool = proxies_typed
    if socks_only:
        pool = [p for p in pool if p.get("type", "socks5") != "http"]
        if not pool:
            console.print("[#FF0000]⚠️  socks_only=T but no SOCKS proxies — using all[/]")
            pool = proxies_typed

    if not pool:
        return []

    if cfg.get("strict"):
        selected = pool[:blen]
        console.print(f"  [dim]strict chain: first {len(selected)} of {len(pool)}[/dim]")
    elif cfg.get("random"):
        selected = random.sample(pool, min(blen, len(pool)))
        console.print(f"  [dim]random chain: {len(selected)} random[/dim]")
    else:
        top_n = min(100, len(pool))
        top   = pool[:top_n]
        selected = random.sample(top, min(blen, len(top)))
        console.print(f"  [dim]dynamic chain: {len(selected)} from top-{top_n} fastest[/dim]")

    return selected

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WRITE PROXYCHAINS CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def write_pc_conf(proxies, cfg, tor_mode=False, chain_len=None):
    lines = []
    clen = chain_len or cfg["chain_len"]

    if tor_mode:
        lines.append("dynamic_chain")
    elif cfg["strict"]:
        lines.append("strict_chain")
    elif cfg["random"]:
        lines.append("random_chain")
        lines.append(f"chain_len {clen}")
    else:
        lines.append("dynamic_chain")

    if cfg["proxy_dns"]: lines.append("proxy_dns")
    lines.append(f"tcp_read_time_out {cfg['tcp_read']}")
    lines.append(f"tcp_connect_time_out {cfg['tcp_conn']}")
    lines.append("")
    lines.append("[ProxyList]")

    if tor_mode:
        lines.append(f"socks5 {TOR_HOST} {TOR_PORT}")
    else:
        for px in proxies:
            t = _classify_type(px.get("type"), px.get("port", 0))
            if t.startswith("socks4"): t = "socks4"
            elif t == "http":          t = "http"
            else:                      t = "socks5"
            if px.get("user"):
                lines.append(f"{t} {px['host']} {px['port']} {px['user']} {px['pwd'] or ''}")
            else:
                lines.append(f"{t} {px['host']} {px['port']}")

    conf = "\n".join(lines) + "\n"
    tmp  = tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, prefix="drip_pc_"
    )
    tmp.write(conf); tmp.flush(); tmp.close()
    os.chmod(tmp.name, stat.S_IRUSR | stat.S_IWUSR)
    return tmp.name

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIND PROXYCHAINS BINARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def find_proxychains():
    for name in ["proxychains4", "proxychains"]:
        r = subprocess.run(["which", name], capture_output=True, text=True)
        if r.returncode == 0:
            path = r.stdout.strip()
            if name == "proxychains4":
                f_works = True
            else:
                try:
                    ver = subprocess.run([path, "--version"],
                                         capture_output=True, text=True, timeout=2)
                    combined = (ver.stdout + ver.stderr).lower()
                    if "4." in combined or "proxychains-ng" in combined:
                        f_works = True
                    elif "3." in combined:
                        f_works = False
                    else:
                        tmp = tempfile.NamedTemporaryFile(
                            mode="w", suffix=".conf", delete=False
                        )
                        tmp.write("dynamic_chain\nproxy_dns\n[ProxyList]\nsocks5 1.2.3.4 1080\n")
                        tmp.flush(); tmp.close()
                        test = subprocess.run(
                            [path, "-f", tmp.name, "echo", "drip_test"],
                            capture_output=True, text=True, timeout=3
                        )
                        os.unlink(tmp.name)
                        out_all = test.stdout + test.stderr
                        f_works = ("9050" not in out_all and "tor" not in out_all.lower()
                                   and test.returncode in (0, 1))
                except Exception:
                    f_works = False
            return path, f_works
    return None, False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IP HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_real_ip():
    """Get our real public IP, bypassing any proxy/env settings."""
    import re
    services = [
        ["curl", "-s", "--max-time", "5", "--noproxy", "*", "http://api.ipify.org"],
        ["curl", "-s", "--max-time", "5", "--noproxy", "*", "http://icanhazip.com"],
        ["curl", "-s", "--max-time", "5", "--noproxy", "*", "http://checkip.amazonaws.com"],
        ["curl", "-s", "--max-time", "5", "--noproxy", "*", "http://ifconfig.me/ip"],
        ["curl", "-s", "--max-time", "5", "--noproxy", "*", "http://ipecho.net/plain"],
    ]
    for cmd in services:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            ip = r.stdout.strip().splitlines()[0].strip()
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            pass
    return None

def get_exit_ip(pc_bin, pc_conf, is_v4, timeout=8):
    import re
    endpoints = [
        "http://api.ipify.org",
        "http://icanhazip.com",
        "http://checkip.amazonaws.com",
    ]
    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"] = pc_conf

    for url in endpoints:
        try:
            if is_v4:
                cmd = [pc_bin, "-f", pc_conf, "-q", "curl", "-s",
                       "--max-time", str(timeout), url]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout + 3)
            else:
                cmd = [pc_bin, "curl", "-s", "--max-time", str(timeout), url]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=timeout + 3, env=env)
            for line in r.stdout.splitlines():
                line = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                    return line
        except Exception:
            pass
    return None

def _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei, chain_len=None):
    lines = []
    r_flag = ri.get("flag", "🌐"); r_cn = ri.get("country", "?"); r_city = ri.get("city", "")
    lines.append(f"  [bold white]YOUR MACHINE[/bold white]")
    if real_ip:
        lines.append(f"  [bold #FF0000]  IP  : {real_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {r_flag} {r_cn}, {r_city}[/dim]")
        lines.append(f"  [dim]  ← your real identity[/dim]")
    else:
        lines.append(f"  [dim]  IP  : unknown[/dim]")
    lines.append("")
    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼  (traffic enters here)[/dim]")
    lines.append("")
    lines.append(f"  [bold white]ENTRY PROXY  (knows your real IP)[/bold white]")
    if entry_px:
        p_flag = pi.get("flag", "🌐"); p_cn = pi.get("country", "?"); p_city = pi.get("city", "")
        lines.append(f"  [bold #00BFFF]  IP  : {entry_px['host']}:{entry_px['port']}[/bold #00BFFF]")
        lines.append(f"  [dim]  LOC : {p_flag} {p_cn}, {p_city}[/dim]")
        lines.append(f"  [dim]  TYPE: {entry_px['type'].upper()}[/dim]")
    lines.append("")
    actual_hops = chain_len if chain_len else len(proxies)
    if actual_hops > 1:
        lines.append("        [dim]│[/dim]")
        lines.append(f"        [dim]▼  ({actual_hops-1} more hop(s) through chain)[/dim]")
        lines.append("")
    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼  (traffic exits here)[/dim]")
    lines.append("")
    lines.append(f"  [bold white]EXIT IP  (what the target sees)[/bold white]")
    if exit_ip:
        e_flag = ei.get("flag", "🌐"); e_cn = ei.get("country", "?"); e_city = ei.get("city", "")
        lines.append(f"  [bold #FF0000]  IP  : {exit_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {e_flag} {e_cn}, {e_city}[/dim]")
        if real_ip and exit_ip != real_ip:
            lines.append(f"  [bold #FF0000]  ✅  real IP {real_ip} is HIDDEN[/bold #FF0000]")
        elif real_ip and exit_ip == real_ip:
            lines.append(f"  [bold #0055FF]  ⚠️   exit = real IP — proxy NOT working[/bold #0055FF]")
    else:
        lines.append(f"  [dim]  IP  : could not confirm[/dim]")
    lines.append("")
    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼[/dim]")
    lines.append("")
    lines.append("  [bold white]TARGET[/bold white]")
    lines.append("  [dim]  sees only exit IP — never your real IP[/dim]")
    return "\n".join(lines)

def preflight(proxies, cfg, lats, countries, pc_bin, pc_conf, tor_mode, is_v4=True, chain_len=None):
    console.print()
    if tor_mode:
        console.print("  [dim]checking Tor...[/dim]", end=" ")
        try:
            s = socket.create_connection((TOR_HOST, TOR_PORT), timeout=5)
            s.close()
            console.print("[bold #FF0000]✅ Tor up[/]")
        except Exception:
            console.print("[bold #FF0000]❌ Tor not running[/]")
            return False, None
    else:
        sample = proxies[:min(5, len(proxies))]
        parts  = []
        for p in sample:
            ci = countries.get(p["host"], {}); fl = ci.get("flag", "🌐"); cn = ci.get("country", "?")
            parts.append(f"{fl}[bold #00BFFF]{p['host']}:{p['port']}[/][dim]({cn})[/dim]")
        if len(proxies) > 5:
            parts.append(f"[dim]+{len(proxies)-5} more[/dim]")
        console.print("  chain: " + "[dim]→[/dim]".join(parts) + "[dim]→TARGET[/dim]")
        console.print()

        t = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold #FF0000", padding=(0, 1))
        t.add_column("#", width=3, style="dim")
        t.add_column("proxy", min_width=22, style="bold #00BFFF")
        t.add_column("country", min_width=14)
        t.add_column("city", min_width=12, style="dim")
        t.add_column("type", width=7)
        t.add_column("latency", width=10, justify="right")
        t.add_column("", width=3)

        for i, px in enumerate(proxies[:20], 1):
            ci  = countries.get(px["host"], {}); fl = ci.get("flag", "🌐")
            cn  = ci.get("country", "?"); ct = ci.get("city", "")
            lat = lats.get((px["host"], px["port"]))
            ls  = f"[bold #FF0000]{lat}ms[/]" if lat else "—"
            st  = "[#FF0000]✅[/]" if lat else "[#0055FF]❌[/]"
            t.add_row(str(i), f"{px['host']}:{px['port']}", f"{fl} {cn}",
                      ct, px["type"].upper(), ls, st)
        if len(proxies) > 20:
            t.add_row("…", f"[dim]+{len(proxies)-20} more[/dim]", "", "", "", "", "")
        console.print(Align.center(t))

    console.print()
    console.print("  [dim]resolving IPs...[/dim]", end="")

    real_ip = get_real_ip()

    # In tor_mode proxies=[] so synthesise a Tor entry dict so the panel renders
    if tor_mode:
        entry_px = {"host": TOR_HOST, "port": TOR_PORT,
                    "type": "socks5", "user": None, "pwd": None}
    else:
        entry_px = proxies[0] if proxies else None

    exit_result = [None]

    def _fetch_exit():
        exit_result[0] = get_exit_ip(pc_bin, pc_conf, is_v4, timeout=7)

    exit_thread = threading.Thread(target=_fetch_exit, daemon=True)
    exit_thread.start()
    exit_thread.join(timeout=9)
    exit_ip = exit_result[0]

    if exit_ip:
        console.print(f"[bold #FF0000]exit IP: {exit_ip}[/bold #FF0000]")
    else:
        console.print("[dim]exit IP not confirmed (proxies may be slow)[/dim]")

    ips_to_lookup = [ip for ip in [real_ip, exit_ip] if ip]
    geo = lookup_countries(ips_to_lookup, via_proxy=entry_px) if ips_to_lookup else {}

    ri = geo.get(real_ip, {}) if real_ip else {}
    ei = geo.get(exit_ip, {}) if exit_ip else {}

    # Tor mode: show "Tor Network" as the entry location
    if tor_mode:
        pi = {"flag": "🧅", "country": "Tor Network", "city": ""}
    else:
        pi = countries.get(entry_px["host"], {}) if entry_px else {}

    console.print()
    console.print(Panel(
        _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei,
                       chain_len=chain_len or cfg.get("chain_len", 3)),
        title="[bold white]IP FLOW — what each side sees[/bold white]",
        border_style="#FF0000", padding=(0, 2),
    ))
    console.print()
    return True, exit_ip

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_tor():
    try:
        s = socket.create_connection((TOR_HOST, TOR_PORT), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def ensure_tor():
    if check_tor():
        return True
    console.print("[#FF0000]🧅 starting Tor...[/]")
    for cmd, label in [
        (["systemctl", "start", "tor"], "systemctl"),
        (["service",   "tor", "start"], "service"),
    ]:
        try:
            console.print(f"  [dim]trying {label}...[/dim]", end=" ")
            r = subprocess.run(cmd, timeout=8)
            if r.returncode == 0:
                console.print("[dim]ok[/dim]")
                for _ in range(6):
                    time.sleep(1)
                    if check_tor():
                        console.print("[#FF0000]✅ Tor started[/]")
                        return True
            else:
                console.print("[dim]failed[/dim]")
        except Exception as e:
            console.print(f"[dim]{e}[/dim]")

    try:
        console.print("  [dim]trying direct tor binary...[/dim]", end=" ")
        subprocess.Popen(["tor"],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        for _ in range(8):
            time.sleep(1)
            if check_tor():
                console.print("[#FF0000]✅ Tor started[/]")
                return True
        console.print("[dim]timed out[/dim]")
    except Exception:
        pass
    return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LIVE OUTPUT PARSER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def stream_with_live_log(proc, proxies, countries, cfg, ok_count, fail_count):
    """
    ok_count / fail_count are [int] single-element lists shared with main()
    so the footer can display real totals.
    """
    import re
    conn_n    = [0]
    conn_lock = threading.Lock()
    ip_info   = {p["host"]: countries.get(p["host"], {}) for p in proxies}

    def _fmt_ip(ip):
        ci = ip_info.get(ip, {})
        fl = ci.get("flag", "🌐"); cc = ci.get("code", "??")
        return f"{fl}[bold #00BFFF]{ip}[/bold #00BFFF][dim]({cc})[/dim]"

    def _print_conn(chain_ips, dest_ip, dest_port, ok):
        with conn_lock:
            conn_n[0] += 1; n = conn_n[0]
            # update shared counters so footer totals are correct
            if ok:
                ok_count[0]   += 1
            else:
                fail_count[0] += 1
        ts = time.strftime("%H:%M:%S")
        st = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]✗  [/]"
        hops = [_fmt_ip(ip) for ip in chain_ips]
        if dest_ip and dest_ip not in chain_ips:
            hops.append(f"[bold white]{dest_ip}:{dest_port}[/bold white]")
        chain_s = " [dim]→[/dim] ".join(hops) if hops else "[dim]chain[/dim]"
        console.print(f"  [dim]#{n:04d} {ts}[/dim] {st}  {chain_s}")

    def _read_stdout():
        for line in iter(proc.stdout.readline, ""):
            stripped = line.strip()
            skip = (
                "|S-chain|"    in stripped or
                "|D-chain|"    in stripped or
                "|DNS-"        in stripped or
                "ProxyChains"  in stripped or
                "proxychains"  in stripped.lower() or
                (stripped.isdigit() and len(stripped) <= 6)
            )
            if not skip:
                sys.stdout.write(line); sys.stdout.flush()

    def _read_stderr():
        for raw in iter(proc.stderr.readline, ""):
            line = raw.strip()
            # FIX: handle both |S-chain| (strict) AND |D-chain| (dynamic)
            if "|S-chain|" in line or "|D-chain|" in line:
                if "-denied" in line or "-timeout" in line:
                    pairs = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    if pairs:
                        chain_ips          = [ip for ip, _ in pairs[:-1]]
                        dest_ip, dest_port = pairs[-1]
                        _print_conn(chain_ips, dest_ip, dest_port, False)
                    else:
                        console.print(f"  [bold #FF0000]chain failed: {line[:80]}[/bold #FF0000]")
                else:
                    pairs = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                    ok    = line.rstrip().endswith("-OK")
                    if pairs:
                        chain_ips          = [ip for ip, _ in pairs[:-1]]
                        dest_ip, dest_port = pairs[-1]
                        _print_conn(chain_ips, dest_ip, dest_port, ok)
                continue
            if "|DNS-request|" in line:
                host = line.split("|DNS-request|")[-1].strip()
                console.print(f"  [dim]DNS  → {host}[/dim]")
                continue
            if "|DNS-response|" in line:
                info = line.split("|DNS-response|")[-1].strip()
                console.print(f"  [dim]DNS  ← {info}[/dim]")
                continue
            if "ProxyChains" in line or "proxychains.sf.net" in line:
                continue
            sys.stderr.write(raw); sys.stderr.flush()

    t1 = threading.Thread(target=_read_stdout, daemon=True)
    t2 = threading.Thread(target=_read_stderr, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SHARED INFO TABLE HELPER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _make_kv_table(rows):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="#00BFFF bold")
    t.add_column(style="bold white")
    for k, v in rows:
        t.add_row(k, v)
    return t

def print_banner(cfg, proxies, tool_args, tor_mode, pc_bin, pc_conf):
    mode = ("[#FF0000]RANDOM[/]"  if cfg["random"] else
            "[#FF0000]STRICT[/]"  if cfg["strict"] else "[#00BFFF]DYNAMIC[/]")
    src  = ("[#FF0000]🧅 TOR[/] (auto)" if tor_mode else
            f"[#FF0000]{len(proxies)}[/] proxies  [dim](>{cfg['quick_ms']}ms skipped)[/dim]")

    bl = cfg.get("country_blacklist", set())
    bl_str = ", ".join(sorted(bl)) if bl else "[dim]none[/dim]"

    rows = [
        ("⛓️  chain mode",   mode),
        ("📡  source",       src),
        ("🚫  blacklist",    bl_str),
        ("🔧  backend",      f"[#FF0000]{pc_bin}[/]"),
        ("📄  config",       f"[dim]{pc_conf}[/dim]"),
        ("⏱️  timeout",       f"{cfg['timeout']}s  [dim](tcp: {cfg['tcp_conn']}ms)[/dim]"),
        ("🌐  proxy dns",    "[#FF0000]ON[/]" if cfg["proxy_dns"] else "[#0055FF]OFF[/]"),
        ("🕵️  process name", f"kworker/2:1H {'✅' if _RENAME_OK else '[dim](rename unavailable)[/dim]'}"),
        ("🚀  command",      " ".join(tool_args)),
    ]
    console.print()
    console.print(Panel(
        _make_kv_table(rows),
        title="[bold #FF0000]🔥🩸 DRIP — PROXYCHAINS WRAPPER 🩸🔥[/]",
        border_style="#0055FF", padding=(0, 2)
    ))
    console.print()

def print_footer(elapsed, exit_ip, ok_count, fail_count, tor_mode, proxies):
    rows = [
        ("✅  connections ok",     str(ok_count)),
        ("❌  connections failed", str(fail_count)),
    ]
    if not tor_mode:
        rows.append(("📦  proxies used", str(len(proxies))))
    rows.append(("⏱️   elapsed", f"{elapsed:.1f}s"))
    if exit_ip:
        rows.append(("🔴  exit IP", exit_ip))
    console.print()
    console.print(Rule(style="#FF0000"))
    console.print(Align.center(Panel(
        _make_kv_table(rows),
        title="[#FF0000]🩸 DONE 🩸[/]",
        border_style="#0055FF", padding=(0, 2)
    )))
    console.print()

def print_usage():
    console.print(Panel(
        "[#FF0000]Usage:[/]\n"
        "  [white]cat proxies.txt | python3 drip.py <tool> [args][/]\n"
        "  [white]python3 drip.py <tool> [args][/]       [dim]← no proxies = Tor auto[/dim]\n"
        "  [white]python3 drip.py --browser[/]            [dim]← launch Firefox (DNS-safe)[/dim]\n"
        "  [white]cat p.txt | python3 drip.py --browser[/]\n\n"
        "[#00BFFF]Why Firefox?[/]\n"
        "  [bold #FF0000]Firefox[/bold #FF0000] is the ONLY browser that routes DNS through SOCKS5.\n"
        "  [dim]Set: network.proxy.socks_remote_dns = true\n"
        "       network.trr.mode = 5\n"
        "  Chromium/Chrome/Brave have their own DNS stack — it bypasses proxychains.\n"
        "  WebRTC leaks your real IP in Chrome even with proxies.[/dim]\n\n"
        "[#00BFFF]ICMP / Ping:[/]\n"
        "  [dim]ping uses ICMP — not proxychainable. Use TCP-ping instead:\n"
        "  cat p.txt | python3 drip.py nmap -sT -Pn -p 80 target[/dim]\n\n"
        "[#00BFFF]Examples:[/]\n"
        '  [dim]cat p.txt | python3 drip.py sqlmap -u "http://target.com?id=1"\n'
        "  cat p.txt | python3 drip.py nmap -sT target.com\n"
        "  cat p.txt | python3 drip.py --browser[/]\n\n"
        "[#00BFFF]Proxy formats:[/]\n"
        "  [dim]ip:port\n  ip:port:user:pass  (pass may contain colons)[/]\n\n"
        "[#00BFFF]Country blacklist:[/]\n"
        "  [dim]drip.yml → country_blacklist: CN, HK\n"
        "  Chinese/HK proxies have GFW firewalls that silently block sites.\n"
        "  Add any ISO country codes to auto-drop them.[/dim]\n\n"
        "[#00BFFF]Config:[/] [dim]drip.yml (auto-created)[/]",
        title="[#FF0000]🔥 DRIP — PROXYCHAINS WRAPPER 🔥[/]",
        border_style="#0055FF", padding=(1, 4)
    ))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR BROWSER / FIREFOX HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOR_BROWSER_CMDS = [
    "torbrowser-launcher", "tor-browser", "tor-browser-en",
    "/usr/bin/torbrowser-launcher",
    "/opt/tor-browser/Browser/start-tor-browser",
]

LEAKY_BROWSERS = {
    "chromium":        "DNS and WebRTC leak — cannot be fixed with proxychains",
    "chromium-browser":"DNS and WebRTC leak",
    "chrome":          "DNS and WebRTC leak",
    "google-chrome":   "DNS and WebRTC leak",
    "brave-browser":   "DNS leak — own DNS resolver bypasses proxychains",
    "opera":           "DNS and WebRTC leak",
    "vivaldi":         "DNS leak",
    "microsoft-edge":  "DNS and WebRTC leak",
}

TOR_BROWSER_DIRECT = [
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/start-tor-browser"),
    "/opt/tor-browser/Browser/start-tor-browser",
    "/usr/bin/tor-browser",
]

def _make_tor_wrapper(browser_dir):
    firefox_direct = os.path.join(browser_dir, "firefox")
    profile_direct = os.path.join(browser_dir, "TorBrowser", "Data", "Browser", "profile.default")
    tb_script      = os.path.join(browser_dir, "start-tor-browser")

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, prefix="drip_tb_", dir="/tmp"
    )
    wrapper_path = tmp.name

    if os.path.exists(firefox_direct):
        tmp.write(
            "#!/bin/bash\n"
            f"cd \"{browser_dir}\"\n"
            f"exec ./firefox --profile \"{profile_direct}\" --no-remote 2>/dev/null\n"
        )
    elif os.path.exists(tb_script):
        tmp.write(
            "#!/bin/bash\n"
            f"cd \"{browser_dir}\"\n"
            "./start-tor-browser 2>/dev/null &\n"
            "sleep 3\n"
            "FBPID=$(pgrep -f \"tor-browser.*/firefox\" 2>/dev/null | head -1)\n"
            "[ -z \"$FBPID\" ] && FBPID=$(pgrep -f \"Browser/firefox\" 2>/dev/null | head -1)\n"
            "[ -n \"$FBPID\" ] && tail --pid=\"$FBPID\" -f /dev/null 2>/dev/null || wait\n"
        )
    else:
        tmp.write(
            "#!/bin/bash\n"
            "torbrowser-launcher 2>/dev/null &\n"
            "sleep 3\n"
            "FBPID=$(pgrep -f \"Browser/firefox\" 2>/dev/null | head -1)\n"
            "[ -n \"$FBPID\" ] && tail --pid=\"$FBPID\" -f /dev/null 2>/dev/null || wait\n"
        )
    tmp.flush(); tmp.close()
    os.chmod(wrapper_path, stat.S_IRWXU)
    atexit.register(lambda p=wrapper_path: os.unlink(p) if os.path.exists(p) else None)
    return [wrapper_path]

def find_tor_browser():
    for path in TOR_BROWSER_DIRECT:
        if os.path.exists(path):
            return path, True
    for cmd in TOR_BROWSER_CMDS:
        r = subprocess.run(["which", cmd], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip(), False
        if os.path.exists(cmd):
            return cmd, False
    return None, False

def launch_tor_browser_setup():
    console.print("[bold #FF0000]🧅 Tor Browser — the only truly anonymous browser[/]")
    tb, is_direct = find_tor_browser()
    if tb:
        if is_direct:
            console.print("[dim]  found: direct binary[/dim]")
            return _make_tor_wrapper(os.path.dirname(tb))
        else:
            console.print("[dim]  found: launcher — checking for direct binary...[/dim]")
            for path in TOR_BROWSER_DIRECT:
                if os.path.exists(path):
                    console.print(f"[dim]  using direct: {path}[/dim]")
                    return _make_tor_wrapper(os.path.dirname(path))
            console.print("[dim]  first run — Tor Browser will install, then rerun[/dim]")
            return [tb]
    console.print("[dim]  torbrowser-launcher not found — installing...[/dim]")
    try:
        ok = _sudo_run(["sudo", "apt", "install", "-y", "torbrowser-launcher"],
                       timeout=120)
        if ok:
            tb, _ = find_tor_browser()
            if tb: return [tb]
    except Exception:
        pass
    console.print("[#FF0000]❌ could not install torbrowser-launcher[/]")
    return None

def _find_firefox():
    for name in ["firefox-esr", "firefox"]:
        r = subprocess.run(["which", name], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None

def _get_real_user():
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and sudo_user != "root":
        return sudo_user
    return os.environ.get("USER", "")

def _get_all_firefox_profiles():
    import glob, configparser
    profiles = []
    _homes = set()
    _homes.add(os.path.expanduser("~"))
    _sudo_user = os.environ.get("SUDO_USER", "")
    if _sudo_user and _sudo_user != "root":
        _homes.add(f"/home/{_sudo_user}")
    bases = []
    for _home in _homes:
        bases.append(os.path.join(_home, ".mozilla", "firefox"))
        bases.append(os.path.join(_home, ".firefox"))
    for base in bases:
        if not os.path.exists(base): continue
        ini = os.path.join(base, "profiles.ini")
        if os.path.exists(ini):
            cfg = configparser.ConfigParser()
            cfg.read(ini)
            for section in cfg.sections():
                path = cfg.get(section, "Path", fallback=None)
                if not path: continue
                full = (os.path.join(base, path)
                        if cfg.get(section, "IsRelative", fallback="0") == "1"
                        else path)
                if os.path.isdir(full) and full not in profiles:
                    profiles.append(full)
        for pattern in ["*.default-esr", "*.default", "*.default-release", "*.esr"]:
            for p in glob.glob(os.path.join(base, pattern)):
                if p not in profiles:
                    profiles.append(p)
    return profiles

def _find_firefox_profile():
    profiles = _get_all_firefox_profiles()
    return profiles[0] if profiles else None

def _patch_firefox_profile(profile_dir, socks_port=None):
    import re
    port = socks_port or 9150

    user_js_content = textwrap.dedent(f"""\
        // drip.py — proxy + DNS leak fix (auto-generated, restored on exit)
        user_pref("network.proxy.type", 1);
        user_pref("network.proxy.socks", "127.0.0.1");
        user_pref("network.proxy.socks_port", {port});
        user_pref("network.proxy.socks_version", 5);
        user_pref("network.proxy.socks_remote_dns", true);
        user_pref("network.trr.mode", 5);
        user_pref("network.trr.uri", "");
        user_pref("network.trr.bootstrapAddr", "");
        user_pref("network.dns.disablePrefetch", true);
        user_pref("network.dns.disablePrefetchFromHTTPS", true);
        user_pref("network.predictor.enabled", false);
        user_pref("network.prefetch-next", false);
        user_pref("media.peerconnection.enabled", false);
        user_pref("media.peerconnection.ice.default_address_only", true);
        user_pref("network.proxy.no_proxies_on", "");
    """)

    user_js = os.path.join(profile_dir, "user.js")
    Path(user_js).write_text(user_js_content)

    prefs_js = os.path.join(profile_dir, "prefs.js")
    if os.path.exists(prefs_js):
        backup_path = prefs_js + ".drip_backup"
        if not os.path.exists(backup_path):
            shutil.copy2(prefs_js, backup_path)
        atexit.register(_restore_firefox_profile, profile_dir)

        prefs = Path(prefs_js).read_text()
        patches = {
            "network.proxy.type":             "1",
            "network.proxy.socks":            '"127.0.0.1"',
            "network.proxy.socks_port":       str(port),
            "network.proxy.socks_version":    "5",
            "network.proxy.socks_remote_dns": "true",
            "network.trr.mode":               "5",
            "network.dns.disablePrefetch":    "true",
            "media.peerconnection.enabled":   "false",
            "network.proxy.no_proxies_on":    '""',
        }
        for key, val in patches.items():
            prefs = re.sub(rf'user_pref\("{re.escape(key)}".*?\);\n', "", prefs)
            prefs += f'user_pref("{key}", {val});\n'
        Path(prefs_js).write_text(prefs)
    return user_js

def _restore_firefox_profile(profile_dir):
    prefs_js    = os.path.join(profile_dir, "prefs.js")
    backup_path = prefs_js + ".drip_backup"
    user_js     = os.path.join(profile_dir, "user.js")
    try:
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, prefs_js)
            os.unlink(backup_path)
        if os.path.exists(user_js):
            os.unlink(user_js)
    except Exception:
        pass

def _patch_all_profiles(socks_port=None):
    profiles = _get_all_firefox_profiles()
    if not profiles: return []
    patched = []
    for p in profiles:
        try:
            _patch_firefox_profile(p, socks_port)
            patched.append(p)
        except Exception:
            pass
    return patched

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LOCAL SOCKS5 FORWARDER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _start_local_socks5(proxies, cfg, tor_mode):
    import socket as _sock

    if tor_mode:
        chain = [{"host": "127.0.0.1", "port": 9050,
                  "type": "socks5", "user": None, "pwd": None}]
    else:
        chain = [{"host": p["host"], "port": p["port"],
                  "type": p.get("type", "socks5"),
                  "user": p.get("user"), "pwd": p.get("pwd")}
                 for p in proxies]

    import json

    try:
        import pproxy as _pp  # noqa
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pproxy",
                        "--break-system-packages", "-q"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    import json as _json
    all_proxy_list = []
    if not tor_mode:
        for p in proxies:
            pt = (p.get("type") or "socks5").lower()
            if pt in ("socks4","socks4a"): _proto = "socks4"
            elif pt in ("http","https"):   _proto = "http"
            else:                          _proto = "socks5"
            if p.get("user"):
                auth = p["user"] + ":" + (p.get("pwd") or "")
                uri = f"{_proto}://{auth}@{p['host']}:{p['port']}"
            else:
                uri = _proto + "://" + p["host"] + ":" + str(p["port"])
            all_proxy_list.append({
                "uri": uri,
                "label": p["host"] + ":" + str(p["port"])
            })
    else:
        all_proxy_list = [{"uri": "socks5://127.0.0.1:9050", "label": "tor"}]

    if not all_proxy_list:
        console.print("[bold #FF0000]❌ no proxies for forwarder[/bold #FF0000]")
        return None, None, []

    all_proxies_json = _json.dumps(all_proxy_list)

    forwarder_code = textwrap.dedent("""\
        import asyncio, socket, struct, sys, time, threading, json
        try:
            import pproxy
        except ImportError:
            import subprocess as _sp
            _sp.run([sys.executable,'-m','pip','install','pproxy',
                     '--break-system-packages','-q'],
                    stdout=open('/dev/null','w'),stderr=open('/dev/null','w'))
            import pproxy

        T = 20
        PROXIES = json.loads(%%PROXIES_JSON%%)
        _lock = threading.Lock()
        _idx  = [0]
        _fail = [0]
        MAX_FAIL = 2

        def _cur():
            with _lock:
                if not PROXIES: return None
                return PROXIES[_idx[0] % len(PROXIES)]["uri"]

        def _cur_label():
            with _lock:
                if not PROXIES: return ""
                return PROXIES[_idx[0] % len(PROXIES)]["label"]

        def _on_fail():
            with _lock:
                _fail[0] += 1
                if _fail[0] >= MAX_FAIL and len(PROXIES) > 1:
                    old = PROXIES[_idx[0] % len(PROXIES)]["label"]
                    _idx[0] = (_idx[0] + 1) % len(PROXIES)
                    _fail[0] = 0
                    new = PROXIES[_idx[0] % len(PROXIES)]["label"]
                    sys.stderr.write("|DRIP_ROTATE| " + old + " -> " + new + "\\n")
                    sys.stderr.flush()

        def _on_ok():
            with _lock: _fail[0] = 0

        N = [0]; NL = threading.Lock()

        def log(ok, host, port_, reason="", tx=0, rx=0):
            with NL:
                N[0] += 1
                n = N[0]
            ts = time.strftime("%H:%M:%S")
            st = "OK " if ok else "X  "
            msg = "|DRIP| #" + str(n).zfill(4) + " " + ts + " " + st + " " + _cur_label() + "|" + str(host) + ":" + str(port_)
            if ok:
                msg += " TX=" + str(tx) + " RX=" + str(rx)
            if reason:
                msg += " (" + str(reason)[:70] + ")"
            sys.stderr.write(msg + "\\n")
            sys.stderr.flush()

        async def relay(src_r, dst_w, ctr):
            try:
                while True:
                    d = await src_r.read(65536)
                    if not d: break
                    ctr[0] += len(d)
                    dst_w.write(d)
                    await dst_w.drain()
            except Exception:
                pass
            finally:
                try: dst_w.close()
                except Exception: pass

        async def rxn(r, n):
            return await asyncio.wait_for(r.readexactly(n), T)

        async def handle(cr, cw):
            dest_host = "?"
            dest_port = 0
            try:
                h = await rxn(cr, 2)
                if h[0] != 5:
                    return
                await rxn(cr, h[1])
                cw.write(bytes([5, 0]))
                await cw.drain()
                req = await rxn(cr, 4)
                if req[1] != 1:
                    return
                atyp = req[3]
                if atyp == 1:
                    dest_host = socket.inet_ntoa(await rxn(cr, 4))
                elif atyp == 3:
                    n_ = (await rxn(cr, 1))[0]
                    dest_host = (await rxn(cr, n_)).decode()
                elif atyp == 4:
                    dest_host = socket.inet_ntop(socket.AF_INET6, await rxn(cr, 16))
                else:
                    return
                dest_port = struct.unpack(">H", await rxn(cr, 2))[0]
                uri = _cur()
                if uri:
                    pc = pproxy.Connection(uri)
                    r, w = await asyncio.wait_for(pc.tcp_connect(dest_host, dest_port), T)
                else:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(dest_host, dest_port), T)
                cw.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
                await cw.drain()
                tx_c = [0]
                rx_c = [0]
                await asyncio.gather(
                    relay(cr, w, tx_c),
                    relay(r, cw, rx_c),
                    return_exceptions=True
                )
                _on_ok()
                log(True, dest_host, dest_port, tx=tx_c[0], rx=rx_c[0])
            except asyncio.TimeoutError:
                _on_fail()
                log(False, dest_host, dest_port, "timeout")
                try:
                    cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
                    await cw.drain()
                except Exception:
                    pass
            except Exception as e:
                err = str(e)
                _on_fail()
                if not err:
                    err = e.__class__.__name__
                log(False, dest_host, dest_port, err[:70])
                try:
                    cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
                    await cw.drain()
                except Exception:
                    pass
            finally:
                try: cw.close()
                except Exception: pass

        async def main():
            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            sys.stderr.write("|DRIP_PORT:" + str(port) + "|\\n")
            sys.stderr.write("|DRIP_READY|\\n")
            sys.stderr.flush()
            async with server:
                await server.serve_forever()

        asyncio.run(main())
    """).replace("%%PROXIES_JSON%%", repr(all_proxies_json))

    fw_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="drip_fw_"
    )
    fw_path_name = fw_file.name
    fw_file.write(forwarder_code); fw_file.flush(); fw_file.close()
    atexit.register(lambda p=fw_path_name: os.unlink(p) if os.path.exists(p) else None)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-u", fw_path_name],
        env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, bufsize=1
    )

    ready_event  = threading.Event()
    ready_lines  = []
    actual_port  = [None]

    def _wait_ready():
        for raw in iter(proc.stderr.readline, ""):
            ready_lines.append(raw.strip())
            if "|DRIP_PORT:" in raw:
                try:
                    actual_port[0] = int(raw.strip().split(":")[1].rstrip("|"))
                except Exception:
                    pass
            if "|DRIP_READY|" in raw:
                ready_event.set(); return
            if "Traceback" in raw or "Error" in raw:
                ready_event.set(); return

    threading.Thread(target=_wait_ready, daemon=True).start()
    ready_event.wait(timeout=6.0)

    port = actual_port[0]
    if not port:
        proc.terminate()
        return None, None, []

    for _ in range(3):
        try:
            s = _sock.create_connection(("127.0.0.1", port), timeout=1.5)
            s.close()
            return proc, port, ready_lines
        except Exception:
            time.sleep(0.4)

    proc.terminate()
    return None, None, []

def warn_leaky_browser(tool_name):
    name = tool_name.lower().split("/")[-1]
    reason = LEAKY_BROWSERS.get(name)
    if reason:
        msg = (
            "[bold #FF0000]YOUR ANONYMITY WILL BE COMPROMISED[/bold #FF0000]\n\n"
            f"  [bold white]{tool_name}[/bold white] leaks your real identity:\n"
            f"  [dim]{reason}[/dim]\n\n"
            "  [bold #FF0000]USE INSTEAD:[/bold #FF0000]\n"
            "  [bold white]python3 drip.py --browser[/bold white]\n"
            "  [dim](Firefox with DNS-over-proxy + WebRTC disabled)[/dim]\n\n"
            f"  [dim]continuing in 5s... Ctrl+C to cancel[/dim]"
        )
        console.print()
        console.print(Panel(msg,
            title="[bold #FF0000]⚠️  BROWSER LEAK WARNING ⚠️[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)))
        console.print()
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            console.print("[#FF0000]cancelled.[/]"); sys.exit(0)
        return True
    return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BROWSER LOG THREAD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _browser_log_thread(source_proc, proxies, countries, ok_count, fail_count,
                        pending_lines=None):
    import re
    conn_lock = threading.Lock()
    conn_n    = [0]
    ip_info   = {p["host"]: countries.get(p["host"], {}) for p in proxies}

    def _process_line(line):
        if "|DRIP_READY|" in line:
            console.print("  [bold #FF0000]✅ forwarder ready[/bold #FF0000]")
            return
        if "|DRIP_PORT:" in line:
            return
        if "|DRIP_ROTATE|" in line:
            info = line.replace("|DRIP_ROTATE|","").strip()
            console.print(f"  [bold #FFAA00]🔄 proxy rotated → {info}[/bold #FFAA00]")
            return
        if "|S-chain|" in line:
            if "-denied" in line or "-timeout" in line:
                console.print(f"  [bold #FF0000]⛓️  chain failed: {line[:80]}[/bold #FF0000]")
            return
        if "|DNS-request|" in line:
            host = line.split("|DNS-request|")[-1].strip()
            console.print(f"  [dim]DNS  → {host}[/dim]")
            return
        if "|DNS-response|" in line:
            info = line.split("|DNS-response|")[-1].strip()
            console.print(f"  [dim]DNS  ← {info}[/dim]")
            return
        if line.startswith("|DRIP|"):
            parts = line.split()
            if len(parts) < 5: return
            ts, st_s, proxy_and_dest = parts[2], parts[3], parts[4]
            if "|" in proxy_and_dest:
                proxy_label, dest = proxy_and_dest.split("|", 1)
            else:
                proxy_label, dest = "", proxy_and_dest

            ok = (st_s == "OK")
            tx_bytes = rx_bytes = 0
            reason = ""
            if ok:
                for part in parts[5:]:
                    if part.startswith("TX="): tx_bytes = int(part[3:])
                    elif part.startswith("RX="): rx_bytes = int(part[3:])
            elif len(parts) > 5:
                reason = " ".join(parts[5:]).strip("()")
            if ok: ok_count[0]   += 1
            else:  fail_count[0] += 1
            with conn_lock:
                conn_n[0] += 1; n = conn_n[0]
            st = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]✗  [/]"

            active_p = proxies[0] if proxies else None
            if proxies and proxy_label:
                for p in proxies:
                    if f"{p['host']}:{p['port']}" == proxy_label:
                        active_p = p
                        break

            if active_p:
                ci = ip_info.get(active_p["host"], {})
                chain_s = f"{ci.get('flag','🌐')}[bold #00BFFF]{active_p['host']}:{active_p['port']}[/bold #00BFFF][dim]({ci.get('code','??')})[/dim]"
            else:
                chain_s = "[dim]🧅 Tor[/dim]"

            line_out = (
                f"  [dim]#{n:04d} {ts}[/dim] {st}  "
                f"{chain_s} [dim]→[/dim] [bold white]{dest}[/bold white]"
            )
            if ok and (tx_bytes or rx_bytes):
                def _fmt(b):
                    if b < 1024:    return f"{b}B"
                    if b < 1048576: return f"{b/1024:.1f}KB"
                    return f"{b/1048576:.1f}MB"
                line_out += f" [dim]↑{_fmt(tx_bytes)} ↓{_fmt(rx_bytes)}[/dim]"
            if reason and not ok:
                line_out += f" [dim red]{reason}[/dim red]"
            console.print(line_out)
            return
        if "ProxyChains" in line or "proxychains.sf.net" in line:
            return
        noisy = (
            "IPDL" in line or "GLib" in line or "dbus" in line or
            "Gtk" in line  or "fontconfig" in line or "libGL" in line or
            "javascript" in line.lower() or "MOZ_" in line or
            "console.log" in line or "nss_" in line.lower() or
            len(line) > 300
        )
        if line and not noisy:
            console.print(f"  [dim]{line[:120]}[/dim]")

    try:
        if pending_lines:
            for line in pending_lines:
                _process_line(line)
        for raw in iter(source_proc.stderr.readline, ""):
            _process_line(raw.strip())
    except Exception as e:
        console.print(f"  [bold #FF0000]⚠️  log thread error: {e}[/bold #FF0000]")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  /etc/proxychains.conf PATCH (for proxychains v3)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _sudo_run(cmd, timeout=15):
    tty_in = None
    try:
        tty_in = open("/dev/tty", "r")
    except OSError:
        pass
    try:
        r = subprocess.run(
            cmd,
            stdin=tty_in,
            stdout=None,
            stderr=None,
            timeout=timeout,
        )
        return r.returncode == 0
    except Exception:
        return False
    finally:
        if tty_in:
            try: tty_in.close()
            except Exception: pass

def _patch_etc_proxychains(pc_conf_path):
    etc_conf = "/etc/proxychains.conf"
    backup = None
    try:
        if os.path.exists(etc_conf):
            backup = Path(etc_conf).read_text()
        shutil.copy2(pc_conf_path, etc_conf)
        return backup, True
    except PermissionError:
        console.print("  [dim]need sudo to patch /etc/proxychains.conf...[/dim]")
        ok = _sudo_run(["sudo", "cp", pc_conf_path, etc_conf])
        if ok:
            try: backup = Path(etc_conf).read_text()
            except Exception: pass
        return backup, ok
    except Exception:
        return None, False

def _restore_etc_proxychains(backup_content):
    etc_conf = "/etc/proxychains.conf"
    if backup_content is None: return
    try:
        Path(etc_conf).write_text(backup_content)
    except PermissionError:
        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".conf")
            tmp.write(backup_content); tmp.flush(); tmp.close()
            _sudo_run(["sudo", "cp", tmp.name, etc_conf])
            try: os.unlink(tmp.name)
            except Exception: pass
        except Exception:
            pass

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VPN DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_vpn():
    import re
    try:
        r = subprocess.run(["ip", "addr", "show"],
                           capture_output=True, text=True, timeout=3)
        output = r.stdout
    except Exception:
        return False, None, None

    vpn_patterns = [
        r"(tun\d+)", r"(wg\d+)", r"(tap\d+)",
        r"(ppp\d+)", r"(proton\d+)", r"(nordlynx)",
        r"(utun\d+)",
    ]
    for pattern in vpn_patterns:
        m = re.search(pattern, output)
        if m:
            iface = m.group(1)
            block_match = re.search(
                rf"{re.escape(iface)}.*?(?=^\d|\Z)",
                output, re.MULTILINE | re.DOTALL
            )
            ip = None
            if block_match:
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", block_match.group())
                if ip_match:
                    ip = ip_match.group(1)
            return True, iface, ip

    return False, None, None

def detect_protonvpn():
    for name in ["protonvpn-app", "protonvpn-gui"]:
        p = shutil.which(name)
        if p:
            return "gui", p
    p = shutil.which("protonvpn")
    if p:
        try:
            r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=3)
            out = (r.stdout + r.stderr).lower()
            if "cli" not in out and ("protonvpn" in out or r.returncode == 0):
                import glob
                desktop_files = glob.glob("/usr/share/applications/protonvpn*.desktop")
                if desktop_files:
                    return "gui", p
        except Exception:
            pass
        return "cli", p
    for name in ["protonvpn-cli"]:
        p = shutil.which(name)
        if p:
            return "cli", p
    return None, None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL CLASSIFICATION — TCP vs non-TCP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_NON_TCP_TOOLS = {
    "ping":            "ICMP",
    "ping6":           "ICMPv6",
    "traceroute":      "UDP/ICMP",
    "tracepath":       "UDP",
    "arping":          "ARP",
    "netdiscover":     "ARP",
    "arp-scan":        "ARP",
    "hping3":          "raw sockets",
    "nping":           "ICMP",
}

_DNS_TOOLS = {
    "nslookup":        "UDP DNS",
    "dig":             "UDP DNS",
    "host":            "UDP DNS",
    "drill":           "UDP DNS",
    "systemd-resolve": "UDP DNS",
}

_RAW_NMAP_FLAGS = {"-sS", "-sU", "-O", "-sP", "-sn", "-PE", "-PP", "-PM", "-PU", "-PY"}

_BROWSER_EXES = {
    "firefox", "firefox-esr", "chromium", "chromium-browser",
    "google-chrome", "brave-browser", "vivaldi", "opera", "microsoft-edge"
}

def _is_tool_tcp_capable(tool_name, tool_args):
    name = tool_name.lower().split("/")[-1]
    if name in _NON_TCP_TOOLS:
        return False, _NON_TCP_TOOLS[name]
    if name in _DNS_TOOLS:
        return False, _DNS_TOOLS[name]
    if name == "nmap":
        raw_flags = [f for f in tool_args if f in _RAW_NMAP_FLAGS]
        if raw_flags:
            return False, "nmap raw socket flags: " + " ".join(raw_flags)
    return True, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_usage(); sys.exit(0)

    if sys.argv[1] == "--browser":
        _BROWSER_MODE = True
        sys.argv = [sys.argv[0]] + ["firefox"] + sys.argv[2:]
    else:
        _BROWSER_MODE = False

    tool_args = sys.argv[1:]
    cfg       = load_config()
    tool_name = tool_args[0].lower().split("/")[-1]

    # ── Auto-patch nmap for proxychains ────────────
    if tool_name == "nmap" and not _BROWSER_MODE:
        raw_flags = [f for f in tool_args if f in _RAW_NMAP_FLAGS]
        if not raw_flags:
            if "-sT" not in tool_args: tool_args.insert(1, "-sT")
            if "-Pn" not in tool_args: tool_args.insert(1, "-Pn")
            console.print("  [dim]auto-injected -sT -Pn for nmap TCP proxy compatibility[/dim]")

    # ── Auto-patch sqlmap for HTTPS targets over proxy chain ────────
    if tool_name == "sqlmap" and not _BROWSER_MODE:
        url_arg = next((a for a in tool_args if a.startswith("http")), "")
        if url_arg.startswith("https"):
            # TLS handshake over 3 hops on free proxies needs more time
            if "--timeout" not in tool_args:
                tool_args += ["--timeout", "30"]
            if "--retries" not in tool_args:
                tool_args += ["--retries", "2"]
            # tell sqlmap not to abort on proxy-injected error codes
            if "--ignore-code" not in " ".join(tool_args):
                tool_args += ["--ignore-code", "0"]
            console.print(
                "  [dim]HTTPS target: auto-injected --timeout 30 --retries 2 "
                "--ignore-code 0 (SSL over proxy chain is slow)[/dim]"
            )

    # ── Classify tool: can it work through proxychains? ────────────
    can_proxy, non_tcp_reason = _is_tool_tcp_capable(tool_name, tool_args)

    # ── VPN detection ──
    vpn_active, vpn_iface, vpn_ip = detect_vpn()

    # ── NON-TCP TOOL HANDLING ─────────────────────────────────────
    if not can_proxy and not _BROWSER_MODE:
        if vpn_active:
            console.print()
            console.print(Panel(
                _make_kv_table([
                    ("🔒  VPN",     f"[bold #FF0000]{vpn_iface}[/bold #FF0000] active"),
                    ("🔧  tool",    f"[bold white]{tool_name}[/bold white] [dim]({non_tcp_reason} — not proxychainable)[/dim]"),
                    ("📡  routing", f"[dim]{tool_name} → VPN tunnel → target[/dim]"),
                    ("🚀  command", " ".join(tool_args)),
                ]),
                title="[bold #FF0000]🔥🩸 DRIP — DIRECT VPN MODE 🩸🔥[/]",
                border_style="#0055FF", padding=(0, 2)
            ))
            console.print()
        else:
            _ptype, _ppath = detect_protonvpn()
            if _ptype == "gui":
                _pvpn_hint = "  [bold #FF0000]ProtonVPN (GUI)[/bold #FF0000]  open the ProtonVPN app → Quick Connect"
            elif _ptype == "cli":
                _pvpn_hint = f"  [bold #FF0000]ProtonVPN (CLI)[/bold #FF0000]  {_ppath} connect --fastest -p tcp"
            else:
                _pvpn_hint = "  [bold #FF0000]ProtonVPN[/bold #FF0000]  not installed — get from protonvpn.com"
            console.print(Panel(
                "[bold #FF0000]⚠️  NON-TCP TOOL — RUNNING WITHOUT PROTECTION[/bold #FF0000]\n\n"
                f"  tool   : {tool_name}  ({non_tcp_reason})\n"
                "  reason : proxychains only intercepts TCP.\n"
                f"           {tool_name} uses {non_tcp_reason} which goes through your real IP.\n\n"
                "[bold white]Connect a VPN first for anonymity:[/bold white]\n\n"
                f"{_pvpn_hint}\n"
                "  [bold #FF0000]OpenVPN[/bold #FF0000]         sudo openvpn --config your.ovpn\n"
                "  [bold #FF0000]WireGuard[/bold #FF0000]       sudo wg-quick up wg0\n\n"
                "[dim]drip auto-detects any VPN (tun0/wg0/proton0).[/dim]\n\n"
                "[bold white]Continuing in 5s... Ctrl+C to cancel[/bold white]",
                title="[bold #FF0000]⚠️  NO VPN DETECTED[/bold #FF0000]",
                border_style="#FFAA00", padding=(0, 2)
            ))
            console.print()
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                console.print("[#FF0000]cancelled.[/]"); sys.exit(0)

        start = time.perf_counter()
        try:
            try:
                _tty_stdin = open("/dev/tty", "r")
            except OSError:
                _tty_stdin = None

            proc = subprocess.Popen(
                tool_args,
                stdin=_tty_stdin,
                preexec_fn=os.setpgrp,
            )
            proc.wait()
            rc = proc.returncode or 0
        except FileNotFoundError:
            console.print(f"[#FF0000]❌ command not found: {tool_args[0]}[/]")
            rc = 127
        except KeyboardInterrupt:
            try:
                pgid = os.getpgid(proc.pid)
                if pgid != os.getpgrp():
                    os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
            console.print("\n[#FF0000]⚠️  interrupted[/]")
            rc = 130
        finally:
            try:
                if _tty_stdin: _tty_stdin.close()
            except Exception:
                pass

        elapsed = time.perf_counter() - start
        console.print()
        console.print(Rule(style="#FF0000"))
        mode_label = f"VPN ({vpn_iface})" if vpn_active else "DIRECT (no protection)"
        console.print(Align.center(Panel(
            _make_kv_table([
                ("🔧  mode",    mode_label),
                ("⏱️   elapsed", f"{elapsed:.1f}s"),
            ]),
            title="[#FF0000]🩸 DONE 🩸[/]",
            border_style="#0055FF", padding=(0, 2)
        )))
        console.print()
        sys.exit(rc)

    # ── Browser warning ───────────────────────────────────────────
    if not _BROWSER_MODE and tool_name in _BROWSER_EXES:
        console.print(Panel(
            f"[bold #FF0000]⚠️  ANONYMITY WARNING[/bold #FF0000]\n\n"
            f"  Running [bold white]{tool_args[0]}[/bold white] through proxychains leaks DNS + real IP.\n\n"
            f"  [bold white]Use instead:[/bold white]\n"
            f"  [bold #FF0000]cat proxies.txt | python3 drip.py --browser[/bold #FF0000]\n\n"
            f"  [dim]Continuing in 5s... Ctrl+C to cancel[/dim]",
            title="[bold #FF0000]🔥 USE --browser FOR FULL ANONYMITY[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)
        ))
        console.print()
        try: time.sleep(5)
        except KeyboardInterrupt:
            console.print("[#FF0000]cancelled.[/]"); sys.exit(0)

    warn_leaky_browser(tool_args[0])

    pc_bin, is_v4 = find_proxychains()
    if not pc_bin:
        if   shutil.which("pacman"): install_cmd = "sudo pacman -S proxychains-ng"
        elif shutil.which("apt"):    install_cmd = "sudo apt install proxychains4"
        elif shutil.which("dnf"):    install_cmd = "sudo dnf install proxychains-ng"
        elif shutil.which("yum"):    install_cmd = "sudo yum install proxychains-ng"
        elif shutil.which("zypper"): install_cmd = "sudo zypper install proxychains-ng"
        else:                        install_cmd = "sudo apt install proxychains4"
        console.print(Panel(
            "[bold #FF0000]❌ proxychains not found![/bold #FF0000]\n\n"
            f"  [dim]Install:[/dim] [bold white]{install_cmd}[/bold white]",
            title="[bold #FF0000]MISSING DEPENDENCY[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)
        ))
        sys.exit(1)

    if not is_v4:
        console.print(Panel(
            "[bold #FF0000]⚠️  proxychains v3 detected[/bold #FF0000]\n\n"
            "  [dim]drip will patch [bold]/etc/proxychains.conf[/bold] before each run\n"
            "  and restore it after.\n\n"
            "  Upgrade recommended: [bold #FF0000]sudo apt install proxychains4[/bold #FF0000][/dim]",
            title="[bold #FF0000]proxychains v3[/bold #FF0000]",
            border_style="#0055FF", padding=(0, 2)
        ))
        console.print()

    if sys.stdin.isatty():
        tor_mode = True
        if not ensure_tor():
            console.print("[#FF0000]❌ Tor could not start.[/]")
            console.print("[dim]  sudo apt install tor && sudo systemctl start tor[/dim]")
            sys.exit(1)
        proxies = []; lats = {}; countries = {}
    else:
        tor_mode = False
        try:
            stdin_data = sys.stdin.read()
        except Exception:
            stdin_data = ""
        if not stdin_data.strip():
            console.print(Panel(
                "[bold #FF0000]❌ no proxy input received[/bold #FF0000]\n\n"
                "  [dim]Usage:[/dim] [bold white]cat proxies.txt | python3 drip.py <tool> [args][/bold white]\n\n"
                "  [dim]Your file might not exist. Check with:[/dim]\n"
                "  [bold white]ls *.txt[/bold white]",
                title="[bold #FF0000]NO PROXY FILE[/bold #FF0000]",
                border_style="#FF0000", padding=(0, 2)
            ))
            sys.exit(1)
        raw = parse_proxies(stdin_data, cfg["ptype"])
        if not raw:
            console.print("[#FF0000]❌ no valid proxies found in input[/]"); sys.exit(1)
        try:
            tty_fd = open("/dev/tty", "r")
            os.dup2(tty_fd.fileno(), 0)
            sys.stdin = tty_fd
        except OSError:
            pass
        proxies, lats = fast_filter(raw, cfg["quick_ms"])
        if not proxies:
            console.print(f"[#FF0000]❌ no proxies passed {cfg['quick_ms']}ms filter[/]")
            sys.exit(1)
        countries = {}
        if cfg["country"]:
            console.print("[dim]  looking up countries...[/dim]", end=" ")
            ips = list({p["host"] for p in proxies})
            entry_px = proxies[0] if proxies else None
            try:
                countries = lookup_countries(ips, via_proxy=entry_px)
                console.print("[#FF0000]done[/]")
            except Exception:
                console.print("[dim]skipped[/dim]")

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        #  COUNTRY BLACKLIST FILTER — applied after geo lookup
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        blacklist = cfg.get("country_blacklist", set())
        if blacklist and countries:
            before_count = len(proxies)
            proxies, dropped_count, dropped_details = filter_blacklisted_countries(
                proxies, countries, blacklist, lats
            )
            show_blacklist_results(before_count, dropped_count, dropped_details, blacklist)

            if not proxies:
                console.print(
                    f"[#FF0000]❌ ALL proxies were blacklisted! "
                    f"({', '.join(sorted(blacklist))})[/]"
                )
                console.print(
                    "[dim]  edit drip.yml → country_blacklist to allow more countries[/dim]"
                )
                sys.exit(1)
        elif blacklist and not countries:
            console.print(
                f"  [dim]⚠️  blacklist ({', '.join(sorted(blacklist))}) active "
                f"but country lookup was skipped — cannot filter[/dim]"
            )

    # ── Compute capped proxy pool ──────────────────────────────────
    clen = cfg["chain_len"]

    if tor_mode:
        display_proxies = proxies
    elif cfg["strict"]:
        display_proxies = proxies[:clen]
    elif cfg["random"]:
        display_proxies = proxies[:clen * 5]
    else:
        display_proxies = proxies[:max(clen * 6, 20)]

    pc_conf = write_pc_conf(display_proxies, cfg, tor_mode)
    atexit.register(lambda p=pc_conf: os.unlink(p) if os.path.exists(p) else None)

    print_banner(cfg, display_proxies, tool_args, tor_mode, pc_bin, pc_conf)

    ok, exit_ip = preflight(display_proxies, cfg, lats, countries, pc_bin, pc_conf, tor_mode, is_v4,
                           chain_len=clen)
    if not ok: sys.exit(1)

    start = time.perf_counter()
    ok_count = [0]; fail_count = [0]

    console.print(Rule(style="#FF0000"))
    console.print("  [dim]#     time      result   PROXY-HOP(s) → DESTINATION          ↑sent  ↓recv[/dim]")
    console.print(Rule(style="#0055FF")); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  BROWSER MODE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if _BROWSER_MODE:
        ff = _find_firefox()
        if not ff:
            console.print("[#FF0000]❌ Firefox not found[/]")
            console.print("[dim]  sudo apt install firefox-esr[/dim]")
            sys.exit(1)

        if tor_mode and not proxies:
            browser_proxies_for_analysis = [
                {"host": "127.0.0.1", "port": 9050, "type": "socks5",
                 "user": None, "pwd": None}
            ]
        else:
            browser_proxies_for_analysis = proxies

        proxies_typed, type_counts = analyze_proxy_types(browser_proxies_for_analysis)
        if not tor_mode:
            show_proxy_type_warning(type_counts, cfg.get("socks_only", False))
        socks_only = cfg.get("socks_only", False)
        browser_pool = proxies_typed
        if socks_only:
            browser_pool = [p for p in browser_pool if p.get("type", "socks5") != "http"]
            if not browser_pool:
                console.print("[#FF0000]⚠️  socks_only=T but no SOCKS proxies — using all[/]")
                browser_pool = proxies_typed
        if not tor_mode:
            browser_pool = browser_pool[:15]
            if cfg.get("random"): random.shuffle(browser_pool)

        console.print(
            f"  [bold #FF0000]⛓️  browser proxy pool: {len(browser_pool)} fallback(s)[/bold #FF0000]  "
            f"[dim](auto-rotation enabled)[/dim]"
        )
        console.print()

        console.print("  [dim]starting SOCKS5 forwarder...[/dim]")
        fw_proc, fw_port, pending_lines = _start_local_socks5(browser_pool, cfg, tor_mode)

        if fw_proc and fw_port:
            console.print(f"  [bold #FF0000]✅ SOCKS5 forwarder → 127.0.0.1:{fw_port}[/bold #FF0000]")
            patched = _patch_all_profiles(socks_port=fw_port)
            if patched:
                console.print(f"  [bold #FF0000]✅ patched {len(patched)} Firefox profile(s)[/bold #FF0000]")
                for p in patched[:2]:
                    console.print(f"     [dim]127.0.0.1:{fw_port} | socks_remote_dns=true | WebRTC=off | backup saved[/dim]")
            else:
                console.print("  [#FF0000]⚠️  no Firefox profiles found — open Firefox once first[/]")
        else:
            console.print("  [bold #FF0000]❌ SOCKS5 forwarder failed to start[/bold #FF0000]")
            sys.exit(1)

        console.print()
        log_thread = None
        try:
            _real_user = _get_real_user()
            ff_env = os.environ.copy()
            if _real_user and _real_user != "root" and os.getuid() == 0:
                ff_cmd = ["sudo", "-u", _real_user, ff]
                if "DISPLAY" not in ff_env:
                    ff_env["DISPLAY"] = ":0"
            else:
                ff_cmd = [ff]
            ff_proc = subprocess.Popen(
                ff_cmd, env=ff_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            log_thread = threading.Thread(
                target=_browser_log_thread,
                args=(fw_proc, browser_pool, countries, ok_count, fail_count,
                      pending_lines),
                daemon=False, name="drip-log"
            )
            log_thread.start()
            ff_proc.wait()
            rc = ff_proc.returncode or 0
        except KeyboardInterrupt:
            rc = 0
        finally:
            try: fw_proc.terminate()
            except Exception: pass

        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=3.0)

        console.print(); console.print(Rule(style="#FF0000"))
        print_footer(time.perf_counter()-start, exit_ip,
                     ok_count[0], fail_count[0], tor_mode, browser_pool)
        sys.exit(rc)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  REGULAR PROXYCHAINS MODE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"]  = pc_conf
    env["PROXYCHAINS_QUIET_MODE"] = "0"

    if not is_v4:
        etc_backup, etc_patched = _patch_etc_proxychains(pc_conf)
        if not etc_patched:
            console.print(Panel(
                "[bold #FF0000]⚠️  proxychains v3 config override FAILED[/bold #FF0000]\n\n"
                "  Fix options:\n"
                "  [bold #FF0000]1.[/bold #FF0000] sudo python3 drip.py ...\n"
                "  [bold #FF0000]2.[/bold #FF0000] sudo apt install proxychains4\n"
                "  [bold #FF0000]3.[/bold #FF0000] sudo chmod 666 /etc/proxychains.conf\n\n"
                "  [dim]Connections may route through Tor[/dim]",
                border_style="#FF0000", padding=(0, 2)
            ))
            console.print()
    else:
        etc_backup, etc_patched = None, False

    # NOTE: -q removed intentionally — on some proxychains4 builds -q also
    # suppresses |D-chain| lines, making connection tracking show 0/0.
    cmd = [pc_bin, "-f", pc_conf] + tool_args

    try:
        try:
            _tty_stdin = open("/dev/tty", "r")
        except OSError:
            _tty_stdin = None

        proc = subprocess.Popen(
            cmd, env=env,
            stdin=_tty_stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
            preexec_fn=os.setpgrp,
        )
        stream_with_live_log(proc, proxies, countries, cfg, ok_count, fail_count)
        proc.wait()
        rc = proc.returncode or 0

    except FileNotFoundError:
        console.print(f"[#FF0000]❌ command not found: {tool_args[0]}[/]")
        rc = 127
    except KeyboardInterrupt:
        try:
            pgid = os.getpgid(proc.pid)
            if pgid != os.getpgrp():
                os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        console.print("\n[#FF0000]⚠️  interrupted[/]")
        rc = 130
    finally:
        if etc_patched:
            _restore_etc_proxychains(etc_backup)
        try:
            if _tty_stdin:
                _tty_stdin.close()
        except Exception:
            pass

    console.print()
    console.print(Rule(style="#FF0000"))
    print_footer(time.perf_counter()-start, exit_ip,
                 ok_count[0], fail_count[0], tor_mode, display_proxies)
    sys.exit(rc)


if __name__ == "__main__":
    main()
