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
# FIX M6: log if it worked/failed in debug mode, not bare except
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

# FIX C1: geo cache path — country lookups cached 24h so we don't
#         blast ip-api.com with your real IP on every run
GEO_CACHE_PATH = Path.home() / ".cache" / "drip" / "geo.json"
GEO_CACHE_TTL  = 86400  # 24 hours

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFAULT_CONFIG = """# drip.yml — proxychains wrapper config

# ── Chain mode (ONE = T) ─────────────────────────────
strict_chain:   F   # Strict mode fails if one proxy is dead
dynamic_chain:  T   # Dynamic mode skips dead proxies automatically
random_chain:   F   # random proxies each connection

# ── Options ─────────────────────────────────────────
chain_len:      3       # proxies in random mode
timeout:        8       # connect timeout per proxy (seconds)
quick_timeout:  3000    # ms — skip proxy if no response in 3000ms
proxy_type:     socks5  # socks5 | socks4 | http
proxy_dns:      T       # resolve DNS through proxy (no leaks)
tcp_read_time:  15000   # proxychains TCP read timeout ms
tcp_conn_time:  8000    # proxychains TCP connect timeout ms
country_lookup: T       # show country flags

# ── Browser mode ─────────────────────────────────────
browser_chain_len: 1    # hops for browser mode — keep at 1 for free proxies!
socks_only:     F       # T = drop HTTP proxies in browser mode

# ── VPN settings ─────────────────────────────────────
# use_openvpn: T = use OpenVPN (.ovpn file)
#              F = use ProtonVPN CLI
use_openvpn:    T

# OpenVPN: path to your .ovpn file (only used if use_openvpn: T)
# Put the file in same folder as drip.py or use full path.
# Leave blank to disable: vpn_config:
vpn_config:     vpngate_public-vpn-156.opengw.net_tcp_443.ovpn

# ProtonVPN: credentials (only used if use_openvpn: F)
# Get your OpenVPN/IKEv2 username+password from:
# proton.me → Account → Downloads → OpenVPN / IKEv2 credentials
# Leave blank to be prompted at runtime.
proton_user:
proton_pass:
"""
def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(DEFAULT_CONFIG)
    lines = []
    for line in CONFIG_PATH.read_text().splitlines():
        s = line.strip()
        # FIX L6: only strip comments at line start or after whitespace
        # so passwords containing # are not truncated
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
    _vpn_raw = str(cfg.get("vpn_config") or "").strip()
    if _vpn_raw:
        _vpn_path = Path(_vpn_raw)
        if not _vpn_path.is_absolute():
            _vpn_path = SCRIPT_DIR / _vpn_path
        _vpn_config = str(_vpn_path)
    else:
        _vpn_config = None

    return {
        "strict":       b("strict_chain", True),
        "dynamic":      b("dynamic_chain"),
        "random":       b("random_chain"),
        "chain_len":    max(1, int(cfg.get("chain_len", 3))),
        "browser_len":  max(1, int(cfg.get("browser_chain_len", 3))),
        "timeout":      max(1.0, float(cfg.get("timeout", 8))),
        "quick_ms":     max(50, int(cfg.get("quick_timeout", 3000))),
        "ptype":        str(cfg.get("proxy_type", "socks5")).lower().strip(),
        "proxy_dns":    b("proxy_dns", True),
        "tcp_read":     int(cfg.get("tcp_read_time", 15000)),
        "tcp_conn":     int(cfg.get("tcp_conn_time", 8000)),
        "country":      b("country_lookup", True),
        "socks_only":   b("socks_only"),
        "vpn_config":   _vpn_config,
        "use_openvpn":  b("use_openvpn", True),
        "proton_user":  str(cfg.get("proton_user") or "").strip(),
        "proton_pass":  str(cfg.get("proton_pass") or "").strip(),
    }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FLAGS  (FIX L1: lazy-loaded, not at module level)
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

# FIX C1: country lookups no longer leak your real IP.
# - Results cached 24h in ~/.cache/drip/geo.json
# - Only uncached IPs are looked up
# - via_proxy param lets you route the lookup through the chain
def lookup_countries(ips, via_proxy=None):
    cache   = _load_geo_cache()
    needed  = [ip for ip in ips if ip not in cache]
    result  = {ip: cache[ip] for ip in ips if ip in cache}

    if not needed:
        return result

    # Build proxy dict if we have a proxy to route through
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

    # Update cache with new entries
    cache.update(result)
    _save_geo_cache(cache)
    return result

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PORT SETS  (FIX Bug1 + duplicate: ONE definition, frozenset)
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
        # FIX M1: split max 4 parts so passwords can contain colons
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
#  UNIFIED PROXY TYPE CLASSIFIER  (FIX: one function, used everywhere)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _classify_type(declared_type, port):
    """Single source of truth for port→protocol mapping."""
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
#  FAST FILTER  (FIX Bug3: returns sorted by latency)
#  FIX M7: merged quick-test + SOCKS5 probe into ONE connection
#  so we don't make 2 rounds of TCP connections per proxy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _probe_and_time(px, ms):
    """
    Single TCP connection that:
    1. Measures latency (replaces _quick_test)
    2. Detects real proxy protocol (replaces separate detect_proxy_types)
    Returns (latency_ms, detected_type) or (None, None) if unreachable.
    """
    t0 = time.perf_counter()
    try:
        s = socket.socket()
        s.settimeout(ms / 1000.0)
        s.connect((px["host"], px["port"]))
        lat = int((time.perf_counter() - t0) * 1000)

        # Send SOCKS5 greeting while we have the connection open
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
            # No response to SOCKS5 handshake — port-based guess
            detected = _classify_type(px.get("type"), px["port"])
        finally:
            s.close()
        return lat, detected
    except Exception:
        return None, None

# FIX M2: worker count configurable, default 50 not 150
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
                # Update proxy with detected type
                px = {**px, "type": detected}
                fast.append(px)
                lats[(px["host"], px["port"])] = lat

    # FIX Bug3: sort by actual latency before returning
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
        # FIX: use unified classifier, not duplicated inline logic
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
    """
    Select best proxies for browser chaining.
    FIX M8: comment and code now agree — uses latency-sorted pool.
    """
    blen      = cfg.get("browser_len", 3)
    socks_only = cfg.get("socks_only", False)

    pool = proxies_typed
    if socks_only:
        pool = [p for p in pool if p.get("type", "socks5") != "http"]
        if not pool:
            console.print("[#FF0000]⚠️  socks_only=T but no SOCKS proxies — using all[/]")
            pool = proxies_typed

    # Pool is already latency-sorted (fast_filter returns sorted)
    if cfg.get("strict"):
        selected = pool[:blen]
        console.print(f"  [dim]strict chain: first {len(selected)} of {len(pool)}[/dim]")
    elif cfg.get("random"):
        selected = random.sample(pool, min(blen, len(pool)))
        console.print(f"  [dim]random chain: {len(selected)} random[/dim]")
    else:
        # Dynamic: pick from top-N fastest (pool is already sorted)
        top_n = min(20, len(pool))
        top   = pool[:top_n]
        selected = random.sample(top, min(blen, len(top)))
        console.print(f"  [dim]dynamic chain: {len(selected)} from top-{top_n} fastest[/dim]")

    return selected

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WRITE PROXYCHAINS CONFIG
#  FIX M3: set 600 permissions on temp file (proxy creds inside)
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
        # ── ROOT CAUSE OF THE 243s PING BUG ──────────────────────────
        # In dynamic_chain mode proxychains routes through EVERY proxy
        # in the ProxyList in order, skipping dead ones.
        # Dumping all 536 proxies = potentially a 536-hop chain.
        #
        # FIX: cap the ProxyList to a sensible pool size:
        #   strict  → exactly clen proxies (all must work)
        #   dynamic → clen * 4 proxies max (dead ones are skipped,
        #             so we need a few extras to guarantee clen live hops)
        #   random  → clen * 5 proxies (random.sample picks clen of them)
        #
        # Proxies are already sorted by latency (fast_filter returns sorted)
        # so we always take the FASTEST ones.
        # Pool is already capped by main() before calling write_pc_conf.
        # We write all proxies we receive — no second cap needed.
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
    # FIX M3: explicitly set 600 — config may contain credentials
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
#  FIX C2: real IP lookup uses raw IPs to avoid DNS leaking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Direct IPs — no DNS resolution needed, safer for real IP detection
_REAL_IP_URLS = [
    ("34.117.59.81",    "http://34.117.59.81"),    # api.ipify.org
    ("34.160.111.145",  "http://34.160.111.145"),  # icanhazip.com
    ("54.243.157.52",   "http://54.243.157.52"),   # checkip.amazonaws.com
]

def get_real_ip():
    import re
    for _, url in _REAL_IP_URLS:
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "5", "--noproxy", "*",
                 "-H", "Host: api.ipify.org", url],
                capture_output=True, text=True, timeout=8
            )
            ip = r.stdout.strip()
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
    """
    chain_len: actual number of hops proxychains will use.
    In dynamic mode this is cfg['chain_len'] (e.g. 3), not len(proxies) (e.g. 20).
    Passing it here fixes the "19 more hops" display bug.
    """
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
    # Use chain_len for hop display — NOT len(proxies) which is the pool size.
    # In dynamic mode: pool=20 proxies but actual hops used = chain_len=3.
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

    real_ip   = get_real_ip()
    entry_px  = proxies[0] if proxies else None
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
#  FIX M4: added per-step timeout feedback, total timeout capped
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
            # BUG FIX (tty): don't capture output — if systemctl needs
            # a password or prints an error we want the user to see it.
            r = subprocess.run(cmd, timeout=8)
            if r.returncode == 0:
                console.print("[dim]ok[/dim]")
                for _ in range(6):   # wait up to 6s with feedback
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
def stream_with_live_log(proc, proxies, countries, cfg):
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
        ts = time.strftime("%H:%M:%S")
        st = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]✗  [/]"
        hops = [_fmt_ip(ip) for ip in chain_ips]
        if dest_ip and dest_ip not in chain_ips:
            hops.append(f"[bold white]{dest_ip}:{dest_port}[/bold white]")
        chain_s = " [dim]→[/dim] ".join(hops) if hops else "[dim]chain[/dim]"
        console.print(f"  [dim]#{n:04d} {ts}[/dim] {st}  {chain_s}")

    def _read_stdout():
        for line in iter(proc.stdout.readline, ""):
            # Filter proxychains diagnostic lines that leak to stdout.
            # On some distros proxychains prints port numbers, proxy counts,
            # or connection IDs to stdout even with -q flag.
            stripped = line.strip()
            skip = (
                "|S-chain|"    in stripped or
                "|D-chain|"    in stripped or
                "|DNS-"        in stripped or
                "ProxyChains"  in stripped or
                "proxychains"  in stripped.lower() or
                # Pure number lines (port, pid, count) — proxychains artifact
                (stripped.isdigit() and len(stripped) <= 6)
            )
            if not skip:
                sys.stdout.write(line); sys.stdout.flush()

    def _read_stderr():
        for raw in iter(proc.stderr.readline, ""):
            line = raw.strip()
            if "|S-chain|" in line:
                # FIX M5: don't swallow chain failures
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
#  SHARED INFO TABLE HELPER  (FIX L4: no more duplicate table code)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _make_kv_table(rows):
    """rows = list of (key, value) strings."""
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
    rows = [
        ("⛓️  chain mode",   mode),
        ("📡  source",       src),
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
        "[#00BFFF]Config:[/] [dim]drip.yml (auto-created)[/]",
        title="[#FF0000]🔥 DRIP — PROXYCHAINS WRAPPER 🔥[/]",
        border_style="#0055FF", padding=(1, 4)
    ))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR BROWSER / FIREFOX HELPERS
#  FIX Bug5 + L5: temp wrapper uses tempfile + atexit cleanup
#  FIX L2: removed hardcoded /root path (expanduser already covers it)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOR_BROWSER_CMDS = [
    "torbrowser-launcher", "tor-browser", "tor-browser-en",
    "/usr/bin/torbrowser-launcher",
    "/opt/tor-browser/Browser/start-tor-browser",
]

# FIX L5: use full name matching, not startswith, to avoid false positives
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
    """FIX Bug5: use tempfile + atexit so wrapper is always cleaned up."""
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
    # 700 — only owner can read/execute
    os.chmod(wrapper_path, stat.S_IRWXU)
    # Always clean up on exit
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
        # BUG FIX (tty): sudo apt needs tty so password prompt shows.
        # capture_output=True would silently swallow the prompt.
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

def _get_all_firefox_profiles():
    import glob, configparser
    profiles = []
    # FIX L2: removed hardcoded /root path — expanduser("~") already handles root
    bases = [
        os.path.expanduser("~/.mozilla/firefox"),
        os.path.expanduser("~/.firefox"),
    ]
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
    """
    FIX C3: backup prefs.js before patching, register atexit restore.
    """
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
        # FIX C3: backup before patching
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
    """Restore prefs.js from backup created by _patch_firefox_profile."""
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
#  FIX C4: forwarder code uses textwrap.dedent, not string concat
#  FIX Bug4 + Bug6: temp file tracked, port race fixed via retry
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _start_local_socks5(proxies, cfg, tor_mode):
    import socket as _sock

    # FIX Bug6: let OS pick the port AND hold it until forwarder grabs it
    # We pass port=0 to the forwarder script so IT picks the port,
    # then reads it back from stderr
    if tor_mode:
        chain = [{"host": "127.0.0.1", "port": 9050,
                  "type": "socks5", "user": None, "pwd": None}]
    else:
        # fast_filter already ran detection — types are correct
        chain = [{"host": p["host"], "port": p["port"],
                  "type": p.get("type", "socks5"),
                  "user": p.get("user"), "pwd": p.get("pwd")}
                 for p in proxies]

    import json
    chain_json = json.dumps(chain)

    try:
        import pproxy as _pp  # noqa
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pproxy",
                        "--break-system-packages", "-q"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _pproxy_uri(c):
        parts = []
        for p in c:
            pt = (p.get("type") or "socks5").lower()
            if pt in ("socks4", "socks4a"): proto = "socks4"
            elif pt in ("http", "https"):   proto = "http"
            else:                           proto = "socks5"
            # pproxy uses __ as chain separator (internal convention)
            parts.append(proto + "://" + p["host"] + ":" + str(p["port"]))
        return "__".join(parts)

    chain_uri = _pproxy_uri(chain) if chain else ""

    # FIX C4: forwarder as a proper dedented string, not 80 lines of concat
    # FIX Bug6: forwarder binds to port 0 (OS picks) and prints |DRIP_PORT:N|
    forwarder_code = textwrap.dedent(f"""\
        import asyncio, socket, struct, sys, time, threading
        try:
            import pproxy
        except ImportError:
            import subprocess as _sp
            _sp.run([sys.executable,'-m','pip','install','pproxy',
                     '--break-system-packages','-q'],
                    stdout=open('/dev/null','w'),stderr=open('/dev/null','w'))
            import pproxy

        CHAIN_URI = {repr(chain_uri)}
        T         = 20

        proxy_chain = pproxy.Connection(CHAIN_URI) if CHAIN_URI else None
        N = [0]; NL = threading.Lock()

        def log(ok, host, port_, reason='', tx=0, rx=0):
            with NL: N[0] += 1; n = N[0]
            ts  = time.strftime('%H:%M:%S')
            st  = 'OK ' if ok else 'X  '
            msg = '|DRIP| #' + f'{{n:04d}}' + ' ' + ts + ' ' + st + ' ' + str(host) + ':' + str(port_)
            if ok:     msg += ' TX=' + str(tx) + ' RX=' + str(rx)
            if reason: msg += ' (' + str(reason)[:70] + ')'
            sys.stderr.write(msg + '\\n'); sys.stderr.flush()

        async def relay(src_r, dst_w, counter):
            try:
                while True:
                    d = await src_r.read(65536)
                    if not d: break
                    counter[0] += len(d)
                    dst_w.write(d); await dst_w.drain()
            except Exception: pass
            finally:
                try: dst_w.close()
                except Exception: pass

        async def rx(r, n):
            return await asyncio.wait_for(r.readexactly(n), T)

        async def handle(cr, cw):
            dest_host = '?'; dest_port = 0
            try:
                h = await rx(cr, 2)
                if h[0] != 5: return
                await rx(cr, h[1])
                cw.write(bytes([5, 0])); await cw.drain()
                req = await rx(cr, 4)
                if req[1] != 1: return
                atyp = req[3]
                if   atyp == 1: dest_host = socket.inet_ntoa(await rx(cr, 4))
                elif atyp == 3:
                    n_ = (await rx(cr, 1))[0]
                    dest_host = (await rx(cr, n_)).decode()
                elif atyp == 4: dest_host = socket.inet_ntop(socket.AF_INET6, await rx(cr, 16))
                else: return
                dest_port = struct.unpack('>H', await rx(cr, 2))[0]
                hops = len(CHAIN_URI.split('__')) if CHAIN_URI else 1
                if proxy_chain:
                    r, w = await asyncio.wait_for(
                        proxy_chain.tcp_connect(dest_host, dest_port), T * hops)
                else:
                    r, w = await asyncio.wait_for(
                        asyncio.open_connection(dest_host, dest_port), T)
                cw.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                tx_c = [0]; rx_c = [0]
                await asyncio.gather(relay(cr, w, tx_c), relay(r, cw, rx_c),
                                     return_exceptions=True)
                log(True, dest_host, dest_port, tx=tx_c[0], rx=rx_c[0])
            except asyncio.TimeoutError:
                log(False, dest_host, dest_port, 'timeout')
                try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                except Exception: pass
            except Exception as e:
                log(False, dest_host, dest_port, str(e)[:70])
                try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                except Exception: pass
            finally:
                try: cw.close()
                except Exception: pass

        async def main():
            # FIX Bug6: bind to port 0 — OS picks, no TOCTOU race
            server = await asyncio.start_server(handle, '127.0.0.1', 0)
            port = server.sockets[0].getsockname()[1]
            sys.stderr.write('|DRIP_PORT:' + str(port) + '|\\n')
            sys.stderr.write('|DRIP_READY|\\n')
            sys.stderr.flush()
            async with server:
                await server.serve_forever()

        asyncio.run(main())
    """)

    fw_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="drip_fw_"
    )
    fw_path_name = fw_file.name
    fw_file.write(forwarder_code); fw_file.flush(); fw_file.close()
    # FIX Bug4: always clean up forwarder script on exit
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
            # FIX Bug6: read actual port from forwarder
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

    # Verify forwarder is actually listening
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
    # FIX L5: exact name match only — no startswith false positives
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
#  FIX M5: chain failures no longer silently dropped
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
            return  # already handled in _wait_ready
        # FIX M5: catch |S-chain| failures, not just successes
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
            ts, st_s, dest = parts[2], parts[3], parts[4]
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
            if proxies:
                cparts = []
                for p in proxies[:3]:
                    ci = ip_info.get(p["host"], {})
                    cparts.append(
                        f"{ci.get('flag','🌐')}[bold #00BFFF]{p['host']}:{p['port']}[/bold #00BFFF]"
                        f"[dim]({ci.get('code','??')})[/dim]"
                    )
                if len(proxies) > 3:
                    cparts.append(f"[dim]+{len(proxies)-3}[/dim]")
                chain_s = " [dim]→[/dim] ".join(cparts)
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
    """
    BUG FIX (sudo/tty): Run a sudo command with tty properly attached.

    OLD CODE used capture_output=True which piped stderr — sudo wrote
    its password prompt to stderr, it got swallowed, user typed into
    nothing, 5s timeout fired, call silently failed.

    FIX:
    - stdout/stderr=None  → inherit terminal (prompt visible)
    - stdin from /dev/tty → works even when fd 0 is at EOF
                            (drip consumed stdin reading the proxy list)
    """
    tty_in = None
    try:
        tty_in = open("/dev/tty", "r")
    except OSError:
        pass  # non-interactive — sudo will fail, that's expected
    try:
        r = subprocess.run(
            cmd,
            stdin=tty_in,
            stdout=None,   # pass-through to terminal
            stderr=None,   # pass-through — sudo prompt visible here
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
#  Checks if a VPN tunnel interface is active (tun0, tun1, wg0, etc.)
#  When VPN is ON: ALL tools work — ping, nslookup, nmap -sS, etc.
#                  VPN handles ICMP/UDP/raw sockets at OS level.
#                  proxychains adds another hop on top.
#  When VPN is OFF: raw socket tools warned but still allowed to run.
#                   User's choice — we just inform them.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detect_vpn():
    """
    Detect active VPN tunnel interface.
    Returns (is_active, interface_name, vpn_ip) or (False, None, None).
    Checks for: tun0-9, wg0-9, tap0-9, ppp0-9, proton0, nordlynx.
    """
    import re
    try:
        r = subprocess.run(["ip", "addr", "show"],
                           capture_output=True, text=True, timeout=3)
        output = r.stdout
    except Exception:
        return False, None, None

    # VPN interface patterns
    vpn_patterns = [
        r"(tun\d+)", r"(wg\d+)", r"(tap\d+)",
        r"(ppp\d+)", r"(proton\d+)", r"(nordlynx)",
        r"(utun\d+)",  # macOS
    ]
    for pattern in vpn_patterns:
        m = re.search(pattern, output)
        if m:
            iface = m.group(1)
            # Extract IP from that interface block
            # Find the block for this interface
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
    """
    Detect which ProtonVPN is available: GUI, CLI, or neither.
    GUI takes priority over CLI — always prefer GUI.
    Returns ("gui", path) | ("cli", path) | (None, None)
    """
    # GUI — protonvpn-app or the GTK app registered as "protonvpn"
    for name in ["protonvpn-app", "protonvpn-gui"]:
        p = shutil.which(name)
        if p:
            return "gui", p
    # protonvpn binary — could be GUI or CLI, check --version output
    p = shutil.which("protonvpn")
    if p:
        try:
            r = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=3)
            out = (r.stdout + r.stderr).lower()
            # GUI version outputs something like "ProtonVPN 3.x" without "cli"
            if "cli" not in out and ("protonvpn" in out or r.returncode == 0):
                # Try launching silently — GUI apps open a window
                # Heuristic: if it has a .desktop entry it's the GUI
                import glob
                desktop_files = glob.glob("/usr/share/applications/protonvpn*.desktop")
                if desktop_files:
                    return "gui", p
        except Exception:
            pass
        return "cli", p
    # CLI only
    for name in ["protonvpn-cli"]:
        p = shutil.which(name)
        if p:
            return "cli", p
    return None, None

# Tools that use raw sockets / ICMP / UDP
# With VPN: all work fine — VPN handles them at OS level
# Without VPN: warn user but still run (their choice)
_RAW_SOCKET_TOOLS = {
    "ping":            "ICMP — bypasses proxychains without VPN",
    "ping6":           "ICMPv6 — bypasses proxychains without VPN",
    "traceroute":      "UDP/ICMP — bypasses proxychains without VPN",
    "tracepath":       "UDP — bypasses proxychains without VPN",
    "arping":          "ARP — bypasses proxychains without VPN",
    "netdiscover":     "ARP — bypasses proxychains without VPN",
    "arp-scan":        "ARP — bypasses proxychains without VPN",
    "hping3":          "raw sockets — bypasses proxychains without VPN",
    "nping":           "ICMP by default — bypasses proxychains without VPN",
    "nslookup":        "UDP DNS — goes to local router without VPN",
    "dig":             "UDP DNS — goes to local router without VPN",
    "host":            "UDP DNS — bypasses proxychains without VPN",
    "drill":           "UDP DNS — bypasses proxychains without VPN",
    "systemd-resolve": "UDP DNS — bypasses proxychains without VPN",
}

# nmap flags that need raw sockets
# With VPN: pass them through untouched — VPN handles raw sockets
# Without VPN: warn user, still run (their choice)
_RAW_NMAP_FLAGS = {"-sS", "-sU", "-O", "-sP", "-sn", "-PE", "-PP", "-PM", "-PU", "-PY"}

_BROWSER_EXES = {
    "firefox", "firefox-esr", "chromium", "chromium-browser",
    "google-chrome", "brave-browser", "vivaldi", "opera", "microsoft-edge"
}

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

    # VPN CHECK — only for raw-socket tools
    _needs_vpn = (
        tool_name in _RAW_SOCKET_TOOLS or
        (tool_name == "nmap" and any(f in _RAW_NMAP_FLAGS for f in tool_args))
    )
    vpn_active, vpn_iface, vpn_ip = detect_vpn() if _needs_vpn else (False, None, None)
    if _needs_vpn:
        if vpn_active:
            console.print(
                f"  [bold #FF0000]🔒 VPN active ({vpn_iface})[/bold #FF0000]  "
                f"[dim]{tool_name} → VPN → proxychains → target[/dim]"
            )
            console.print()
        else:
            _ptype, _ppath = detect_protonvpn()
            _raw_reason = (
                _RAW_SOCKET_TOOLS.get(tool_name) or
                "nmap flags: " + " ".join(f for f in tool_args if f in _RAW_NMAP_FLAGS)
            )
            if _ptype == "gui":
                _pvpn_hint = "  [bold #FF0000]ProtonVPN (GUI)[/bold #FF0000]  open the ProtonVPN app → Quick Connect"
            elif _ptype == "cli":
                _pvpn_hint = f"  [bold #FF0000]ProtonVPN (CLI)[/bold #FF0000]  {_ppath} connect --fastest -p tcp"
            else:
                _pvpn_hint = "  [bold #FF0000]ProtonVPN[/bold #FF0000]  not installed — get from protonvpn.com"
            console.print(Panel(
                "[bold #FF0000]⚠️  RAW SOCKET TOOL — VPN recommended[/bold #FF0000]\n\n"
                f"  tool   : {tool_name}  ({_raw_reason})\n"
                "  reason : proxychains only intercepts TCP.\n"
                "           ICMP/UDP goes through your real IP without VPN.\n\n"
                "[bold white]Run any VPN for better anonymity:[/bold white]\n\n"
                f"{_pvpn_hint}\n"
                "  [bold #FF0000]OpenVPN[/bold #FF0000]         sudo openvpn --config your.ovpn\n"
                "  [bold #FF0000]WireGuard[/bold #FF0000]       sudo wg-quick up wg0\n\n"
                "[dim]drip auto-detects any VPN (tun0/wg0/proton0).[/dim]\n\n"
                "[bold white]Continuing in 5s... Ctrl+C to cancel[/bold white]",
                title="[bold #FF0000]⚠️  RUN VPN FOR BETTER ANONYMITY[/bold #FF0000]",
                border_style="#FFAA00", padding=(0, 2)
            ))
            console.print()
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                console.print("[#FF0000]cancelled.[/]"); sys.exit(0)

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
        # BUG FIX (stdin/tty): sys.stdin.read() above consumed fd 0.
        # Any child process launched later that needs user input
        # (sudo password, sqlmap interactive prompts, hydra confirmations)
        # would get immediate EOF.
        # FIX: reopen /dev/tty as fd 0 so child processes can read from
        # the real terminal even though we consumed the pipe.
        try:
            tty_fd = open("/dev/tty", "r")
            os.dup2(tty_fd.fileno(), 0)
            sys.stdin = tty_fd
        except OSError:
            pass  # non-interactive env (CI, script) — expected, skip
        # FIX M7: fast_filter now does latency + protocol in one round
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
                # FIX C1: route geo lookup through first proxy
                countries = lookup_countries(ips, via_proxy=entry_px)
                console.print("[#FF0000]done[/]")
            except Exception:
                console.print("[dim]skipped[/dim]")

    # ── Compute capped proxy pool ONCE — used for conf AND display ──
    # This ensures the IP flow, chain display, and banner all show the
    # real number of proxies in the chain — not the full input list.
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
    # Register cleanup for pc_conf
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

        proxies_typed, type_counts = analyze_proxy_types(proxies)
        show_proxy_type_warning(type_counts, cfg.get("socks_only", False))
        browser_chain = select_browser_chain(proxies_typed, cfg, lats)
        console.print(
            f"  [bold #FF0000]⛓️  browser chain: {len(browser_chain)} hop(s)[/bold #FF0000]  "
            f"[dim](browser_chain_len={cfg['browser_len']})[/dim]"
        )
        console.print()

        console.print("  [dim]starting SOCKS5 forwarder...[/dim]")
        fw_proc, fw_port, pending_lines = _start_local_socks5(browser_chain, cfg, tor_mode)

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
            ff_proc = subprocess.Popen(
                [ff], env=os.environ.copy(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            log_thread = threading.Thread(
                target=_browser_log_thread,
                args=(fw_proc, browser_chain, countries, ok_count, fail_count,
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
        # browser_chain is the actual chain used — show that, not full list
        print_footer(time.perf_counter()-start, exit_ip,
                     ok_count[0], fail_count[0], tor_mode, browser_chain)
        sys.exit(rc)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  REGULAR PROXYCHAINS MODE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"]  = pc_conf
    env["PROXYCHAINS_QUIET_MODE"] = "0"

    # FIX: only patch /etc for proxychains v3.
    # v4 supports -f flag so it reads our temp conf directly — no sudo needed.
    # Patching /etc on v4 systems caused a bogus sudo prompt every run.
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
        etc_backup, etc_patched = None, False   # v4: -f flag handles it, no /etc patch needed

    cmd = [pc_bin, "-f", pc_conf, "-q"] + tool_args if is_v4 else \
          [pc_bin, "-f", pc_conf]       + tool_args

    try:
        # BUG FIX (sudo/tty): was os.setsid which creates a new SESSION
        # with NO controlling terminal. sudo writes its password prompt
        # to /dev/tty (the controlling terminal of the process).
        # With no controlling terminal, sudo gets "sudo: no tty present"
        # and the prompt is silently swallowed.
        #
        # FIX: use os.setpgrp() instead — creates a new PROCESS GROUP
        # (so Ctrl+C handling still works) but keeps the controlling
        # terminal so sudo, ssh, gpg etc. can show prompts normally.
        #
        # stdin=open("/dev/tty") ensures interactive tools get the real
        # terminal even if fd 0 was previously at EOF from proxy reading.
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
        stream_with_live_log(proc, proxies, countries, cfg)
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
        # Close the tty fd we opened for stdin — don't leak it
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
