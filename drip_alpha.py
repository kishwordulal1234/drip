#!/usr/bin/env python3
"""
drip.py — proxychains wrapper with elite UI
usage: cat proxies.txt | python3 drip.py <tool> [args]
       python3 drip.py <tool> [args]   ← tor auto
"""

import sys, os, subprocess, socket, time, threading, random, tempfile, signal
import shutil, stat, atexit, textwrap, hashlib, struct, json, re, ipaddress
import configparser, glob
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SAFE DEPENDENCY INSTALLER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_REQUIRED_PACKAGES = {
    "rich":     ("rich",     ">=13.0.0"),
    "requests": ("requests", ">=2.28.0"),
    "pyyaml":   ("yaml",     None),
}

def _ensure_deps():
    missing = []
    for pkg, (imp, ver) in _REQUIRED_PACKAGES.items():
        try:
            __import__(imp)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return True
    for pkg in missing:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--user", pkg, "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
            )
            if r.returncode != 0:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "-q"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60
                )
                if r.returncode != 0:
                    print(f"[ERROR] Failed to install '{pkg}'. Install manually:", file=sys.stderr)
                    print(f"  pip install {pkg}", file=sys.stderr)
                    return False
        except Exception as e:
            print(f"[ERROR] Could not install '{pkg}': {e}", file=sys.stderr)
            return False
    for pkg, (imp, ver) in _REQUIRED_PACKAGES.items():
        try:
            __import__(imp)
        except ImportError:
            print(f"[ERROR] '{pkg}' installed but import '{imp}' still fails.", file=sys.stderr)
            return False
    return True

if not _ensure_deps():
    sys.exit(1)

import yaml
import requests as _req
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.rule    import Rule
from rich.align   import Align
from rich         import box

_UI_FD = os.dup(2)
_UI_FILE = os.fdopen(_UI_FD, "w")
console = Console(file=_UI_FILE)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROCESS RENAME — OPT-IN ONLY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_RENAME_OK = False
_PROCESS_RENAME_ENABLED = False

def _try_rename_process(name=None):
    global _RENAME_OK
    if not _PROCESS_RENAME_ENABLED:
        return
    try:
        import ctypes
        for lib_name in ["libc.so.6", "libc.so", "libc.dylib"]:
            try:
                libc = ctypes.CDLL(lib_name, use_errno=True)
                break
            except OSError:
                continue
        else:
            return
        proc_name = (name or "drip-worker").encode()[:15] + b"\x00"
        ret = libc.prctl(15, proc_name, 0, 0, 0)
        _RENAME_OK = (ret == 0)
    except Exception:
        pass

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
SCRIPT_DIR  = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "drip.yml"
GEO_CACHE_PATH = Path.home() / ".cache" / "drip" / "geo.json"
GEO_CACHE_TTL  = 86400

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FILE LOCKING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FileLock:
    def __init__(self, path):
        self.path = str(path) + ".lock"
        self.fd = None
    def __enter__(self):
        try:
            import fcntl
            self.fd = open(self.path, "w")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError):
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except ImportError:
            pass
        return self
    def __exit__(self, *args):
        if self.fd:
            try:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try: self.fd.close()
            except Exception: pass
            try: os.unlink(self.path)
            except Exception: pass

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECURE TEMP FILES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_TEMP_FILES = []
_TEMP_LOCK = threading.Lock()

def _secure_temp_file(suffix=".conf", prefix="drip_", content=None, mode=0o600):
    old_umask = os.umask(0o077)
    try:
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.fchmod(fd, mode)
        if content:
            if isinstance(content, str):
                content = content.encode()
            os.write(fd, content)
        os.close(fd)
    finally:
        os.umask(old_umask)
    with _TEMP_LOCK:
        _TEMP_FILES.append(path)
    return path

def _cleanup_temp_files():
    with _TEMP_LOCK:
        for p in _TEMP_FILES:
            try:
                if os.path.exists(p): os.unlink(p)
            except Exception: pass
        _TEMP_FILES.clear()

atexit.register(_cleanup_temp_files)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SIGNAL HANDLING + CLEANUP REGISTRY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_CLEANUP_CALLBACKS = []
_CLEANUP_LOCK = threading.Lock()

def register_cleanup(fn):
    with _CLEANUP_LOCK:
        _CLEANUP_CALLBACKS.append(fn)

def _run_cleanups():
    with _CLEANUP_LOCK:
        for fn in reversed(_CLEANUP_CALLBACKS):
            try: fn()
            except Exception: pass
        _CLEANUP_CALLBACKS.clear()

def _signal_handler(signum, frame):
    _run_cleanups()
    _cleanup_temp_files()
    os._exit(128 + signum)

signal.signal(signal.SIGTERM, _signal_handler)
try:
    signal.signal(signal.SIGHUP, _signal_handler)
except (AttributeError, OSError):
    pass
atexit.register(_run_cleanups)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFAULT_CONFIG = """# drip.yml — proxychains wrapper config

# ── Chain mode (exactly ONE should be T) ──────────────
strict_chain:   F   # Strict: fails if any proxy dead
dynamic_chain:  T   # Dynamic: skips dead proxies
random_chain:   F   # Random: picks random subset each connection

# ── Options ───────────────────────────────────────────
chain_len:      3       # how many proxies in your chain
timeout:        8       # connect timeout per proxy (seconds)
quick_timeout:  3000    # ms — drop proxy if no response
proxy_type:     socks5  # socks5 | socks4 | http
proxy_dns:      T       # resolve DNS through proxy
tcp_read_time:  15000
tcp_conn_time:  8000
country_lookup: T

# ── Country blacklist ─────────────────────────────────
country_blacklist: "CN, HK"

# ── Browser mode ───────────────────────────────────
browser_chain_len: 1
socks_only:     F

# ── Process rename (disabled by default) ──────────────
process_rename: F
process_name: "drip-worker"

# ── Privacy ───────────────────────────────────────────
show_real_ip:   F
preflight_ip_check: F

# ── Proxy rotation ────────────────────────────────────
rotation:           T       # enable automatic proxy rotation
rotation_interval:  0       # seconds between rotations (0 = rotate on failure only)
max_conn_fails:     3       # consecutive FULL CONNECTION failures before rotating
rotate_pool_size:   10      # how many proxies to keep in rotation pool
"""

def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(DEFAULT_CONFIG)
        console.print(f"  [dim]created default config: {CONFIG_PATH}[/dim]")
    try:
        cfg = yaml.safe_load(CONFIG_PATH.read_text()) or {}
    except yaml.YAMLError as e:
        console.print(f"[bold #FF0000]YAML parse error in {CONFIG_PATH}:[/bold #FF0000]")
        console.print(f"  [dim]{e}[/dim]")
        cfg = {}
    if not cfg:
        console.print(f"  [dim]config appears empty, using defaults[/dim]")
    def b(k, d=False):
        v = cfg.get(k, d)
        return str(v).strip().upper() in ("T","TRUE","YES","1") if not isinstance(v, bool) else v
    raw_bl = cfg.get("country_blacklist", "CN, HK")
    if isinstance(raw_bl, str):
        blacklist = {c.strip().upper() for c in raw_bl.split(",") if c.strip()}
    elif isinstance(raw_bl, list):
        blacklist = {str(c).strip().upper() for c in raw_bl if str(c).strip()}
    else:
        blacklist = set()
    strict  = b("strict_chain", False)
    dynamic = b("dynamic_chain", True)
    rand    = b("random_chain", False)
    active = sum([strict, dynamic, rand])
    if active > 1:
        console.print("[bold #FF0000]Multiple chain modes active! Using priority: strict > random > dynamic[/bold #FF0000]")
        if strict: dynamic = False; rand = False
        elif rand: dynamic = False
    elif active == 0:
        dynamic = True
    return {
        "strict": strict, "dynamic": dynamic, "random": rand,
        "chain_len":   max(1, int(cfg.get("chain_len", 3))),
        "browser_len": max(1, int(cfg.get("browser_chain_len", 1))),
        "timeout":     max(1.0, float(cfg.get("timeout", 8))),
        "quick_ms":    max(50, int(cfg.get("quick_timeout", 3000))),
        "ptype":       str(cfg.get("proxy_type", "socks5")).lower().strip(),
        "proxy_dns":   b("proxy_dns", True),
        "tcp_read":    int(cfg.get("tcp_read_time", 15000)),
        "tcp_conn":    int(cfg.get("tcp_conn_time", 8000)),
        "country":     b("country_lookup", True),
        "socks_only":  b("socks_only"),
        "country_blacklist": blacklist,
        "process_rename": b("process_rename", False),
        "process_name":   str(cfg.get("process_name", "drip-worker")),
        "show_real_ip":   b("show_real_ip", False),
        "preflight_ip":   b("preflight_ip_check", False),
        # ── Rotation settings ─────────────────────────────────────
        "rotation":           b("rotation", True),
        "rotation_interval":  max(0, int(cfg.get("rotation_interval", 0))),
        "max_conn_fails":     max(1, int(cfg.get("max_conn_fails", 3))),
        "rotate_pool_size":   max(3, int(cfg.get("rotate_pool_size", 10))),
    }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COUNTRY BADGES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_REGION_COLOR = {
    "AF":"#00BFFF","AM":"#00BFFF","AZ":"#00BFFF","BD":"#00BFFF","BN":"#00BFFF",
    "BT":"#00BFFF","CN":"#00BFFF","GE":"#00BFFF","HK":"#00BFFF","ID":"#00BFFF",
    "IN":"#00BFFF","JP":"#00BFFF","KG":"#00BFFF","KH":"#00BFFF","KP":"#00BFFF",
    "KR":"#00BFFF","KZ":"#00BFFF","LA":"#00BFFF","LK":"#00BFFF","MM":"#00BFFF",
    "MN":"#00BFFF","MV":"#00BFFF","MY":"#00BFFF","NP":"#00BFFF","PH":"#00BFFF",
    "PK":"#00BFFF","SG":"#00BFFF","TH":"#00BFFF","TJ":"#00BFFF","TM":"#00BFFF",
    "TW":"#00BFFF","UZ":"#00BFFF","VN":"#00BFFF","AU":"#00BFFF","NZ":"#00BFFF",
    "PG":"#00BFFF","FJ":"#00BFFF","SB":"#00BFFF",
    "AD":"#4488FF","AL":"#4488FF","AT":"#4488FF","BA":"#4488FF","BE":"#4488FF",
    "BG":"#4488FF","BY":"#4488FF","CH":"#4488FF","CY":"#4488FF","CZ":"#4488FF",
    "DE":"#4488FF","DK":"#4488FF","EE":"#4488FF","ES":"#4488FF","FI":"#4488FF",
    "FR":"#4488FF","GB":"#4488FF","GR":"#4488FF","HR":"#4488FF","HU":"#4488FF",
    "IE":"#4488FF","IS":"#4488FF","IT":"#4488FF","LI":"#4488FF","LT":"#4488FF",
    "LU":"#4488FF","LV":"#4488FF","MC":"#4488FF","MD":"#4488FF","ME":"#4488FF",
    "MK":"#4488FF","MT":"#4488FF","NL":"#4488FF","NO":"#4488FF","PL":"#4488FF",
    "PT":"#4488FF","RO":"#4488FF","RS":"#4488FF","RU":"#4488FF","SE":"#4488FF",
    "SI":"#4488FF","SK":"#4488FF","UA":"#4488FF",
    "AE":"#FF8800","BH":"#FF8800","IQ":"#FF8800","IR":"#FF8800","IL":"#FF8800",
    "JO":"#FF8800","KW":"#FF8800","LB":"#FF8800","OM":"#FF8800","QA":"#FF8800",
    "SA":"#FF8800","SY":"#FF8800","TR":"#FF8800","YE":"#FF8800",
    "AR":"#00CC66","BO":"#00CC66","BR":"#00CC66","BZ":"#00CC66","CA":"#00CC66",
    "CL":"#00CC66","CO":"#00CC66","CR":"#00CC66","CU":"#00CC66","DO":"#00CC66",
    "EC":"#00CC66","GT":"#00CC66","GY":"#00CC66","HN":"#00CC66","HT":"#00CC66",
    "JM":"#00CC66","MX":"#00CC66","NI":"#00CC66","PA":"#00CC66","PE":"#00CC66",
    "PY":"#00CC66","SR":"#00CC66","SV":"#00CC66","TT":"#00CC66","US":"#00CC66",
    "UY":"#00CC66","VE":"#00CC66",
    "AO":"#FFCC00","BJ":"#FFCC00","BW":"#FFCC00","CD":"#FFCC00","CF":"#FFCC00",
    "CG":"#FFCC00","CI":"#FFCC00","CM":"#FFCC00","DJ":"#FFCC00","DZ":"#FFCC00",
    "EG":"#FFCC00","ET":"#FFCC00","GA":"#FFCC00","GH":"#FFCC00","GM":"#FFCC00",
    "GN":"#FFCC00","KE":"#FFCC00","LR":"#FFCC00","LY":"#FFCC00","MA":"#FFCC00",
    "MG":"#FFCC00","ML":"#FFCC00","MR":"#FFCC00","MU":"#FFCC00","MW":"#FFCC00",
    "MZ":"#FFCC00","NA":"#FFCC00","NE":"#FFCC00","NG":"#FFCC00","RW":"#FFCC00",
    "SC":"#FFCC00","SD":"#FFCC00","SL":"#FFCC00","SN":"#FFCC00","SO":"#FFCC00",
    "SS":"#FFCC00","TD":"#FFCC00","TG":"#FFCC00","TN":"#FFCC00","TZ":"#FFCC00",
    "UG":"#FFCC00","ZA":"#FFCC00","ZM":"#FFCC00","ZW":"#FFCC00",
}

def _flag(cc):
    cc = (cc or "??").upper()
    if cc == "??": return "[dim]??"
    color = _REGION_COLOR.get(cc, "#888888")
    return f"[bold {color}]{cc}[/bold {color}]"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  GEO CACHE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _load_geo_cache():
    try:
        if GEO_CACHE_PATH.exists():
            with FileLock(GEO_CACHE_PATH):
                data = json.loads(GEO_CACHE_PATH.read_text())
                if time.time() - data.get("_ts", 0) < GEO_CACHE_TTL:
                    return data.get("entries", {})
    except Exception: pass
    return {}

def _save_geo_cache(entries):
    try:
        GEO_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(GEO_CACHE_PATH):
            tmp = str(GEO_CACHE_PATH) + ".tmp"
            Path(tmp).write_text(json.dumps({"_ts": time.time(), "entries": entries}))
            os.replace(tmp, str(GEO_CACHE_PATH))
    except Exception: pass

_GEO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

def lookup_countries(ips):
    cache   = _load_geo_cache()
    needed  = [ip for ip in ips if ip not in cache]
    result  = {ip: cache[ip] for ip in ips if ip in cache}
    if not needed: return result
    s = _req.Session()
    s.trust_env = False
    s.headers["User-Agent"] = _GEO_USER_AGENT
    for i in range(0, len(needed), 100):
        batch = needed[i:i+100]
        if i > 0: time.sleep(1.5)
        try:
            try:
                r = s.post("https://ip-api.com/batch?fields=query,countryCode,country,city",
                           json=[{"query": ip} for ip in batch], timeout=8)
            except _req.exceptions.SSLError:
                r = s.post("http://ip-api.com/batch?fields=query,countryCode,country,city",
                           json=[{"query": ip} for ip in batch], timeout=8)
            if r.status_code == 429:
                console.print("  [dim]ip-api rate limited, waiting...[/dim]")
                time.sleep(5); continue
            if r.status_code != 200:
                for ip in batch:
                    result[ip] = {"code":"??","country":"?","city":"","flag":"[dim]??"}
                continue
            data = r.json()
            if not isinstance(data, list):
                for ip in batch:
                    result[ip] = {"code":"??","country":"?","city":"","flag":"[dim]??"}
                continue
            for e in data:
                if not isinstance(e, dict): continue
                ip = e.get("query",""); cc = e.get("countryCode","??")
                result[ip] = {"code":cc,"country":e.get("country","?"),
                              "city":e.get("city",""),"flag":_flag(cc)}
        except Exception:
            for ip in batch:
                result.setdefault(ip, {"code":"??","country":"?","city":"","flag":"[dim]??"})
    s.close()
    cache.update(result)
    _save_geo_cache(cache)
    return result

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COUNTRY BLACKLIST
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def filter_blacklisted_countries(proxies, countries, blacklist):
    if not blacklist: return proxies, 0, {}
    kept = []; dropped = {}
    for px in proxies:
        ci = countries.get(px["host"], {})
        cc = ci.get("code", "??").upper()
        if cc in blacklist:
            dropped[cc] = dropped.get(cc, 0) + 1
        else:
            kept.append(px)
    return kept, sum(dropped.values()), dropped

def show_blacklist_results(total_before, total_dropped, dropped_details, blacklist):
    if not blacklist: return
    if total_dropped == 0 and not dropped_details: return
    lines = []
    if total_dropped > 0:
        lines.append(f"[bold #FF0000]COUNTRY BLACKLIST — {total_dropped} proxies dropped[/bold #FF0000]")
        lines.append("")
        for cc in sorted(dropped_details.keys()):
            lines.append(f"  {_flag(cc)} [bold #FF0000]{cc}[/bold #FF0000]  ->  [bold white]{dropped_details[cc]}[/bold white] dropped")
        lines.append("")
        lines.append(f"  [dim]{total_before} total -> {total_before - total_dropped} kept[/dim]")
        lines.append(f"  [dim]blacklist: {', '.join(sorted(blacklist))}[/dim]")
    else:
        lines.append(f"[dim]blacklist active ({', '.join(sorted(blacklist))}) — 0 dropped[/dim]")
    if total_dropped > 0:
        console.print(Panel("\n".join(lines),
            title="[bold #FF0000]BLACKLISTED COUNTRIES[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)))
    else:
        console.print("  " + lines[0])
    console.print()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PORT SETS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_HTTP_PROXY_PORTS  = frozenset({80,81,443,3128,3129,8008,8080,8118,8123,8181,8888,6588,3333})
_SOCKS_PROXY_PORTS = frozenset({1080,1081,1082,1083,9050,9150})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY PARSING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _validate_host(host):
    if not host or not host.strip(): return False
    host = host.strip()
    if any(c in host for c in ['\n','\r','\x00',' ','\t']): return False
    try: ipaddress.IPv4Address(host); return True
    except ValueError: pass
    try: ipaddress.IPv6Address(host.strip("[]")); return True
    except ValueError: pass
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
        return True
    return False

def _sanitize_field(value):
    if value is None: return None
    return re.sub(r'[\n\r\x00]', '', str(value).strip())

def parse_proxies(text, ptype="socks5"):
    out = []; seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        ipv6_match = re.match(r'^\[([^\]]+)\]:(\d+)(?::(.+))?$', line)
        if ipv6_match:
            host = ipv6_match.group(1)
            try: port = int(ipv6_match.group(2))
            except ValueError: continue
            rest = ipv6_match.group(3)
            user = pwd = None
            if rest:
                parts = rest.split(":", 1)
                user = _sanitize_field(parts[0]) if parts[0] else None
                pwd  = _sanitize_field(parts[1]) if len(parts) > 1 else None
        else:
            p = line.split(":", 3)
            try:
                if len(p) < 2: continue
                host = p[0].strip(); port = int(p[1].strip())
                user = _sanitize_field(p[2]) if len(p) > 2 else None
                pwd  = _sanitize_field(p[3]) if len(p) > 3 else None
            except (ValueError, IndexError): continue
        if not _validate_host(host): continue
        if not (1 <= port <= 65535): continue
        key = (host, port)
        if key in seen: continue
        seen.add(key)
        out.append({"host":host,"port":port,"user":user,"pwd":pwd,"type":ptype})
    return out

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY TYPE CLASSIFIER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _classify_type(declared_type, port):
    if port in _HTTP_PROXY_PORTS: return "http"
    if port in _SOCKS_PROXY_PORTS:
        pt = (declared_type or "socks5").lower()
        return pt if pt.startswith("socks") else "socks5"
    pt = (declared_type or "socks5").lower()
    if pt in ("socks5","socks5h"): return "socks5"
    if pt in ("socks4","socks4a"): return "socks4"
    if pt in ("http","https"):     return "http"
    return "socks5"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FAST FILTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _probe_and_time(px, ms):
    s = None
    try:
        t0 = time.perf_counter()
        s = socket.socket()
        s.settimeout(ms / 1000.0)
        s.connect((px["host"], px["port"]))
        lat = int((time.perf_counter() - t0) * 1000)
        detected = _classify_type(px.get("type"), px["port"])
        if px["port"] not in _HTTP_PROXY_PORTS:
            try:
                s.settimeout(1.5)
                s.sendall(bytes([5, 1, 0]))
                data = s.recv(2)
                if data and len(data) >= 2:
                    if data[0] == 5:
                        detected = "socks5"
                    elif data[0] == 0 and data[1] in (90, 91, 92, 93):
                        detected = "socks4"
                    else:
                        detected = "http"
            except Exception: pass
        return lat, detected
    except Exception:
        return None, None
    finally:
        if s:
            try: s.close()
            except Exception: pass

def fast_filter(proxies, ms, workers=50):
    fast = []; lats = {}
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        workers = min(workers, max(10, (soft - 100) // 2))
    except Exception:
        workers = min(workers, 30)
    actual = min(workers, len(proxies))
    console.print(f"  [dim]probing {len(proxies)} proxies ({ms}ms cutoff, {actual} threads)...[/dim]", end=" ")
    console.print()
    console.print("  [dim]NOTE: probing connects directly to each proxy (your IP is visible to proxy operators)[/dim]")
    with ThreadPoolExecutor(max_workers=actual) as ex:
        futs = {ex.submit(_probe_and_time, px, ms): px for px in proxies}
        for f in as_completed(futs):
            px = futs[f]
            try: lat, detected = f.result()
            except Exception: lat, detected = None, None
            if lat is not None and detected is not None:
                px = {**px, "type": detected}
                fast.append(px); lats[(px["host"], px["port"])] = lat
    fast.sort(key=lambda p: lats.get((p["host"], p["port"]), 9999))
    console.print(f"  [bold #FF0000]{len(fast)}/{len(proxies)} passed[/]")
    return fast, lats

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY TYPE ANALYSIS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def analyze_proxy_types(proxies):
    counts = {"socks5":0,"socks4":0,"http":0}; typed = []
    for p in proxies:
        t = _classify_type(p.get("type"), p.get("port", 0))
        if t not in counts: t = "socks5"
        counts[t] += 1; typed.append({**p, "type": t})
    return typed, counts

def show_proxy_type_warning(counts, socks_only=False):
    http_count = counts["http"]
    if http_count == 0: return
    socks_count = counts["socks5"] + counts["socks4"]
    lines = []
    if socks_count > 0 and http_count > 0:
        lines.append("[bold #FF0000]MIXED PROXY TYPES DETECTED![/bold #FF0000]")
        lines.append("")
        if counts["socks5"]: lines.append(f"  [bold #FF0000]{counts['socks5']}[/bold #FF0000] SOCKS5")
        if counts["socks4"]: lines.append(f"  [bold #FF0000]{counts['socks4']}[/bold #FF0000] SOCKS4")
        if counts["http"]:   lines.append(f"  [bold #0055FF]{counts['http']}[/bold #0055FF]  HTTP")
        lines.append("")
        if socks_only:
            lines.append(f"  [bold #FF0000]HTTP proxies SKIPPED[/bold #FF0000] (socks_only=T)")
        else:
            lines.append("  [dim]All types used[/dim]")
    elif http_count > 0 and socks_count == 0:
        lines.append("[bold #FF0000]ALL PROXIES ARE HTTP — chaining unreliable[/bold #FF0000]")
    if lines:
        console.print(Panel("\n".join(lines),
            title="[bold #FF0000]PROXY TYPE WARNING[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)))
        console.print()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WRITE PROXYCHAINS CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _select_chain_proxies(proxies, cfg, lats):
    clen = cfg["chain_len"]
    if cfg["random"]:
        pool_size = min(len(proxies), clen * 5)
        return proxies[:pool_size], clen
    if cfg["strict"]:
        return proxies[:clen], clen
    extras = min(3, len(proxies) - clen)
    pool_size = min(len(proxies), clen + max(0, extras))
    return proxies[:pool_size], clen

def _write_pc_conf_internal(proxies, cfg, tor_mode=False, chain_len=None, quiet=True):
    lines = []
    clen = chain_len or cfg["chain_len"]
    if tor_mode:
        lines.append("dynamic_chain")
    elif cfg["strict"]:
        lines.append("strict_chain")
    elif cfg["random"]:
        lines.append("random_chain")
        lines.append(f"chain_len = {clen}")
    else:
        lines.append("dynamic_chain")
    if cfg["proxy_dns"]: lines.append("proxy_dns")
    lines.append(f"tcp_read_time_out {cfg['tcp_read']}")
    lines.append(f"tcp_connect_time_out {cfg['tcp_conn']}")
    if quiet:
        lines.append("quiet_mode")
    lines.append("")
    lines.append("[ProxyList]")
    if tor_mode:
        lines.append(f"socks5 {TOR_HOST} {TOR_PORT}")
    else:
        for px in proxies:
            t = _classify_type(px.get("type"), px.get("port", 0))
            if t.startswith("socks4"): t = "socks4"
            elif t == "http": t = "http"
            else: t = "socks5"
            host = _sanitize_field(px['host'])
            port = int(px['port'])
            if not host or not (1 <= port <= 65535): continue
            if px.get("user"):
                user = _sanitize_field(px['user'])
                pwd  = _sanitize_field(px.get('pwd', ''))
                if user: lines.append(f"{t} {host} {port} {user} {pwd}")
                else: lines.append(f"{t} {host} {port}")
            else:
                lines.append(f"{t} {host} {port}")
    conf = "\n".join(lines) + "\n"
    pfx = "drip_pc_" if quiet else "drip_pcv_"
    return _secure_temp_file(suffix=".conf", prefix=pfx, content=conf, mode=0o600)

def write_pc_conf(proxies, cfg, tor_mode=False, chain_len=None):
    return _write_pc_conf_internal(proxies, cfg, tor_mode, chain_len, quiet=True)

def write_pc_conf_verbose(proxies, cfg, tor_mode=False, chain_len=None):
    return _write_pc_conf_internal(proxies, cfg, tor_mode, chain_len, quiet=False)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIND PROXYCHAINS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def find_proxychains():
    for name in ["proxychains4", "proxychains"]:
        path = shutil.which(name)
        if not path: continue
        try:
            st = os.stat(path)
            if st.st_uid not in (0, os.getuid()):
                console.print(f"  [bold #FF0000]WARNING: {path} owned by uid {st.st_uid}[/bold #FF0000]")
                continue
        except Exception: pass
        if name == "proxychains4":
            return path, True
        try:
            ver = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=2)
            combined = (ver.stdout + ver.stderr).lower()
            if "proxychains-ng" in combined or re.search(r'\bversion\s+4\.', combined):
                return path, True
            return path, False
        except Exception:
            return path, False
    return None, False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IP HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_real_ip():
    for url in ["https://api.ipify.org", "https://icanhazip.com"]:
        try:
            r = subprocess.run(["curl","-s","--max-time","5","--noproxy","*",
                                "-A",_GEO_USER_AGENT,url],
                               capture_output=True, text=True, timeout=8)
            ip = r.stdout.strip().splitlines()[0].strip()
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip): return ip
        except Exception: pass
    return None

def get_exit_ip(pc_bin, pc_conf, is_v4, timeout=12):
    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"] = pc_conf
    for url in ["https://api.ipify.org", "https://icanhazip.com",
                 "http://api.ipify.org", "http://icanhazip.com"]:
        try:
            if is_v4:
                cmd = [pc_bin, "-f", pc_conf, "curl", "-s",
                       "-A", _GEO_USER_AGENT, "--max-time", str(timeout), url]
            else:
                cmd = [pc_bin, "curl", "-s",
                       "-A", _GEO_USER_AGENT, "--max-time", str(timeout), url]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 10, env=env)
            for line in r.stdout.splitlines():
                line = line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                    return line
        except Exception: pass
    return None

_IP_PORT_RE = re.compile(r'(\d+\.\d+\.\d+\.\d+|\[[0-9a-fA-F:]+\]):(\d+)')

def _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei,
                   chain_len=None, show_real=False):
    lines = []
    lines.append(f"  [bold white]YOUR MACHINE[/bold white]")
    if show_real and real_ip:
        lines.append(f"  [bold #FF0000]  IP  : {real_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {ri.get('flag','[dim]??')} {ri.get('country','?')}, {ri.get('city','')}[/dim]")
    else:
        lines.append(f"  [dim]  IP  : [hidden for privacy][/dim]")
    lines.append("")
    lines.append("        [dim]|[/dim]")
    lines.append("        [dim]v  (traffic enters here)[/dim]")
    lines.append("")
    lines.append(f"  [bold white]ENTRY PROXY[/bold white]")
    if entry_px:
        lines.append(f"  [bold #00BFFF]  IP  : {entry_px['host']}:{entry_px['port']}[/bold #00BFFF]")
        lines.append(f"  [dim]  LOC : {pi.get('flag','[dim]??')} {pi.get('country','?')}, {pi.get('city','')}[/dim]")
        lines.append(f"  [dim]  TYPE: {entry_px['type'].upper()}[/dim]")
    lines.append("")
    actual_hops = chain_len if chain_len else len(proxies)
    if actual_hops > 1:
        lines.append("        [dim]|[/dim]")
        lines.append(f"        [dim]v  ({actual_hops-1} more hop(s))[/dim]")
        lines.append("")
    lines.append("        [dim]|[/dim]")
    lines.append("        [dim]v  (traffic exits here)[/dim]")
    lines.append("")
    lines.append(f"  [bold white]EXIT IP  (what the target sees)[/bold white]")
    if exit_ip:
        lines.append(f"  [bold #FF0000]  IP  : {exit_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {ei.get('flag','[dim]??')} {ei.get('country','?')}, {ei.get('city','')}[/dim]")
        if show_real and real_ip:
            if exit_ip != real_ip:
                lines.append(f"  [bold #FF0000]  real IP is HIDDEN[/bold #FF0000]")
            else:
                lines.append(f"  [bold #0055FF]  exit = real IP — proxy NOT working[/bold #0055FF]")
    else:
        lines.append(f"  [dim]  IP  : confirming via proxy chain...[/dim]")
    lines.append("")
    lines.append("        [dim]|[/dim]")
    lines.append("        [dim]v[/dim]")
    lines.append("")
    lines.append("  [bold white]TARGET[/bold white]")
    lines.append("  [dim]  sees only exit IP[/dim]")
    return "\n".join(lines)

def preflight(proxies, cfg, lats, countries, pc_bin, pc_conf, tor_mode,
              is_v4=True, chain_len=None):
    console.print()
    if tor_mode:
        console.print("  [dim]checking Tor...[/dim]", end=" ")
        try:
            s = socket.create_connection((TOR_HOST, TOR_PORT), timeout=5); s.close()
            console.print("[bold #FF0000]Tor up[/]")
        except Exception:
            console.print("[bold #FF0000]Tor not running[/]")
            return False, None
    else:
        sample = proxies[:min(5, len(proxies))]
        parts = []
        for p in sample:
            ci = countries.get(p["host"], {})
            parts.append(f"{ci.get('flag','[dim]??')}[bold #00BFFF]{p['host']}:{p['port']}[/][dim]({ci.get('country','?')})[/dim]")
        if len(proxies) > 5:
            parts.append(f"[dim]+{len(proxies)-5} more[/dim]")
        console.print("  chain: " + "[dim]->[/dim]".join(parts) + "[dim]->TARGET[/dim]")
        console.print()
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold #FF0000", padding=(0, 1))
        t.add_column("#", width=3, style="dim")
        t.add_column("proxy", min_width=22, style="bold #00BFFF")
        t.add_column("country", min_width=14)
        t.add_column("city", min_width=12, style="dim")
        t.add_column("type", width=7)
        t.add_column("latency", width=10, justify="right")
        t.add_column("", width=3)
        for i, px in enumerate(proxies[:20], 1):
            ci = countries.get(px["host"], {})
            lat = lats.get((px["host"], px["port"]))
            t.add_row(str(i), f"{px['host']}:{px['port']}", f"{ci.get('flag','[dim]??')} {ci.get('country','?')}",
                      ci.get("city",""), px["type"].upper(),
                      f"[bold #FF0000]{lat}ms[/]" if lat else "—",
                      "[#FF0000]OK[/]" if lat else "[#0055FF]X[/]")
        if len(proxies) > 20:
            t.add_row("...", f"[dim]+{len(proxies)-20} more[/dim]", "", "", "", "", "")
        console.print(Align.center(t))
    console.print()
    real_ip = None
    exit_ip = None
    if tor_mode:
        entry_px = {"host":TOR_HOST,"port":TOR_PORT,"type":"socks5","user":None,"pwd":None}
    else:
        entry_px = proxies[0] if proxies else None
    console.print("  [dim]confirming exit IP through proxy chain...[/dim]", end=" ")
    exit_result = [None]
    def _fetch_exit():
        exit_result[0] = get_exit_ip(pc_bin, pc_conf, is_v4, timeout=15)
    exit_thread = threading.Thread(target=_fetch_exit, daemon=True)
    exit_thread.start()
    exit_thread.join(timeout=30)
    exit_ip = exit_result[0]
    if exit_ip:
        console.print(f"[bold #FF0000]{exit_ip}[/bold #FF0000]")
    else:
        console.print("[dim]timed out (proxies may be slow, but will still work)[/dim]")
    if cfg.get("preflight_ip"):
        console.print("  [dim]checking real IP (preflight_ip_check=T)...[/dim]", end=" ")
        real_ip = get_real_ip()
        if real_ip:
            if cfg.get("show_real_ip"):
                console.print(f"[bold #FF0000]{real_ip}[/bold #FF0000]")
            else:
                console.print(f"[dim]obtained (hidden, show_real_ip=F)[/dim]")
    exit_geo = lookup_countries([exit_ip]) if exit_ip else {}
    real_geo = lookup_countries([real_ip]) if real_ip else {}
    ri = real_geo.get(real_ip, {}) if real_ip else {}
    ei = exit_geo.get(exit_ip, {}) if exit_ip else {}
    if tor_mode:
        pi = {"flag":"[bold #AA88FF]TOR[/bold #AA88FF]","country":"Tor Network","city":""}
    else:
        pi = countries.get(entry_px["host"], {}) if entry_px else {}
    console.print()
    console.print(Panel(
        _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei,
                       chain_len=chain_len or cfg.get("chain_len", 3),
                       show_real=cfg.get("show_real_ip", False)),
        title="[bold white]IP FLOW[/bold white]",
        border_style="#FF0000", padding=(0, 2),
    ))
    console.print()
    return True, exit_ip

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_tor_proc = None

def check_tor():
    try:
        s = socket.create_connection((TOR_HOST, TOR_PORT), timeout=3); s.close()
        return True
    except Exception: return False

def _cleanup_tor():
    global _tor_proc
    if _tor_proc:
        try:
            if _tor_proc.poll() is None:
                _tor_proc.terminate()
                try: _tor_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try: _tor_proc.kill(); _tor_proc.wait(timeout=2)
                    except Exception: pass
        except Exception: pass
        _tor_proc = None

def ensure_tor():
    global _tor_proc
    if check_tor(): return True
    console.print("[#FF0000]starting Tor...[/]")
    for cmd, label in [
        (["systemctl","start","tor"], "systemctl"),
        (["service","tor","start"], "service"),
    ]:
        try:
            console.print(f"  [dim]trying {label}...[/dim]", end=" ")
            r = subprocess.run(cmd, timeout=8, capture_output=True)
            if r.returncode == 0:
                console.print("[dim]ok[/dim]")
                for _ in range(6):
                    time.sleep(1)
                    if check_tor():
                        console.print("[#FF0000]Tor started[/]"); return True
            else: console.print("[dim]failed[/dim]")
        except Exception as e: console.print(f"[dim]{e}[/dim]")
    try:
        console.print("  [dim]trying direct tor binary...[/dim]", end=" ")
        _tor_proc = subprocess.Popen(["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        register_cleanup(_cleanup_tor)
        for _ in range(8):
            time.sleep(1)
            if check_tor():
                console.print("[#FF0000]Tor started[/]"); return True
        console.print("[dim]timed out[/dim]"); _cleanup_tor()
    except Exception: pass
    return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXYCHAINS LINE DETECTION (IMPROVED)
#
#  Proxychains output anatomy for ONE connection:
#
#    |D-chain|-<>-46.105.160.186:1080-<>-5.182.86.181:1080-<--timeout
#    |D-chain|-<>-46.105.160.186:1080-<>-23.95.61.242:1080-<><>-www.revel.com.hk:443-<><>-OK
#
#  The ENTIRE chain line represents ONE connection attempt.
#  "OK" at the end = connection succeeded (even if some hops timed out)
#  No "OK" / ends with "timeout"/"denied" = FULL connection failed
#
#  Verbose mode also produces hop-by-hop lines:
#    |D-chain|-<>-46.105.160.186:1080-<>-<>-5.182.86.181:1080-<>-OK
#    These are INTERMEDIATE and do NOT represent full connections.
#
#  CRITICAL FIX: We track chain state to only count COMPLETED
#  connections (ending OK or final failure), NOT intermediate hops.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PC_CHAIN_RE = re.compile(
    r'(\|[SDR]-chain\|'
    r'|\|DNS-(?:request|response)\|'
    r'|\[proxychains\]'
    r')',
    re.IGNORECASE
)

_PC_VERBOSE_RE = re.compile(
    r'^\s*'
    r'('
    r'\.{2,}\s+'
    r'|<--socket\s+error'
    r'|<--denied'
    r'|<--timeout'
    r')',
    re.IGNORECASE
)

_PC_BOILERPLATE_STRS = (
    "config file found:",
    "preloading /",
    "DLL init:",
    "proxychains.sf.net",
    "libproxychains",
    "proxychains can't load",
)

def _is_proxychains_line(line):
    """Return True if this line is ENTIRELY proxychains output."""
    if not line:
        return False
    if _PC_CHAIN_RE.search(line):
        return True
    if _PC_VERBOSE_RE.match(line):
        return True
    for c in _PC_BOILERPLATE_STRS:
        if c in line:
            return True
    return False


def _classify_chain_line(line):
    """Classify a proxychains line into connection-level events.

    Returns one of:
        "conn_ok"       — a FULL connection completed successfully
        "conn_fail"     — a FULL connection attempt failed entirely
        "hop"           — intermediate chain hop (ignore for rotation)
        "dns"           — DNS request/response (ignore for rotation)
        "noise"         — boilerplate / unclassifiable (ignore)

    The key distinction:
        |D-chain|...-<><>-TARGET:443-<><>-OK     → "conn_ok"  (reached target)
        |D-chain|...-<--timeout                    → depends: if target was reached = hop, else conn_fail
        ...  OK                                    → "hop" (verbose intermediate)
        ...  timeout                               → "hop" (verbose intermediate)

    We detect FULL connection results by looking for the TARGET in the chain line.
    In proxychains output, a successful connection always shows the target host/port
    followed by -<><>-OK or similar.
    """
    if not line:
        return "noise"

    stripped = line.rstrip()

    # DNS lines — always ignore for rotation
    if "|DNS-request|" in stripped or "|DNS-response|" in stripped:
        return "dns"

    # Chain lines: |D-chain|, |S-chain|, |R-chain|
    chain_match = re.match(r'^\|[DSR]-chain\|', stripped)
    if chain_match:
        # This is a full chain line. Check how it ends:
        # Successful full connection: ends with -OK or -<><>-OK
        # The target appears as the LAST host:port before -OK
        if stripped.endswith("-OK") or stripped.endswith("<><>-OK"):
            return "conn_ok"
        # Full connection failure: entire chain failed to reach target
        # This happens when the line ends with timeout/denied and contains
        # the target (usually the last entry)
        if stripped.endswith("timeout") or stripped.endswith("denied"):
            # Count pipe-separated segments to see if we reached deep enough
            # In dynamic_chain, individual hop failures are shown as separate
            # lines only in verbose mode. The main chain line shows the RESULT.
            return "conn_fail"
        # Intermediate state or noise
        return "hop"

    # Verbose hop lines: " ...  IP:port  ...  OK" or " ...  IP:port  ...  timeout"
    if _PC_VERBOSE_RE.match(stripped):
        # These are ALWAYS intermediate hop results, never full connections
        return "hop"

    # Boilerplate
    for c in _PC_BOILERPLATE_STRS:
        if c in stripped:
            return "noise"

    return "noise"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY ROTATION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ProxyRotator:
    """Thread-safe proxy rotation engine.

    Only rotates on FULL CONNECTION failures (not individual chain hops).
    A chain with 4 proxies in dynamic mode will have some hops fail —
    that's normal and expected. We only rotate when the entire connection
    to the target fails repeatedly.
    """

    def __init__(self, all_proxies, cfg, lats, countries, is_v4, pc_bin):
        self._lock = threading.Lock()
        self._all = list(all_proxies)
        self._cfg = cfg
        self._lats = lats
        self._countries = countries
        self._is_v4 = is_v4
        self._pc_bin = pc_bin

        self._max_conn_fails = cfg.get("max_conn_fails", 3)
        self._interval  = cfg.get("rotation_interval", 0)
        self._pool_size = cfg.get("rotate_pool_size", 10)

        self._consec_conn_fails = 0   # only FULL connection failures
        self._total_rotations = 0
        self._last_rotate_time = time.time()
        self._current_offset = 0

        # Stats
        self._total_conn_ok = 0
        self._total_conn_fail = 0
        self._total_hops_ok = 0
        self._total_hops_fail = 0

        self._chain, self._clen = self._pick_chain(0)
        self._conf_path = self._write_conf(self._chain)

    def _pick_chain(self, offset):
        clen = self._cfg["chain_len"]
        pool = self._all[offset:] + self._all[:offset]
        pool = pool[:max(clen, self._pool_size)]
        if self._cfg["random"]:
            random.shuffle(pool)
            return pool[:min(len(pool), clen * 5)], clen
        if self._cfg["strict"]:
            return pool[:clen], clen
        extras = min(3, len(pool) - clen)
        return pool[:min(len(pool), clen + max(0, extras))], clen

    def _write_conf(self, proxies):
        return _write_pc_conf_internal(proxies, self._cfg, tor_mode=False,
                                       chain_len=self._clen, quiet=False)

    @property
    def conf_path(self):
        with self._lock:
            return self._conf_path

    @property
    def chain(self):
        with self._lock:
            return list(self._chain)

    @property
    def total_rotations(self):
        with self._lock:
            return self._total_rotations

    def record_conn_ok(self):
        """A full connection to the target succeeded."""
        with self._lock:
            self._consec_conn_fails = 0
            self._total_conn_ok += 1

    def record_conn_fail(self):
        """A full connection to the target failed.
        Returns True if rotation was triggered."""
        rotated = False
        with self._lock:
            self._consec_conn_fails += 1
            self._total_conn_fail += 1
            if self._consec_conn_fails >= self._max_conn_fails:
                rotated = self._rotate_locked("conn_fails")
        return rotated

    def record_hop_ok(self):
        """An intermediate chain hop succeeded (not a full connection)."""
        with self._lock:
            self._total_hops_ok += 1

    def record_hop_fail(self):
        """An intermediate chain hop failed (not a full connection)."""
        with self._lock:
            self._total_hops_fail += 1

    def check_timed_rotation(self):
        if self._interval <= 0:
            return False
        with self._lock:
            if time.time() - self._last_rotate_time >= self._interval:
                return self._rotate_locked("interval")
        return False

    def _rotate_locked(self, reason="manual"):
        """Must be called with self._lock held."""
        if len(self._all) <= self._cfg["chain_len"]:
            self._consec_conn_fails = 0
            return False

        old_entry = self._chain[0] if self._chain else None
        self._current_offset = (self._current_offset + self._cfg["chain_len"]) % len(self._all)
        self._chain, self._clen = self._pick_chain(self._current_offset)
        self._conf_path = self._write_conf(self._chain)
        self._consec_conn_fails = 0
        self._total_rotations += 1
        self._last_rotate_time = time.time()

        new_entry = self._chain[0] if self._chain else None
        old_s = f"{old_entry['host']}:{old_entry['port']}" if old_entry else "?"
        new_s = f"{new_entry['host']}:{new_entry['port']}" if new_entry else "?"
        console.print(
            f"  [bold #FFAA00]⟳ ROTATED[/bold #FFAA00] chain #{self._total_rotations} "
            f"[dim]({reason}: {self._max_conn_fails} full connections failed)[/dim]  "
            f"{old_s} [dim]->[/dim] {new_s}  "
            f"[dim]({len(self._chain)} proxies)[/dim]"
        )
        return True

    def get_stats(self):
        with self._lock:
            return {
                "conn_ok": self._total_conn_ok,
                "conn_fail": self._total_conn_fail,
                "hops_ok": self._total_hops_ok,
                "hops_fail": self._total_hops_fail,
                "rotations": self._total_rotations,
            }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LIVE OUTPUT — CLEAN SEPARATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def stream_with_live_log(proc, proxies, countries, cfg, ok_count, fail_count, rotator=None):
    """Stream tool output cleanly. Proxychains chain lines are silently counted.
    Rotation only triggers on FULL connection failures, not hop failures."""

    _output_lock = threading.Lock()

    def _read_stdout():
        try:
            for line in iter(proc.stdout.readline, ""):
                with _output_lock:
                    sys.stdout.write(line)
                    sys.stdout.flush()
        except (ValueError, OSError):
            pass

    def _read_stderr():
        try:
            for raw in iter(proc.stderr.readline, ""):
                line = raw.rstrip('\n\r')

                if _is_proxychains_line(line):
                    # Classify: is this a full connection result or just a hop?
                    event = _classify_chain_line(line)

                    if event == "conn_ok":
                        ok_count[0] += 1
                        if rotator:
                            rotator.record_conn_ok()
                    elif event == "conn_fail":
                        fail_count[0] += 1
                        if rotator:
                            rotator.record_conn_fail()
                    elif event == "hop":
                        # Individual hop — track stats but do NOT trigger rotation
                        if rotator:
                            stripped = line.rstrip()
                            if stripped.endswith("-OK") or stripped.endswith("OK"):
                                rotator.record_hop_ok()
                            else:
                                rotator.record_hop_fail()
                    # dns and noise: ignore completely

                    # Don't print — keep tool output clean
                    continue

                # Real tool stderr — pass through untouched
                with _output_lock:
                    sys.stderr.write(raw)
                    sys.stderr.flush()
        except (ValueError, OSError):
            pass

    def _rotation_timer():
        if not rotator:
            return
        interval = cfg.get("rotation_interval", 0)
        if interval <= 0:
            return
        while proc.poll() is None:
            time.sleep(min(interval, 5))
            if proc.poll() is not None:
                break
            rotator.check_timed_rotation()

    t1 = threading.Thread(target=_read_stdout, daemon=True)
    t2 = threading.Thread(target=_read_stderr, daemon=True)
    t1.start()
    t2.start()

    t3 = None
    if rotator and cfg.get("rotation_interval", 0) > 0:
        t3 = threading.Thread(target=_rotation_timer, daemon=True)
        t3.start()

    t1.join(timeout=None)
    t2.join(timeout=None)
    proc.wait()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UI HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _make_kv_table(rows):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="#00BFFF bold", min_width=20)
    t.add_column(style="bold white")
    for k, v in rows: t.add_row(k, v)
    return t

def print_banner(cfg, proxies, tool_args, tor_mode, pc_bin, pc_conf):
    mode = ("[#FF0000]RANDOM[/]" if cfg["random"] else
            "[#FF0000]STRICT[/]" if cfg["strict"] else "[#00BFFF]DYNAMIC[/]")
    src = ("[#FF0000]TOR[/] (auto)" if tor_mode else
           f"[#FF0000]{len(proxies)}[/] proxies  [dim](>{cfg['quick_ms']}ms skipped)[/dim]")
    bl = cfg.get("country_blacklist", set())
    bl_str = ", ".join(sorted(bl)) if bl else "[dim]none[/dim]"
    rot_str = "[#FF0000]ON[/]" if cfg.get("rotation") else "[dim]OFF[/dim]"
    if cfg.get("rotation"):
        mf = cfg.get("max_conn_fails", 3)
        ri = cfg.get("rotation_interval", 0)
        rot_str += f"  [dim](after {mf} full connection fails"
        if ri > 0:
            rot_str += f", or every {ri}s"
        rot_str += f")[/dim]"
    rows = [
        ("chain mode",     mode),
        ("source",         src),
        ("blacklist",      bl_str),
        ("rotation",       rot_str),
        ("backend",        f"[#FF0000]{pc_bin}[/]"),
        ("config",         f"[dim]{pc_conf}[/dim]"),
        ("timeout",        f"{cfg['timeout']}s  [dim](tcp: {cfg['tcp_conn']}ms)[/dim]"),
        ("proxy dns",      "[#FF0000]ON[/]" if cfg["proxy_dns"] else "[#0055FF]OFF[/]"),
        ("process rename", f"{'enabled' if _PROCESS_RENAME_ENABLED else '[dim]disabled[/dim]'}"),
        ("command",        " ".join(tool_args)),
    ]
    console.print()
    console.print(Panel(_make_kv_table(rows),
        title="[bold #FF0000]DRIP — PROXYCHAINS WRAPPER[/]",
        border_style="#0055FF", padding=(0, 2)))
    console.print()

def print_footer(elapsed, exit_ip, ok_count, fail_count, tor_mode, proxies, rotator=None):
    rows = [("connections ok", str(ok_count)), ("connections failed", str(fail_count))]
    if not tor_mode: rows.append(("proxies in chain", str(len(proxies))))
    if rotator:
        stats = rotator.get_stats()
        rotations = stats["rotations"]
        if rotations > 0:
            rows.append(("chain rotations", f"[bold #FFAA00]{rotations}[/bold #FFAA00]"))
        rows.append(("hop stats", f"[dim]ok:{stats['hops_ok']} fail:{stats['hops_fail']}[/dim]"))
    rows.append(("elapsed", f"{elapsed:.1f}s"))
    if exit_ip: rows.append(("exit IP", exit_ip))
    console.print(); console.print(Rule(style="#FF0000"))
    console.print(Align.center(Panel(_make_kv_table(rows),
        title="[#FF0000]DONE[/]", border_style="#0055FF", padding=(0, 2))))
    console.print()

def print_usage():
    console.print(Panel(
        "[#FF0000]Usage:[/]\n"
        "  [white]cat proxies.txt | python3 drip.py <tool> [args][/]\n"
        "  [white]python3 drip.py <tool> [args][/]       [dim]<- no proxies = Tor auto[/dim]\n"
        "  [white]python3 drip.py --browser[/]            [dim]<- launch Firefox (DNS-safe)[/dim]\n\n"
        "[#00BFFF]Examples:[/]\n"
        '  [dim]cat p.txt | python3 drip.py sqlmap -u "http://target.com?id=1"\n'
        "  cat p.txt | python3 drip.py nmap -sT target.com\n"
        "  cat p.txt | python3 drip.py ghauri -u \"http://target.com?id=1\" --dbs\n"
        "  cat p.txt | python3 drip.py --browser[/]\n\n"
        "[#00BFFF]Proxy formats:[/]\n"
        "  [dim]ip:port\n  ip:port:user:pass[/]\n\n"
        "[#00BFFF]Config:[/] [dim]drip.yml (auto-created)[/]",
        title="[#FF0000]DRIP — PROXYCHAINS WRAPPER[/]",
        border_style="#0055FF", padding=(1, 4)))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BROWSER HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LEAKY_BROWSERS = {
    "chromium":"DNS and WebRTC leak","chromium-browser":"DNS and WebRTC leak",
    "chrome":"DNS and WebRTC leak","google-chrome":"DNS and WebRTC leak",
    "brave-browser":"DNS leak","opera":"DNS and WebRTC leak",
    "vivaldi":"DNS leak","microsoft-edge":"DNS and WebRTC leak",
}

_BROWSER_EXES = {
    "firefox","firefox-esr","chromium","chromium-browser",
    "google-chrome","brave-browser","vivaldi","opera","microsoft-edge"
}

TOR_BROWSER_DIRECT = [
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
    "/opt/tor-browser/Browser/start-tor-browser", "/usr/bin/tor-browser",
]

def _find_firefox():
    for name in ["firefox-esr", "firefox"]:
        path = shutil.which(name)
        if path: return path
    return None

def _get_real_user():
    for var in ["SUDO_USER", "DOAS_USER"]:
        u = os.environ.get(var, "")
        if u and u != "root": return u
    pkexec_uid = os.environ.get("PKEXEC_UID", "")
    if pkexec_uid:
        try:
            import pwd; return pwd.getpwuid(int(pkexec_uid)).pw_name
        except Exception: pass
    try:
        r = subprocess.run(["logname"], capture_output=True, text=True, timeout=2)
        if r.returncode == 0 and r.stdout.strip() and r.stdout.strip() != "root":
            return r.stdout.strip()
    except Exception: pass
    return os.environ.get("USER", "")

def _get_current_user_firefox_profiles():
    real_user = _get_real_user()
    home = os.path.expanduser(f"~{real_user}") if real_user and real_user != "root" else os.path.expanduser("~")
    profiles = []
    base = os.path.join(home, ".mozilla", "firefox")
    if not os.path.exists(base): return profiles
    ini = os.path.join(base, "profiles.ini")
    if os.path.exists(ini):
        cfg = configparser.ConfigParser()
        try: cfg.read(ini)
        except Exception: pass
        for section in cfg.sections():
            path = cfg.get(section, "Path", fallback=None)
            if not path: continue
            full = os.path.join(base, path) if cfg.get(section, "IsRelative", fallback="0") == "1" else path
            if os.path.isdir(full) and full not in profiles: profiles.append(full)
    for pattern in ["*.default-esr","*.default","*.default-release","*.esr"]:
        for p in glob.glob(os.path.join(base, pattern)):
            if p not in profiles: profiles.append(p)
    return profiles

_PATCHED_PROFILES = []
_PATCHED_PROFILES_LOCK = threading.Lock()

def _patch_firefox_profile(profile_dir, socks_port=None):
    port = socks_port or 9150
    user_js_content = textwrap.dedent(f"""\
        user_pref("network.proxy.type", 1);
        user_pref("network.proxy.socks", "127.0.0.1");
        user_pref("network.proxy.socks_port", {port});
        user_pref("network.proxy.socks_version", 5);
        user_pref("network.proxy.socks_remote_dns", true);
        user_pref("network.trr.mode", 5);
        user_pref("network.trr.uri", "");
        user_pref("network.dns.disablePrefetch", true);
        user_pref("network.dns.disablePrefetchFromHTTPS", true);
        user_pref("network.predictor.enabled", false);
        user_pref("network.prefetch-next", false);
        user_pref("media.peerconnection.enabled", false);
        user_pref("media.peerconnection.ice.default_address_only", true);
        user_pref("network.proxy.no_proxies_on", "");
    """)
    with FileLock(os.path.join(profile_dir, ".drip_lock")):
        user_js = os.path.join(profile_dir, "user.js")
        user_js_backup = user_js + ".drip_backup"
        if os.path.exists(user_js) and not os.path.exists(user_js_backup):
            shutil.copy2(user_js, user_js_backup)
        Path(user_js).write_text(user_js_content)
        prefs_js = os.path.join(profile_dir, "prefs.js")
        if os.path.exists(prefs_js):
            backup_path = prefs_js + ".drip_backup"
            if not os.path.exists(backup_path):
                shutil.copy2(prefs_js, backup_path)
            prefs = Path(prefs_js).read_text()
            keys_to_patch = {
                "network.proxy.type","network.proxy.socks","network.proxy.socks_port",
                "network.proxy.socks_version","network.proxy.socks_remote_dns",
                "network.trr.mode","network.dns.disablePrefetch",
                "media.peerconnection.enabled","network.proxy.no_proxies_on",
            }
            new_lines = []
            for line in prefs.splitlines():
                skip = any(f'"{key}"' in line for key in keys_to_patch)
                if not skip: new_lines.append(line)
            new_lines.extend([
                f'user_pref("network.proxy.type", 1);',
                f'user_pref("network.proxy.socks", "127.0.0.1");',
                f'user_pref("network.proxy.socks_port", {port});',
                f'user_pref("network.proxy.socks_version", 5);',
                f'user_pref("network.proxy.socks_remote_dns", true);',
                f'user_pref("network.trr.mode", 5);',
                f'user_pref("network.dns.disablePrefetch", true);',
                f'user_pref("media.peerconnection.enabled", false);',
                f'user_pref("network.proxy.no_proxies_on", "");',
            ])
            Path(prefs_js).write_text("\n".join(new_lines) + "\n")
    with _PATCHED_PROFILES_LOCK:
        if profile_dir not in _PATCHED_PROFILES:
            _PATCHED_PROFILES.append(profile_dir)
    return user_js

def _restore_firefox_profile(profile_dir):
    try:
        with FileLock(os.path.join(profile_dir, ".drip_lock")):
            for base_name in ["prefs.js", "user.js"]:
                original = os.path.join(profile_dir, base_name)
                backup = original + ".drip_backup"
                if os.path.exists(backup):
                    shutil.copy2(backup, original); os.unlink(backup)
                elif base_name == "user.js" and os.path.exists(original):
                    os.unlink(original)
    except Exception: pass

def _restore_all_profiles():
    with _PATCHED_PROFILES_LOCK:
        for p in _PATCHED_PROFILES: _restore_firefox_profile(p)
        _PATCHED_PROFILES.clear()

def _patch_current_user_profiles(socks_port=None):
    profiles = _get_current_user_firefox_profiles()
    if not profiles: return []
    patched = []
    for p in profiles:
        try: _patch_firefox_profile(p, socks_port); patched.append(p)
        except Exception: pass
    if patched: register_cleanup(_restore_all_profiles)
    return patched

def warn_leaky_browser(tool_name):
    name = tool_name.lower().split("/")[-1]
    reason = LEAKY_BROWSERS.get(name)
    if reason:
        console.print(Panel(
            f"[bold #FF0000]ANONYMITY WARNING[/bold #FF0000]\n\n"
            f"  {tool_name} leaks: {reason}\n\n"
            f"  Use: [bold white]python3 drip.py --browser[/bold white]\n"
            f"  [dim]continuing in 5s...[/dim]",
            title="[bold #FF0000]BROWSER LEAK[/bold #FF0000]",
            border_style="#FF0000", padding=(0, 2)))
        try: time.sleep(5)
        except KeyboardInterrupt:
            console.print("[#FF0000]cancelled.[/]"); sys.exit(0)
        return True
    return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LOCAL SOCKS5 FORWARDER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _start_local_socks5(proxies, cfg, tor_mode):
    all_proxy_list = []
    if not tor_mode:
        for p in proxies:
            pt = (p.get("type") or "socks5").lower()
            if pt in ("socks4","socks4a"): _proto = "socks4"
            elif pt in ("http","https"): _proto = "http"
            else: _proto = "socks5"
            if p.get("user"):
                uri = f"{_proto}://{p['user']}:{p.get('pwd','') or ''}@{p['host']}:{p['port']}"
            else:
                uri = f"{_proto}://{p['host']}:{p['port']}"
            all_proxy_list.append({"uri":uri,"label":f"{p['host']}:{p['port']}"})
    else:
        all_proxy_list = [{"uri":"socks5://127.0.0.1:9050","label":"tor"}]
    if not all_proxy_list:
        console.print("[bold #FF0000]no proxies for forwarder[/bold #FF0000]"); return None, None, []
    auth_token = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    proxy_json_path = _secure_temp_file(suffix=".json", prefix="drip_px_",
        content=json.dumps({"proxies":all_proxy_list,"auth_token":auth_token}), mode=0o600)
    forwarder_code = textwrap.dedent("""\
        import asyncio, socket, struct, sys, time, threading, json, random
        try:
            import pproxy
        except ImportError:
            import subprocess as _sp
            _sp.run([sys.executable,'-m','pip','install','--user','pproxy','-q'],
                    stdout=open('/dev/null','w'),stderr=open('/dev/null','w'))
            import pproxy
        with open(sys.argv[1]) as f: _data = json.load(f)
        PROXIES = _data["proxies"]
        T = 20; MAX_CONCURRENT = 200
        _lock = threading.Lock(); _idx = [0]; _fail = [0]; MAX_FAIL = 2
        _sem = asyncio.Semaphore(MAX_CONCURRENT)
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
                    if len(PROXIES) > 2:
                        choices = [i for i in range(len(PROXIES)) if i != (_idx[0] % len(PROXIES))]
                        _idx[0] = random.choice(choices)
                    else:
                        _idx[0] = (_idx[0] + 1) % len(PROXIES)
                    _fail[0] = 0
                    new = PROXIES[_idx[0] % len(PROXIES)]["label"]
                    sys.stderr.write("|DRIP_ROTATE| " + old + " -> " + new + "\\n"); sys.stderr.flush()
        def _on_ok():
            with _lock: _fail[0] = 0
        N = [0]; NL = threading.Lock()
        def log(ok, host, port_, reason="", tx=0, rx=0):
            with NL: N[0] += 1; n = N[0]
            ts = time.strftime("%H:%M:%S")
            msg = "|DRIP| #" + str(n).zfill(4) + " " + ts + " " + ("OK " if ok else "X  ") + " " + _cur_label() + "|" + str(host) + ":" + str(port_)
            if ok: msg += " TX=" + str(tx) + " RX=" + str(rx)
            if reason: msg += " (" + str(reason)[:70] + ")"
            sys.stderr.write(msg + "\\n"); sys.stderr.flush()
        async def relay(src_r, dst_w, ctr):
            try:
                while True:
                    d = await src_r.read(65536)
                    if not d: break
                    ctr[0] += len(d); dst_w.write(d); await dst_w.drain()
            except Exception: pass
            finally:
                try: dst_w.close()
                except Exception: pass
        async def rxn(r, n):
            return await asyncio.wait_for(r.readexactly(n), T)
        async def handle(cr, cw):
            dest_host = "?"; dest_port = 0
            try:
                async with _sem:
                    h = await rxn(cr, 2)
                    if h[0] != 5: return
                    await rxn(cr, h[1])
                    cw.write(bytes([5, 0])); await cw.drain()
                    req = await rxn(cr, 4)
                    if req[1] != 1: return
                    atyp = req[3]
                    if atyp == 1: dest_host = socket.inet_ntoa(await rxn(cr, 4))
                    elif atyp == 3:
                        n_ = (await rxn(cr, 1))[0]; dest_host = (await rxn(cr, n_)).decode()
                    elif atyp == 4: dest_host = socket.inet_ntop(socket.AF_INET6, await rxn(cr, 16))
                    else: return
                    dest_port = struct.unpack(">H", await rxn(cr, 2))[0]
                    uri = _cur()
                    if uri:
                        pc = pproxy.Connection(uri)
                        r, w = await asyncio.wait_for(pc.tcp_connect(dest_host, dest_port), T)
                    else:
                        r, w = await asyncio.wait_for(asyncio.open_connection(dest_host, dest_port), T)
                    cw.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                    tx_c = [0]; rx_c = [0]
                    await asyncio.gather(relay(cr, w, tx_c), relay(r, cw, rx_c), return_exceptions=True)
                    _on_ok(); log(True, dest_host, dest_port, tx=tx_c[0], rx=rx_c[0])
            except asyncio.TimeoutError:
                _on_fail(); log(False, dest_host, dest_port, "timeout")
                try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                except Exception: pass
            except Exception as e:
                _on_fail(); log(False, dest_host, dest_port, (str(e) or e.__class__.__name__)[:70])
                try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()
                except Exception: pass
            finally:
                try: cw.close()
                except Exception: pass
        async def main():
            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            sys.stderr.write("|DRIP_PORT:" + str(port) + "|\\n")
            sys.stderr.write("|DRIP_READY|\\n"); sys.stderr.flush()
            async with server: await server.serve_forever()
        asyncio.run(main())
    """)
    fw_path = _secure_temp_file(suffix=".py", prefix="drip_fw_", content=forwarder_code, mode=0o600)
    env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen([sys.executable, "-u", fw_path, proxy_json_path],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
    ready_event = threading.Event(); ready_lines = []; actual_port = [None]
    def _wait():
        for raw in iter(proc.stderr.readline, ""):
            if len(ready_lines) < 500: ready_lines.append(raw.strip())
            if "|DRIP_PORT:" in raw:
                try: actual_port[0] = int(raw.strip().split(":")[1].rstrip("|"))
                except Exception: pass
            if "|DRIP_READY|" in raw: ready_event.set(); return
            if "Traceback" in raw or "Error" in raw: ready_event.set(); return
    threading.Thread(target=_wait, daemon=True).start()
    ready_event.wait(timeout=6.0)
    port = actual_port[0]
    if not port: proc.terminate(); return None, None, []
    for _ in range(3):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.5); s.close()
            return proc, port, ready_lines
        except Exception: time.sleep(0.4)
    proc.terminate(); return None, None, []

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BROWSER LOG THREAD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _browser_log_thread(source_proc, proxies, countries, ok_count, fail_count, pending_lines=None):
    conn_lock = threading.Lock(); conn_n = [0]
    ip_info = {p["host"]: countries.get(p["host"], {}) for p in proxies}
    def _process_line(line):
        if "|DRIP_READY|" in line:
            console.print("  [bold #FF0000]forwarder ready[/bold #FF0000]"); return
        if "|DRIP_PORT:" in line: return
        if "|DRIP_ROTATE|" in line:
            console.print(f"  [bold #FFAA00]⟳ proxy rotated -> {line.replace('|DRIP_ROTATE|','').strip()}[/bold #FFAA00]"); return
        if "|S-chain|" in line or "|D-chain|" in line: return
        if "|DNS-request|" in line:
            console.print(f"  [dim]DNS  -> {line.split('|DNS-request|')[-1].strip()}[/dim]"); return
        if "|DNS-response|" in line:
            console.print(f"  [dim]DNS  <- {line.split('|DNS-response|')[-1].strip()}[/dim]"); return
        if line.startswith("|DRIP|"):
            parts = line.split()
            if len(parts) < 5: return
            ts, st_s, proxy_and_dest = parts[2], parts[3], parts[4]
            proxy_label, dest = proxy_and_dest.split("|", 1) if "|" in proxy_and_dest else ("", proxy_and_dest)
            ok = (st_s == "OK")
            tx_bytes = rx_bytes = 0; reason = ""
            if ok:
                for part in parts[5:]:
                    if part.startswith("TX="):
                        try: tx_bytes = int(part[3:])
                        except: pass
                    elif part.startswith("RX="):
                        try: rx_bytes = int(part[3:])
                        except: pass
            elif len(parts) > 5: reason = " ".join(parts[5:]).strip("()")
            with conn_lock:
                if ok: ok_count[0] += 1
                else: fail_count[0] += 1
                conn_n[0] += 1; n = conn_n[0]
            st = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]X  [/]"
            active_p = proxies[0] if proxies else None
            if proxies and proxy_label:
                for p in proxies:
                    if f"{p['host']}:{p['port']}" == proxy_label: active_p = p; break
            if active_p:
                ci = ip_info.get(active_p["host"], {})
                chain_s = f"{ci.get('flag','??')}[bold #00BFFF]{active_p['host']}:{active_p['port']}[/bold #00BFFF][dim]({ci.get('code','??')})[/dim]"
            else: chain_s = "[dim]Tor[/dim]"
            line_out = f"  [dim]#{n:04d} {ts}[/dim] {st}  {chain_s} [dim]->[/dim] [bold white]{dest}[/bold white]"
            if ok and (tx_bytes or rx_bytes):
                def _fmt(b):
                    if b < 1024: return f"{b}B"
                    if b < 1048576: return f"{b/1024:.1f}KB"
                    return f"{b/1048576:.1f}MB"
                line_out += f" [dim]up:{_fmt(tx_bytes)} dn:{_fmt(rx_bytes)}[/dim]"
            if reason and not ok: line_out += f" [dim red]{reason}[/dim red]"
            console.print(line_out); return
        if "ProxyChains" in line or "proxychains.sf.net" in line: return
        noisy = any(x in line for x in ["IPDL","GLib","dbus","Gtk","fontconfig","libGL","MOZ_","console.log"]) or len(line) > 300
        if line and not noisy: console.print(f"  [dim]{line[:120]}[/dim]")
    try:
        if pending_lines:
            for line in pending_lines: _process_line(line)
        for raw in iter(source_proc.stderr.readline, ""):
            _process_line(raw.strip())
    except Exception: pass

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  /etc/proxychains.conf PATCH (v3)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_ETC_BACKUP_PATH = "/etc/proxychains.conf.drip_backup"

def _sudo_run(cmd, timeout=15):
    allowed = ["sudo apt ","sudo cp ","sudo systemctl ","sudo service "]
    cmd_str = " ".join(cmd)
    if not any(cmd_str.startswith(p) for p in allowed): return False
    tty_in = None
    try: tty_in = open("/dev/tty", "r")
    except OSError: pass
    try: return subprocess.run(cmd, stdin=tty_in, timeout=timeout).returncode == 0
    except Exception: return False
    finally:
        if tty_in:
            try: tty_in.close()
            except: pass

def _patch_etc_proxychains(pc_conf_path):
    etc_conf = "/etc/proxychains.conf"
    try:
        with FileLock(etc_conf):
            if os.path.exists(etc_conf) and not os.path.exists(_ETC_BACKUP_PATH):
                try: shutil.copy2(etc_conf, _ETC_BACKUP_PATH)
                except PermissionError: _sudo_run(["sudo","cp",etc_conf,_ETC_BACKUP_PATH])
            try: shutil.copy2(pc_conf_path, etc_conf); return True
            except PermissionError:
                return _sudo_run(["sudo","cp",pc_conf_path,etc_conf])
    except Exception: return False

def _restore_etc_proxychains():
    etc_conf = "/etc/proxychains.conf"
    if not os.path.exists(_ETC_BACKUP_PATH): return
    try:
        with FileLock(etc_conf):
            try: shutil.copy2(_ETC_BACKUP_PATH, etc_conf); os.unlink(_ETC_BACKUP_PATH)
            except PermissionError:
                _sudo_run(["sudo","cp",_ETC_BACKUP_PATH,etc_conf])
    except Exception: pass

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VPN DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def detect_vpn():
    try:
        r = subprocess.run(["ip","addr","show"], capture_output=True, text=True, timeout=3)
        output = r.stdout
    except Exception: return False, None, None
    for pattern in [r"(tun\d+)",r"(wg\d+)",r"(tap\d+)",r"(ppp\d+)",r"(proton\d+)",r"(nordlynx)"]:
        m = re.search(pattern, output)
        if m:
            iface = m.group(1)
            block = re.search(rf"{re.escape(iface)}.*?(?=^\d|\Z)", output, re.MULTILINE|re.DOTALL)
            ip = None
            if block:
                ip_m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", block.group())
                if ip_m: ip = ip_m.group(1)
            return True, iface, ip
    return False, None, None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL CLASSIFICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_NON_TCP_TOOLS = {"ping":"ICMP","ping6":"ICMPv6","traceroute":"UDP/ICMP","tracepath":"UDP",
                  "arping":"ARP","netdiscover":"ARP","arp-scan":"ARP","hping3":"raw sockets","nping":"ICMP"}
_DNS_TOOLS = {"nslookup":"UDP DNS","dig":"UDP DNS","host":"UDP DNS","drill":"UDP DNS"}
_RAW_NMAP_FLAGS = {"-sS","-sU","-O","-sP","-sn","-PE","-PP","-PM","-PU","-PY"}

_BATCH_TOOLS = {
    "sqlmap":  "--batch",
    "ghauri":  "--batch",
}
_RANDOM_AGENT_TOOLS = {"sqlmap", "ghauri"}

def _is_tool_tcp_capable(tool_name, tool_args):
    name = tool_name.lower().split("/")[-1]
    if name in _NON_TCP_TOOLS: return False, _NON_TCP_TOOLS[name]
    if name in _DNS_TOOLS: return False, _DNS_TOOLS[name]
    if name == "nmap":
        raw = [f for f in tool_args if f in _RAW_NMAP_FLAGS]
        if raw: return False, "nmap raw flags: " + " ".join(raw)
    return True, None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h","--help"):
        print_usage(); sys.exit(0)

    if sys.argv[1] == "--browser":
        _BROWSER_MODE = True
        sys.argv = [sys.argv[0]] + ["firefox"] + sys.argv[2:]
    else:
        _BROWSER_MODE = False

    tool_args = sys.argv[1:]
    cfg = load_config()
    tool_name = tool_args[0].lower().split("/")[-1]

    global _PROCESS_RENAME_ENABLED
    _PROCESS_RENAME_ENABLED = cfg.get("process_rename", False)
    if _PROCESS_RENAME_ENABLED:
        _try_rename_process(cfg.get("process_name", "drip-worker"))

    _child_procs = []; _child_lock = threading.Lock()
    def _kill_children():
        with _child_lock:
            for p in _child_procs:
                try:
                    if p.poll() is None:
                        p.terminate()
                        try: p.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            try: p.kill(); p.wait(timeout=2)
                            except Exception: pass
                except Exception: pass
            _child_procs.clear()
    register_cleanup(_kill_children)

    # ── Auto-patch nmap ───────────────────────────────────────────
    if tool_name == "nmap" and not _BROWSER_MODE:
        raw = [f for f in tool_args if f in _RAW_NMAP_FLAGS]
        if not raw:
            if "-sT" not in tool_args: tool_args.insert(1, "-sT")
            if "-Pn" not in tool_args: tool_args.insert(1, "-Pn")
            console.print("  [dim]auto-injected -sT -Pn for nmap[/dim]")

    # ── Auto-patch sqlmap/ghauri ──────────────────────────────────
    if tool_name in _BATCH_TOOLS and not _BROWSER_MODE:
        batch_flag = _BATCH_TOOLS[tool_name]
        if batch_flag not in tool_args:
            tool_args.insert(1, batch_flag)
            console.print(f"  [dim]auto-injected {batch_flag} (non-interactive mode)[/dim]")
        if tool_name in _RANDOM_AGENT_TOOLS:
            if "--random-agent" not in tool_args:
                tool_args.insert(1, "--random-agent")
                console.print("  [dim]auto-injected --random-agent (anonymity)[/dim]")
        url_arg = next((a for a in tool_args if a.startswith("http")), "")
        if url_arg.startswith("https"):
            if "--timeout" not in tool_args:
                tool_args += ["--timeout", "30"]
            if "--retries" not in tool_args:
                tool_args += ["--retries", "2"]
            console.print("  [dim]HTTPS target: auto-injected --timeout 30 --retries 2[/dim]")

    # ── Auto-patch nikto ──────────────────────────────────────────
    if tool_name == "nikto" and not _BROWSER_MODE:
        if "-timeout" not in tool_args and "-Timeout" not in tool_args:
            tool_args += ["-timeout", "15"]
            console.print("  [dim]auto-injected -timeout 15 for nikto[/dim]")

    # ── Auto-patch ffuf/gobuster timeouts ─────────────────────────
    if tool_name in ("wfuzz", "ffuf", "gobuster") and not _BROWSER_MODE:
        if tool_name == "ffuf":
            if "-timeout" not in " ".join(tool_args):
                tool_args += ["-timeout", "20"]
                console.print("  [dim]auto-injected -timeout 20 for ffuf[/dim]")
        elif tool_name == "gobuster":
            if "--timeout" not in tool_args:
                tool_args += ["--timeout", "20s"]
                console.print("  [dim]auto-injected --timeout 20s for gobuster[/dim]")

    can_proxy, non_tcp_reason = _is_tool_tcp_capable(tool_name, tool_args)
    vpn_active, vpn_iface, vpn_ip = detect_vpn()

    # ━━━━━ NON-TCP TOOL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if not can_proxy and not _BROWSER_MODE:
        if vpn_active:
            console.print(Panel(_make_kv_table([
                ("VPN", f"[bold #FF0000]{vpn_iface}[/bold #FF0000] active"),
                ("tool", f"{tool_name} ({non_tcp_reason})"),
                ("command", " ".join(tool_args)),
            ]), title="[bold #FF0000]DRIP — DIRECT VPN MODE[/]", border_style="#0055FF", padding=(0,2)))
        else:
            console.print(Panel(
                f"[bold #FF0000]NON-TCP TOOL — NO PROTECTION[/bold #FF0000]\n\n"
                f"  {tool_name} uses {non_tcp_reason} — not proxychainable\n"
                f"  Connect a VPN first.\n\n"
                f"  [dim]Continuing in 5s... Ctrl+C to cancel[/dim]",
                title="[bold #FF0000]NO VPN[/bold #FF0000]", border_style="#FFAA00", padding=(0,2)))
            try: time.sleep(5)
            except KeyboardInterrupt: console.print("[#FF0000]cancelled.[/]"); sys.exit(0)
        start = time.perf_counter()
        proc = None
        _tty = None
        try:
            try: _tty = open("/dev/tty", "r")
            except OSError: pass
            proc = subprocess.Popen(tool_args, stdin=_tty)
            with _child_lock: _child_procs.append(proc)
            proc.wait(); rc = proc.returncode or 0
        except FileNotFoundError:
            console.print(f"[#FF0000]command not found: {tool_args[0]}[/]"); rc = 127
        except KeyboardInterrupt:
            if proc and proc.poll() is None:
                try: proc.terminate()
                except Exception: pass
            rc = 130
        finally:
            if _tty:
                try: _tty.close()
                except: pass
        elapsed = time.perf_counter() - start
        console.print(); console.print(Rule(style="#FF0000"))
        console.print(Align.center(Panel(_make_kv_table([
            ("mode", f"VPN ({vpn_iface})" if vpn_active else "DIRECT"),
            ("elapsed", f"{elapsed:.1f}s"),
        ]), title="[#FF0000]DONE[/]", border_style="#0055FF", padding=(0,2))))
        sys.exit(rc)

    # Browser warning
    if not _BROWSER_MODE and tool_name in _BROWSER_EXES:
        console.print(Panel(
            f"  Running {tool_args[0]} through proxychains leaks DNS.\n"
            f"  Use: [bold white]python3 drip.py --browser[/bold white]\n"
            f"  [dim]Continuing in 5s...[/dim]",
            title="[bold #FF0000]USE --browser[/bold #FF0000]", border_style="#FF0000", padding=(0,2)))
        try: time.sleep(5)
        except KeyboardInterrupt: console.print("[#FF0000]cancelled.[/]"); sys.exit(0)

    warn_leaky_browser(tool_args[0])

    pc_bin, is_v4 = find_proxychains()
    if not pc_bin:
        install_cmd = "sudo apt install proxychains4"
        if shutil.which("pacman"): install_cmd = "sudo pacman -S proxychains-ng"
        elif shutil.which("dnf"): install_cmd = "sudo dnf install proxychains-ng"
        console.print(Panel(f"[bold #FF0000]proxychains not found![/bold #FF0000]\n\n  Install: {install_cmd}",
            title="[bold #FF0000]MISSING[/bold #FF0000]", border_style="#FF0000", padding=(0,2)))
        sys.exit(1)

    if not is_v4:
        console.print("[dim]  proxychains v3 detected — will patch /etc/proxychains.conf[/dim]")

    # ━━━━━ Read proxies ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if sys.stdin.isatty():
        tor_mode = True
        if not ensure_tor():
            console.print("[#FF0000]Tor could not start.[/]"); sys.exit(1)
        proxies = []; lats = {}; countries = {}
    else:
        tor_mode = False
        try: stdin_data = sys.stdin.read()
        except Exception: stdin_data = ""
        if not stdin_data.strip():
            console.print("[#FF0000]no proxy input received[/]"); sys.exit(1)
        raw = parse_proxies(stdin_data, cfg["ptype"])
        if not raw:
            console.print("[#FF0000]no valid proxies found[/]"); sys.exit(1)
        try:
            old_fd = os.dup(0)
            tty_fd = os.open("/dev/tty", os.O_RDONLY)
            os.dup2(tty_fd, 0); os.close(tty_fd); os.close(old_fd)
            sys.stdin = os.fdopen(0, "r")
        except OSError:
            console.print("  [dim yellow]warning: could not reconnect stdin to /dev/tty[/dim yellow]")
        proxies, lats = fast_filter(raw, cfg["quick_ms"])
        if not proxies:
            console.print(f"[#FF0000]no proxies passed {cfg['quick_ms']}ms filter[/]"); sys.exit(1)
        countries = {}
        if cfg["country"]:
            console.print("[dim]  looking up countries...[/dim]", end=" ")
            try:
                countries = lookup_countries(list({p["host"] for p in proxies}))
                console.print("[#FF0000]done[/]")
            except Exception: console.print("[dim]skipped[/dim]")
        blacklist = cfg.get("country_blacklist", set())
        if blacklist and countries:
            before = len(proxies)
            proxies, dropped, details = filter_blacklisted_countries(proxies, countries, blacklist)
            show_blacklist_results(before, dropped, details, blacklist)
            if not proxies:
                console.print(f"[#FF0000]ALL proxies blacklisted![/]"); sys.exit(1)

    # ━━━━━ Select chain proxies ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if tor_mode:
        chain_proxies = proxies
        clen = cfg["chain_len"]
    else:
        chain_proxies, clen = _select_chain_proxies(proxies, cfg, lats)
        console.print(
            f"  [bold #FF0000]chain: {len(chain_proxies)} proxies "
            f"(chain_len={cfg['chain_len']}"
            f"{'+' + str(len(chain_proxies) - cfg['chain_len']) + ' backup' if len(chain_proxies) > cfg['chain_len'] else ''}"
            f") from {len(proxies)} available[/bold #FF0000]"
        )

    # Write configs
    pc_conf_quiet = write_pc_conf(chain_proxies, cfg, tor_mode, chain_len=clen)
    pc_conf_verbose = write_pc_conf_verbose(chain_proxies, cfg, tor_mode, chain_len=clen)

    # Patch /etc for v3
    if not is_v4:
        register_cleanup(_restore_etc_proxychains)
        _patch_etc_proxychains(pc_conf_verbose)

    print_banner(cfg, chain_proxies, tool_args, tor_mode, pc_bin, pc_conf_verbose)

    ok, exit_ip = preflight(chain_proxies, cfg, lats, countries, pc_bin, pc_conf_quiet,
                            tor_mode, is_v4, chain_len=clen)
    if not ok: sys.exit(1)

    start = time.perf_counter()
    ok_count = [0]; fail_count = [0]

    # ━━━━━ Init proxy rotator ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    rotator = None
    if not tor_mode and cfg.get("rotation") and len(proxies) > cfg["chain_len"]:
        rotator = ProxyRotator(proxies, cfg, lats, countries, is_v4, pc_bin)
        console.print(
            f"  [bold #FFAA00]⟳ rotation enabled[/bold #FFAA00]  "
            f"[dim](pool:{len(proxies)}, rotate after {cfg['max_conn_fails']} full connection fails"
            f"{', or every ' + str(cfg['rotation_interval']) + 's' if cfg['rotation_interval'] > 0 else ''})[/dim]"
        )
        console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  BROWSER MODE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if _BROWSER_MODE:
        console.print(Rule(style="#FF0000"))
        console.print("  [dim]#     time      result   PROXY -> DESTINATION[/dim]")
        console.print(Rule(style="#0055FF")); console.print()
        ff = _find_firefox()
        if not ff:
            console.print("[#FF0000]Firefox not found. sudo apt install firefox-esr[/]"); sys.exit(1)
        if tor_mode and not proxies:
            browser_pool = [{"host":"127.0.0.1","port":9050,"type":"socks5","user":None,"pwd":None}]
        else:
            proxies_typed, type_counts = analyze_proxy_types(proxies)
            if not tor_mode: show_proxy_type_warning(type_counts, cfg.get("socks_only", False))
            socks_only = cfg.get("socks_only", False)
            browser_pool = proxies_typed
            if socks_only:
                browser_pool = [p for p in browser_pool if p.get("type","socks5") != "http"]
                if not browser_pool: browser_pool = proxies_typed
            browser_pool = browser_pool[:15]
            if cfg.get("random"): random.shuffle(browser_pool)
        console.print(f"  [bold #FF0000]browser proxy pool: {len(browser_pool)} (single-hop with rotation)[/bold #FF0000]")
        console.print()
        console.print("  [dim]starting SOCKS5 forwarder...[/dim]")
        fw_proc, fw_port, pending = _start_local_socks5(browser_pool, cfg, tor_mode)
        if fw_proc and fw_port:
            with _child_lock: _child_procs.append(fw_proc)
            console.print(f"  [bold #FF0000]SOCKS5 forwarder -> 127.0.0.1:{fw_port}[/bold #FF0000]")
            patched = _patch_current_user_profiles(socks_port=fw_port)
            if patched:
                console.print(f"  [bold #FF0000]patched {len(patched)} Firefox profile(s)[/bold #FF0000]")
            else:
                console.print("  [#FF0000]no Firefox profiles found[/]")
        else:
            console.print("[bold #FF0000]SOCKS5 forwarder failed[/bold #FF0000]"); sys.exit(1)
        console.print()
        log_thread = None
        try:
            _real_user = _get_real_user()
            ff_env = os.environ.copy()
            ff_env.pop("PROXYCHAINS_CONF_FILE", None)
            if _real_user and _real_user != "root" and os.getuid() == 0:
                ff_cmd = ["sudo","-u",_real_user,ff]
                if "DISPLAY" not in ff_env: ff_env["DISPLAY"] = ":0"
            else:
                ff_cmd = [ff]
            ff_proc = subprocess.Popen(ff_cmd, env=ff_env, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
            with _child_lock: _child_procs.append(ff_proc)
            log_thread = threading.Thread(target=_browser_log_thread,
                args=(fw_proc, browser_pool, countries, ok_count, fail_count, pending),
                daemon=True, name="drip-log")
            log_thread.start()
            ff_proc.wait(); rc = ff_proc.returncode or 0
        except KeyboardInterrupt: rc = 0
        finally:
            try:
                if fw_proc and fw_proc.poll() is None:
                    fw_proc.terminate()
            except Exception: pass
        if log_thread and log_thread.is_alive(): log_thread.join(timeout=3.0)
        console.print(); console.print(Rule(style="#FF0000"))
        print_footer(time.perf_counter()-start, exit_ip, ok_count[0], fail_count[0], tor_mode, browser_pool)
        sys.exit(rc)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  REGULAR PROXYCHAINS MODE — WITH ROTATION SUPPORT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    env = os.environ.copy()

    if rotator:
        active_conf = rotator.conf_path
    else:
        active_conf = pc_conf_verbose

    env["PROXYCHAINS_CONF_FILE"] = active_conf
    env["PROXYCHAINS_QUIET_MODE"] = "0"

    if is_v4:
        cmd = [pc_bin, "-f", active_conf] + tool_args
    else:
        cmd = [pc_bin] + tool_args

    proc = None
    _tty = None
    try:
        try: _tty = open("/dev/tty", "r")
        except OSError: pass
        proc = subprocess.Popen(cmd, env=env, stdin=_tty,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        with _child_lock: _child_procs.append(proc)
        stream_with_live_log(proc, chain_proxies, countries, cfg,
                             ok_count, fail_count, rotator=rotator)
        rc = proc.returncode or 0
    except FileNotFoundError:
        console.print(f"[#FF0000]command not found: {tool_args[0]}[/]"); rc = 127
    except KeyboardInterrupt:
        if proc and proc.poll() is None:
            try: proc.terminate()
            except Exception: pass
        console.print("\n[#FF0000]interrupted[/]"); rc = 130
    finally:
        if _tty:
            try: _tty.close()
            except: pass

    console.print(); console.print(Rule(style="#FF0000"))
    print_footer(time.perf_counter()-start, exit_ip, ok_count[0], fail_count[0],
                 tor_mode, chain_proxies, rotator=rotator)
    sys.exit(rc)


if __name__ == "__main__":
    main()
