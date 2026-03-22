#!/usr/bin/env python3
"""
drip.py — proxychains wrapper with elite UI
usage: cat proxies.txt | python3 drip.py <tool> [args]
       python3 drip.py <tool> [args]   ← tor auto
"""

import sys, os, subprocess, socket, time, threading, random, tempfile, signal
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
try:
    import ctypes
    ctypes.CDLL("libc.so.6").prctl(15, b"kworker/2:1H\x00", 0, 0, 0)
except: pass

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050
SCRIPT_DIR  = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "drip.yml"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFAULT_CONFIG = """\
# drip.yml — proxychains wrapper config

# ── Chain mode (ONE = T) ─────────────────────────────
strict_chain:   T   # all proxies in order, fail if any dead
dynamic_chain:  F   # skip dead proxies automatically
random_chain:   F   # random proxies each connection

# ── Options ─────────────────────────────────────────
chain_len:      3       # proxies in random mode
timeout:        8       # connect timeout per proxy (seconds)
quick_timeout:  3000    # ms — skip proxy if no response in 3000ms
proxy_type:     socks5  # socks5 | socks4 | http | auto
proxy_dns:      T       # resolve DNS through proxy (no leaks)
tcp_read_time:  15000   # proxychains TCP read timeout ms
tcp_conn_time:  8000    # proxychains TCP connect timeout ms
country_lookup: T       # show country flags

# ── Browser mode ─────────────────────────────────────
browser_chain_len: 1    # hops for browser mode — keep at 1 for free proxies!
socks_only:     F       # T = drop HTTP proxies in browser mode
"""

def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(DEFAULT_CONFIG)
    lines=[]
    for line in CONFIG_PATH.read_text().splitlines():
        s=line.strip()
        if s.startswith("#"):  lines.append("")
        elif "#" in line:      lines.append(line[:line.index("#")].rstrip())
        else:                  lines.append(line)
    cfg=yaml.safe_load("\n".join(lines)) or {}
    def b(k,d=False):
        v=cfg.get(k,d)
        return str(v).strip().upper() in("T","TRUE","YES","1") if not isinstance(v,bool) else v
    return {
        "strict":      b("strict_chain",True),
        "dynamic":     b("dynamic_chain"),
        "random":      b("random_chain"),
        "chain_len":   max(1,int(cfg.get("chain_len",3))),
        "browser_len": max(1,int(cfg.get("browser_chain_len",3))),
        "timeout":     max(1.0,float(cfg.get("timeout",8))),
        "quick_ms":    max(50,int(cfg.get("quick_timeout",3000))),
        "ptype":       str(cfg.get("proxy_type","socks5")).lower().strip(),
        "proxy_dns":   b("proxy_dns",True),
        "tcp_read":    int(cfg.get("tcp_read_time",15000)),
        "tcp_conn":    int(cfg.get("tcp_conn_time",8000)),
        "country":     b("country_lookup",True),
        "socks_only":  b("socks_only"),
    }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FLAGS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FLAGS={
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
def _flag(cc): return FLAGS.get((cc or "").upper(),"🌐")

def lookup_countries(ips):
    result={}
    s=_req.Session(); s.trust_env=False
    for i in range(0,len(ips),100):
        batch=ips[i:i+100]
        try:
            r=s.post("http://ip-api.com/batch?fields=query,countryCode,country,city",
                     json=[{"query":ip} for ip in batch],timeout=8)
            for e in r.json():
                ip=e.get("query",""); cc=e.get("countryCode","??")
                result[ip]={"code":cc,"country":e.get("country","?"),
                            "city":e.get("city",""),"flag":_flag(cc)}
        except:
            for ip in batch: result[ip]={"code":"??","country":"?","city":"","flag":"🌐"}
    return result

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY PARSING + 300ms QUICK FILTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_proxies(text, ptype="socks5"):
    out=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith("#"): continue
        p=line.split(":")
        try:
            if len(p)==2:
                out.append({"host":p[0],"port":int(p[1]),"user":None,"pwd":None,"type":ptype})
            elif len(p)==4:
                out.append({"host":p[0],"port":int(p[1]),"user":p[2],"pwd":p[3],"type":ptype})
        except: pass
    return out

def _quick_test(px, ms):
    t0=time.perf_counter()
    try:
        s=socket.socket(); s.settimeout(ms/1000.0)
        s.connect((px["host"],px["port"])); s.close()
        return int((time.perf_counter()-t0)*1000)
    except: return None

def fast_filter(proxies, ms, workers=150):
    fast=[]; lats={}
    console.print(f"  [dim]quick-testing {len(proxies)} proxies ({ms}ms cutoff)...[/dim]",end=" ")
    with ThreadPoolExecutor(max_workers=min(workers,len(proxies))) as ex:
        futs={ex.submit(_quick_test,px,ms):px for px in proxies}
        for f in as_completed(futs):
            px=futs[f]; lat=f.result()
            if lat is not None:
                fast.append(px); lats[(px["host"],px["port"])]=lat
    console.print(f"[bold #FF0000]{len(fast)}/{len(proxies)} passed[/]")
    return fast, lats

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY TYPE ANALYSIS + WARNING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_HTTP_PROXY_PORTS = {80, 81, 443, 3128, 3129, 8008, 8080, 8118, 8123,
                     8181, 8888, 6588, 3333}
_SOCKS_PROXY_PORTS = {1080, 1081, 1082, 1083, 9050, 9150}

def classify_proxy_type(p):
    """Classify proxy as socks5/socks4/http based on declared type + port heuristic."""
    pt = (p.get("type") or "socks5").lower()
    port = p.get("port", 0)
    # Port-based override: HTTP ports always HTTP, dedicated SOCKS always SOCKS
    if port in _HTTP_PROXY_PORTS:   return "http"
    if port in _SOCKS_PROXY_PORTS:  return pt if pt.startswith("socks") else "socks5"
    return pt

def analyze_proxy_types(proxies):
    """Count proxy types and return breakdown."""
    counts = {"socks5":0,"socks4":0,"http":0,"other":0}
    typed = []
    for p in proxies:
        t = classify_proxy_type(p)
        if t in ("socks5","socks5h"):        counts["socks5"] += 1; typed.append({**p,"type":"socks5"})
        elif t in ("socks4","socks4a"):      counts["socks4"] += 1; typed.append({**p,"type":"socks4"})
        elif t in ("http","https","http_connect"): counts["http"] += 1; typed.append({**p,"type":"http"})
        else:                                counts["socks5"] += 1; typed.append({**p,"type":"socks5"})
    return typed, counts

def show_proxy_type_warning(counts, socks_only=False):
    """Show warning panel if mixed types or HTTP-only mode active."""
    total = sum(counts.values())
    socks_count = counts["socks5"] + counts["socks4"]
    http_count  = counts["http"]
    if http_count == 0 and socks_count > 0:
        return  # all good, no warning needed
    lines = []
    if socks_count > 0 and http_count > 0:
        lines.append("[bold #FF0000]⚠️  MIXED PROXY TYPES DETECTED![/bold #FF0000]")
        lines.append("")
        if counts["socks5"]: lines.append(f"  [bold #FF0000]{counts['socks5']}[/bold #FF0000] SOCKS5 proxies")
        if counts["socks4"]: lines.append(f"  [bold #FF0000]{counts['socks4']}[/bold #FF0000] SOCKS4 proxies")
        if counts["http"]:   lines.append(f"  [bold #0055FF]{counts['http']}[/bold #0055FF] HTTP proxies")
        lines.append("")
        if socks_only:
            lines.append(f"  [bold #FF0000]HTTP proxies SKIPPED[/bold #FF0000] (socks_only=T in drip.yml)")
            lines.append(f"  [dim]Using {socks_count} SOCKS proxies only[/dim]")
        else:
            lines.append("  [dim]HTTP + SOCKS proxies will ALL be used via pproxy auto-detection[/dim]")
    elif http_count > 0 and socks_count == 0:
        lines.append("[bold #FF0000]⚠️  ALL PROXIES ARE HTTP — browser chain may be unreliable[/bold #FF0000]")
        lines.append("  [dim]HTTP proxies don't support multi-hop tunneling reliably[/dim]")
        lines.append("  [dim]Consider using SOCKS4/SOCKS5 proxies for better results[/dim]")
    if lines:
        console.print(Panel(
            "\n".join(lines),
            title="[bold #FF0000]PROXY TYPE WARNING[/bold #FF0000]",
            border_style="#FF0000", padding=(0,2)
        ))
        console.print()

def select_browser_chain(proxies_typed, cfg):
    """
    Select the best proxies for browser chaining.
    - In strict mode: use ALL proxies (user asked for it, cap at browser_len)
    - In random mode: pick cfg['browser_len'] random proxies
    - In dynamic mode: pick cfg['browser_len'] best (by latency if available)
    Always prefer SOCKS over HTTP. Cap at browser_len.
    socks_only=T filters out HTTP proxies first.
    """
    blen = cfg.get("browser_len", 3)
    socks_only = cfg.get("socks_only", False)

    pool = proxies_typed
    if socks_only:
        pool = [p for p in pool if p.get("type","socks5") != "http"]
        if not pool:
            console.print("[#FF0000]⚠️  socks_only=T but no SOCKS proxies found — using all[/]")
            pool = proxies_typed

    if cfg.get("strict"):
        # Strict: use proxies in order, capped at browser_len
        selected = pool[:blen]
        console.print(f"  [dim]strict chain: using first {len(selected)} of {len(pool)} proxies[/dim]")
    elif cfg.get("random"):
        selected = random.sample(pool, min(blen, len(pool)))
        console.print(f"  [dim]random chain: picked {len(selected)} random proxies[/dim]")
    else:
        # Dynamic: pick blen random proxies from top-20 fastest (rotation per run)
        top = pool[:min(20, len(pool))]
        selected = random.sample(top, min(blen, len(top)))
        console.print(f"  [dim]dynamic chain: {len(selected)} random from top-{len(top)} fastest[/dim]")

    return selected

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WRITE PROXYCHAINS CONFIG
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def write_pc_conf(proxies, cfg, tor_mode=False, chain_len=None):
    """Generate proxychains4.conf and return path."""
    lines=[]

    # chain mode
    if tor_mode:
        lines.append("dynamic_chain")
    elif cfg["strict"]:
        lines.append("strict_chain")
    elif cfg["random"]:
        lines.append("random_chain")
        lines.append(f"chain_len {chain_len or cfg['chain_len']}")
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
        ptype = cfg["ptype"]
        for px in proxies:
            t = px.get("type", ptype)
            if t in ("socks5h","socks5"): t="socks5"
            elif t in ("socks4a","socks4"): t="socks4"
            else: t="http"
            if px.get("user"):
                lines.append(f"{t} {px['host']} {px['port']} {px['user']} {px['pwd'] or ''}")
            else:
                lines.append(f"{t} {px['host']} {px['port']}")

    conf="\n".join(lines)+"\n"
    tmp=tempfile.NamedTemporaryFile(mode="w",suffix=".conf",delete=False,prefix="drip_pc_")
    tmp.write(conf); tmp.flush(); tmp.close()
    return tmp.name

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIND PROXYCHAINS BINARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def find_proxychains():
    """Find proxychains binary and detect version."""
    for name in ["proxychains4","proxychains"]:
        r=subprocess.run(["which",name],capture_output=True,text=True)
        if r.returncode==0:
            path=r.stdout.strip()
            # detect version — v3 doesn't support -f flag
            try:
                ver=subprocess.run([path,"--version"],capture_output=True,text=True,timeout=2)
                is_v4 = "4." in (ver.stdout+ver.stderr) or name=="proxychains4"
            except:
                is_v4 = name=="proxychains4"
            return path, is_v4
    return None, False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PREFLIGHT — test chain + exit IP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def get_real_ip():
    """Get our real IP without any proxy."""
    import re
    for url in ["http://api.ipify.org","http://ifconfig.me/ip","http://icanhazip.com"]:
        try:
            r=subprocess.run(["curl","-s","--max-time","5","--noproxy","*",url],
                             capture_output=True,text=True,timeout=8)
            ip=r.stdout.strip()
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$",ip): return ip
        except: pass
    return None

def get_exit_ip(pc_bin, pc_conf, is_v4):
    """Get exit IP through the proxy chain using HTTP (not HTTPS)."""
    import re
    # try multiple plain HTTP endpoints — proxychains v3 handles HTTP fine
    endpoints = [
        "http://api.ipify.org",
        "http://ifconfig.me/ip",
        "http://icanhazip.com",
        "http://checkip.amazonaws.com",
        "http://ip.42.pl/raw",
    ]
    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"] = pc_conf

    for url in endpoints:
        try:
            if is_v4:
                cmd=[pc_bin,"-f",pc_conf,"-q","curl","-s","--max-time","20",url]
                r=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
            else:
                cmd=[pc_bin,"curl","-s","--max-time","20",url]
                r=subprocess.run(cmd,capture_output=True,text=True,timeout=25,env=env)
            # strip proxychains banner from output
            for line in r.stdout.splitlines():
                line=line.strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$",line):
                    return line
        except: pass
    return None

def _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei):
    """Build a clear visual showing real IP → entry proxy → exit IP → target."""
    lines = []

    # YOUR REAL IP
    r_flag = ri.get("flag","🌐"); r_cn = ri.get("country","?"); r_city = ri.get("city","")
    lines.append(f"  [bold white]YOUR MACHINE[/bold white]")
    if real_ip:
        lines.append(f"  [bold #FF0000]  IP  : {real_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {r_flag} {r_cn}, {r_city}[/dim]")
        lines.append(f"  [dim]  ← this is YOUR real identity[/dim]")
    else:
        lines.append(f"  [dim]  IP  : unknown[/dim]")
    lines.append("")

    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼  (your traffic enters here)[/dim]")
    lines.append("")

    # ENTRY PROXY (first hop)
    lines.append(f"  [bold white]ENTRY PROXY  (first hop — knows your real IP)[/bold white]")
    if entry_px:
        p_flag = pi.get("flag","🌐"); p_cn = pi.get("country","?"); p_city = pi.get("city","")
        lines.append(f"  [bold #00BFFF]  IP  : {entry_px['host']}:{entry_px['port']}[/bold #00BFFF]")
        lines.append(f"  [dim]  LOC : {p_flag} {p_cn}, {p_city}[/dim]")
        lines.append(f"  [dim]  TYPE: {entry_px['type'].upper()}[/dim]")
        lines.append(f"  [dim]  ← this proxy sees your real IP but not the destination[/dim]")
    lines.append("")

    if len(proxies) > 1:
        lines.append("        [dim]│[/dim]")
        lines.append(f"        [dim]▼  ({len(proxies)-1} more hop(s) in between)[/dim]")
        lines.append("")

    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼  (traffic exits here)[/dim]")
    lines.append("")

    # EXIT IP (what target sees)
    lines.append(f"  [bold white]EXIT IP  (what the target sees)[/bold white]")
    if exit_ip:
        e_flag = ei.get("flag","🌐"); e_cn = ei.get("country","?"); e_city = ei.get("city","")
        lines.append(f"  [bold #FF0000]  IP  : {exit_ip}[/bold #FF0000]")
        lines.append(f"  [dim]  LOC : {e_flag} {e_cn}, {e_city}[/dim]")
        if real_ip and exit_ip != real_ip:
            lines.append(f"  [bold #FF0000]  ✅  target sees this IP — your real IP {real_ip} is HIDDEN[/bold #FF0000]")
        elif real_ip and exit_ip == real_ip:
            lines.append(f"  [bold #0055FF]  ⚠️   exit IP = your real IP — proxy NOT working[/bold #0055FF]")
    else:
        lines.append(f"  [dim]  IP  : could not confirm (try: cat p.txt | python3 drip.py curl http://api.ipify.org)[/dim]")

    lines.append("")
    lines.append("        [dim]│[/dim]")
    lines.append("        [dim]▼[/dim]")
    lines.append("")
    lines.append("  [bold white]TARGET (website / server)[/bold white]")
    lines.append("  [dim]  sees only the EXIT IP above — never your real IP[/dim]")

    return "\n".join(lines)

def preflight(proxies, cfg, lats, countries, pc_bin, pc_conf, tor_mode, is_v4=True):
    console.print()

    if tor_mode:
        console.print("  [dim]checking Tor...[/dim]",end=" ")
        try:
            s=socket.create_connection((TOR_HOST,TOR_PORT),timeout=5); s.close()
            console.print("[bold #FF0000]✅ Tor up[/]")
        except:
            console.print("[bold #FF0000]❌ Tor not running[/]")
            return False, None
    else:
        # show chain sample
        sample=proxies[:min(5,len(proxies))]
        parts=[]
        for p in sample:
            ci=countries.get(p["host"],{}); fl=ci.get("flag","🌐"); cn=ci.get("country","?")
            parts.append(f"{fl}[bold #00BFFF]{p['host']}:{p['port']}[/][dim]({cn})[/dim]")
        if len(proxies)>5: parts.append(f"[dim]+{len(proxies)-5} more[/dim]")
        console.print("  chain: "+"[dim]→[/dim]".join(parts)+"[dim]→TARGET[/dim]")
        console.print()

        # per-proxy table
        t=Table(box=box.SIMPLE,show_header=True,header_style="bold #FF0000",padding=(0,1))
        t.add_column("#",width=3,style="dim")
        t.add_column("proxy",min_width=22,style="bold #00BFFF")
        t.add_column("country",min_width=14)
        t.add_column("city",min_width=12,style="dim")
        t.add_column("type",width=7)
        t.add_column("latency",width=10,justify="right")
        t.add_column("",width=3)

        for i,px in enumerate(proxies[:20],1):
            ci=countries.get(px["host"],{}); fl=ci.get("flag","🌐")
            cn=ci.get("country","?"); ct=ci.get("city","")
            lat=lats.get((px["host"],px["port"]))
            ls=f"[bold #FF0000]{lat}ms[/]" if lat else "—"
            st="[#FF0000]✅[/]" if lat else "[#0055FF]❌[/]"
            t.add_row(str(i),f"{px['host']}:{px['port']}",f"{fl} {cn}",ct,
                      px["type"].upper(),ls,st)
        if len(proxies)>20:
            t.add_row("…",f"[dim]+{len(proxies)-20} more proxies[/dim]","","","","","")
        console.print(Align.center(t))

    # ── IP flow diagram ─────────────────────────────────────────────
    console.print()
    console.print("  [dim]resolving IPs...[/dim]")
    real_ip  = get_real_ip()
    exit_ip  = get_exit_ip(pc_bin, pc_conf, is_v4)
    entry_px = proxies[0] if proxies else None

    # lookup all at once
    ips_to_lookup = [ip for ip in [real_ip, exit_ip] if ip]
    if ips_to_lookup:
        geo = lookup_countries(ips_to_lookup)
    else:
        geo = {}

    ri = geo.get(real_ip,  {}) if real_ip  else {}
    ei = geo.get(exit_ip,  {}) if exit_ip  else {}
    pi = countries.get(entry_px["host"], {}) if entry_px else {}

    console.print()
    console.print(Panel(
        _build_ip_flow(real_ip, ri, entry_px, pi, proxies, exit_ip, ei),
        title="[bold white]IP FLOW — what each side sees[/bold white]",
        border_style="#FF0000",
        padding=(0, 2),
    ))
    console.print()
    return True, exit_ip

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def check_tor():
    try: s=socket.create_connection((TOR_HOST,TOR_PORT),timeout=3); s.close(); return True
    except: return False

def ensure_tor():
    if check_tor(): return True
    console.print("[#FF0000]🧅 starting Tor...[/]")
    for cmd in [["systemctl","start","tor"],["service","tor","start"]]:
        try:
            subprocess.run(cmd,capture_output=True,timeout=10)
            time.sleep(3)
            if check_tor(): console.print("[#FF0000]✅ Tor started[/]"); return True
        except: pass
    try:
        subprocess.Popen(["tor"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(5)
        if check_tor(): console.print("[#FF0000]✅ Tor started[/]"); return True
    except: pass
    return False

# ─────────────────────────────────────────────────────────────────────
#  LIVE OUTPUT PARSER  (used for regular proxychains tool mode)
# ─────────────────────────────────────────────────────────────────────
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
            sys.stdout.write(line); sys.stdout.flush()

    def _read_stderr():
        for raw in iter(proc.stderr.readline, ""):
            line = raw.strip()
            if "|S-chain|" in line:
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
#  BANNER + FOOTER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_banner(cfg, proxies, tool_args, tor_mode, pc_bin, pc_conf):
    mode=("[#FF0000]RANDOM[/]" if cfg["random"] else
          "[#FF0000]STRICT[/]" if cfg["strict"] else "[#00BFFF]DYNAMIC[/]")
    src=("[#FF0000]🧅 TOR[/] (auto)" if tor_mode else
         f"[#FF0000]{len(proxies)}[/] proxies  [dim](>{cfg['quick_ms']}ms skipped)[/dim]")
    t=Table(box=box.SIMPLE,show_header=False,padding=(0,2))
    t.add_column(style="#00BFFF bold"); t.add_column(style="bold white")
    t.add_row("⛓️  chain mode",    mode)
    t.add_row("📡  source",        src)
    t.add_row("🔧  backend",       f"[#FF0000]{pc_bin}[/] (battle-tested)")
    t.add_row("📄  config",        f"[dim]{pc_conf}[/dim]")
    t.add_row("⏱️  timeout",        f"{cfg['timeout']}s  [dim](tcp: {cfg['tcp_conn']}ms)[/dim]")
    t.add_row("🌐  proxy dns",     "[#FF0000]ON[/]" if cfg["proxy_dns"] else "[#0055FF]OFF[/]")
    t.add_row("🕵️  process name",  "kworker/2:1H")
    t.add_row("🚀  command",       " ".join(tool_args))
    console.print()
    console.print(Panel(t,title="[bold #FF0000]🔥🩸 DRIP — PROXYCHAINS WRAPPER 🩸🔥[/]",
                        border_style="#0055FF",padding=(0,2)))
    console.print()

def print_footer(elapsed, exit_ip, ok_count, fail_count, tor_mode, proxies):
    t=Table(box=box.SIMPLE,show_header=False,padding=(0,2))
    t.add_column(style="#00BFFF bold"); t.add_column(style="bold white")
    t.add_row("✅  connections ok",    str(ok_count))
    t.add_row("❌  connections failed",str(fail_count))
    if not tor_mode: t.add_row("📦  proxies used",   str(len(proxies)))
    t.add_row("⏱️   elapsed",           f"{elapsed:.1f}s")
    if exit_ip: t.add_row("🔴  exit IP",         exit_ip)
    console.print(); console.print(Rule(style="#FF0000"))
    console.print(Align.center(Panel(t,title="[#FF0000]🩸 DONE 🩸[/]",
                                     border_style="#0055FF",padding=(0,2))))
    console.print()

def print_usage():
    console.print(Panel(
        "[#FF0000]Usage:[/]\n"
        "  [white]cat proxies.txt | python3 drip.py <tool> [args][/]\n"
        "  [white]python3 drip.py <tool> [args][/]       [dim]← no proxies = Tor auto[/dim]\n"
        "  [white]python3 drip.py --browser[/]            [dim]← launch Tor Browser (recommended)[/dim]\n"
        "  [white]cat p.txt | python3 drip.py --browser[/] [dim]← Tor Browser through proxy chain[/dim]\n\n"
        "[#00BFFF]Browser recommendation:[/]\n"
        "  [bold #FF0000]Tor Browser[/bold #FF0000] — zero leaks, fully anonymous\n"
        "  [dim]Firefox  — leaks DNS unless fixed in about:config\n"
        "  Chrome   — leaks DNS + WebRTC, cannot be fully fixed[/dim]\n\n"
        "[#00BFFF]Examples:[/]\n"
        '  [dim]cat p.txt | python3 drip.py sqlmap -u "http://target.com?id=1"\n'
        "  cat p.txt | python3 drip.py nmap -sT target.com\n"
        "  cat p.txt | python3 drip.py --browser\n"
        "  python3 drip.py --browser   ← Tor Browser through Tor[/]\n\n"
        "[#00BFFF]Proxy formats:[/]\n"
        "  [dim]ip:port\n  ip:port:user:pass[/]\n\n"
        "[#00BFFF]Config:[/] [dim]drip.yml (auto-created)[/]",
        title="[#FF0000]🔥 DRIP — PROXYCHAINS WRAPPER 🔥[/]",
        border_style="#0055FF",padding=(1,4)))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOR BROWSER / FIREFOX HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOR_BROWSER_CMDS = [
    "torbrowser-launcher",
    "tor-browser",
    "tor-browser-en",
    "/usr/bin/torbrowser-launcher",
    "/opt/tor-browser/Browser/start-tor-browser",
]

LEAKY_BROWSERS = {
    "chromium": "DNS and WebRTC leak — cannot be fully fixed with proxychains",
    "chrome":   "DNS and WebRTC leak — cannot be fully fixed with proxychains",
    "google-chrome": "DNS and WebRTC leak — cannot be fully fixed",
    "brave":    "DNS leak — has own DNS resolver that bypasses proxychains",
    "opera":    "DNS and WebRTC leak",
    "vivaldi":  "DNS leak",
    "microsoft-edge": "DNS and WebRTC leak",
}

TOR_BROWSER_DIRECT = [
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/start-tor-browser"),
    "/opt/tor-browser/Browser/start-tor-browser",
    "/usr/bin/tor-browser",
]

def _make_tor_wrapper(browser_dir):
    firefox_direct   = os.path.join(browser_dir, "firefox")
    profile_direct   = os.path.join(browser_dir, "TorBrowser", "Data", "Browser", "profile.default")
    tb_script = os.path.join(browser_dir, "start-tor-browser")
    wrapper = Path("/tmp/drip_torbrowser.sh")
    if os.path.exists(firefox_direct):
        wrapper.write_text(
            "#!/bin/bash\n"
            f"cd \"{browser_dir}\"\n"
            f"exec ./firefox --profile \"{profile_direct}\" --no-remote 2>/dev/null\n"
        )
    elif os.path.exists(tb_script):
        wrapper.write_text(
            "#!/bin/bash\n"
            f"cd \"{browser_dir}\"\n"
            "./start-tor-browser 2>/dev/null &\n"
            "sleep 3\n"
            "FBPID=$(pgrep -f \"tor-browser.*/firefox\" 2>/dev/null | head -1)\n"
            "[ -z \"$FBPID\" ] && FBPID=$(pgrep -f \"Browser/firefox\" 2>/dev/null | head -1)\n"
            "[ -n \"$FBPID\" ] && tail --pid=\"$FBPID\" -f /dev/null 2>/dev/null || wait\n"
        )
    else:
        wrapper.write_text(
            "#!/bin/bash\n"
            "torbrowser-launcher 2>/dev/null &\n"
            "sleep 3\n"
            "FBPID=$(pgrep -f \"Browser/firefox\" 2>/dev/null | head -1)\n"
            "[ -n \"$FBPID\" ] && tail --pid=\"$FBPID\" -f /dev/null 2>/dev/null || wait\n"
        )
    wrapper.chmod(0o755)
    return [str(wrapper)]

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
            console.print("[dim]  found: direct binary (will stay alive while browsing)[/dim]")
            browser_dir = os.path.dirname(tb)
            return _make_tor_wrapper(browser_dir)
        else:
            console.print("[dim]  found: launcher — checking for direct binary...[/dim]")
            for path in TOR_BROWSER_DIRECT:
                if os.path.exists(path):
                    console.print(f"[dim]  using direct: {path}[/dim]")
                    browser_dir = os.path.dirname(path)
                    return _make_tor_wrapper(browser_dir)
            console.print("[dim]  first run — Tor Browser will install, then rerun this command[/dim]")
            return [tb]
    console.print("[dim]  torbrowser-launcher not found — installing...[/dim]")
    try:
        subprocess.run(["sudo","apt","install","-y","torbrowser-launcher"],
                       capture_output=True, timeout=120)
        tb, _ = find_tor_browser()
        if tb: return [tb]
    except: pass
    console.print("[#FF0000]❌ could not install torbrowser-launcher[/]")
    console.print("[dim]  manual: sudo apt install torbrowser-launcher[/dim]")
    return None

def _find_firefox():
    for name in ["firefox-esr","firefox"]:
        r = subprocess.run(["which", name], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None

def _get_all_firefox_profiles():
    import glob, configparser
    profiles = []
    bases = [
        os.path.expanduser("~/.mozilla/firefox"),
        os.path.expanduser("~/.firefox"),
        "/root/.mozilla/firefox",
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
                if cfg.get(section, "IsRelative", fallback="0") == "1":
                    full = os.path.join(base, path)
                else:
                    full = path
                if os.path.isdir(full) and full not in profiles:
                    profiles.append(full)
        for pattern in ["*.default-esr","*.default","*.default-release","*.esr"]:
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
    user_js_content = (
        "// drip.py — proxy + DNS leak fix (auto-generated)\n"
        'user_pref("network.proxy.type", 1);\n'
        f'user_pref("network.proxy.socks", "127.0.0.1");\n'
        f'user_pref("network.proxy.socks_port", {port});\n'
        'user_pref("network.proxy.socks_version", 5);\n'
        'user_pref("network.proxy.socks_remote_dns", true);\n'
        'user_pref("network.trr.mode", 5);\n'
        'user_pref("network.trr.uri", "");\n'
        'user_pref("network.trr.bootstrapAddr", "");\n'
        'user_pref("network.dns.disablePrefetch", true);\n'
        'user_pref("network.dns.disablePrefetchFromHTTPS", true);\n'
        'user_pref("network.predictor.enabled", false);\n'
        'user_pref("network.prefetch-next", false);\n'
        'user_pref("media.peerconnection.enabled", false);\n'
        'user_pref("media.peerconnection.ice.default_address_only", true);\n'
        'user_pref("network.proxy.no_proxies_on", "");\n'
    )
    user_js = os.path.join(profile_dir, "user.js")
    Path(user_js).write_text(user_js_content)
    prefs_js = os.path.join(profile_dir, "prefs.js")
    if os.path.exists(prefs_js):
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
            "network.proxy.no_proxies_on":    '""'
        }
        for key, val in patches.items():
            prefs = re.sub(rf'user_pref\("{re.escape(key)}".*?\);\n', "", prefs)
            prefs += f'user_pref("{key}", {val});\n'
        Path(prefs_js).write_text(prefs)
    return user_js

def _patch_all_profiles(socks_port=None):
    profiles = _get_all_firefox_profiles()
    if not profiles: return []
    patched = []
    for p in profiles:
        try:
            _patch_firefox_profile(p, socks_port)
            patched.append(p)
        except Exception: pass
    return patched

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PROXY PROTOCOL AUTO-DETECTION
#  Free proxy lists often mis-label HTTP proxies as "socks5".
#  Proxies on port 80/8080/3128/etc are almost always HTTP CONNECT.
#  We probe each proxy directly before building the chain.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Ports that are always HTTP CONNECT proxies regardless of what the list says
_HTTP_PROXY_PORTS = {80, 81, 443, 8080, 8008, 3128, 3129, 8118, 8123,
                     8888, 8181, 8888, 6588, 3333}
# Ports that are always SOCKS
_SOCKS_PROXY_PORTS = {1080, 1081, 1082, 1083, 9050, 9150}

def _port_guess(port, declared):
    """Fast port-based protocol guess, no network needed."""
    if port in _HTTP_PROXY_PORTS:    return "http"
    if port in _SOCKS_PROXY_PORTS:   return declared or "socks5"
    return declared or "socks5"

async def _probe_one(host, port, timeout=2.5):
    """
    Detect real proxy protocol by probing it directly.
    Send SOCKS5 greeting — check what byte comes back:
      0x05 → SOCKS5   |  anything else (HTTP, SOCKS4, garbage) → try HTTP CONNECT
    Returns: "socks5" | "http" | "socks4" | None (dead/unreachable)
    """
    import asyncio as _ao
    try:
        r, w = await _ao.wait_for(_ao.open_connection(host, port), timeout)
        w.write(bytes([5, 1, 0]))          # SOCKS5 VER=5, NMETHODS=1, NO_AUTH
        await w.drain()
        try:
            data = await _ao.wait_for(r.read(2), timeout)
        except _ao.TimeoutError:
            w.close(); return "socks5"     # slow but no rejection = socks5
        w.close()
        if not data:           return "http"   # closed → HTTP that rejected SOCKS5
        if data[0] == 5:       return "socks5"
        if data[0] == 4:       return "socks4"
        return "http"                          # HTTP/1.x response, starts with 'H'=0x48
    except Exception:
        return None                            # unreachable

def detect_proxy_types(proxies):
    """
    Probe all proxies in parallel and return updated list with correct types.
    Falls back to port-based guess if probe fails.
    """
    import asyncio as _ao

    async def _probe_all():
        tasks = [_probe_one(p["host"], p["port"]) for p in proxies]
        return await _ao.gather(*tasks)

    console.print("  [dim]probing proxy protocols...[/dim]", end=" ")
    try:
        results = _ao.run(_probe_all())
    except RuntimeError:
        # already inside event loop — use port-based guessing only
        results = [None] * len(proxies)

    updated = []
    changes = 0
    for p, detected in zip(proxies, results):
        new_type = detected or _port_guess(p["port"], p.get("type","socks5"))
        if new_type != p.get("type"):
            changes += 1
        updated.append({**p, "type": new_type})

    if changes:
        console.print(f"[bold #FF0000]fixed {changes} mismatched types[/]")
    else:
        console.print("[dim]ok[/dim]")
    return updated

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LOCAL SOCKS5 FORWARDER  (browser mode core)
#
#  Pure-Python implementation — zero proxychains dependency.
#  The forwarder receives the full proxy list as JSON and implements
#  SOCKS5/SOCKS4/HTTP CONNECT chaining entirely in asyncio.
#  Proxy types are auto-detected before the chain is built.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _start_local_socks5(proxies, cfg, tor_mode):
    """
    Start a pure-Python SOCKS5 server that chains through the proxy list.
    Proxy types are auto-detected before building the chain.
    Firefox → our local SOCKS5 (127.0.0.1:PORT) → proxy1 → proxy2 → ... → target
    """
    import socket as _sock, json

    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]

    # Build chain — auto-detect real protocol for each proxy first.
    # Many free proxy lists label HTTP CONNECT proxies as "socks5".
    if tor_mode:
        chain = [{"host": "127.0.0.1", "port": 9050,
                  "type": "socks5", "user": None, "pwd": None}]
    else:
        detected = detect_proxy_types(proxies)
        chain = [{"host": p["host"], "port": p["port"],
                  "type": p.get("type", "socks5"),
                  "user": p.get("user"), "pwd": p.get("pwd")}
                 for p in detected]

    chain_json = json.dumps(chain)

    # ── ensure pproxy is installed ─────────────────────────────────
    try:
        import pproxy as _pp  # noqa
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pproxy",
                        "--break-system-packages", "-q"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ── build pproxy chain URI: socks5://h1:p1__http://h2:p2__... ──
    def _pproxy_uri(c):
        parts = []
        for p in c:
            pt = (p.get("type") or "socks5").lower()
            if pt in ("socks4","socks4a"):  proto = "socks4"
            elif pt in ("http","https"):    proto = "http"
            else:                           proto = "socks5"
            parts.append(proto + "://" + p["host"] + ":" + str(p["port"]))
        return "__".join(parts)

    chain_uri = _pproxy_uri(chain) if chain else ""

    forwarder_code = (
        "import asyncio, socket, struct, sys, time, threading\n"
        "try:\n"
        "    import pproxy\n"
        "except ImportError:\n"
        "    import subprocess as _sp\n"
        "    _sp.run([sys.executable,'-m','pip','install','pproxy','--break-system-packages','-q'],\n"
        "            stdout=open('/dev/null','w'),stderr=open('/dev/null','w'))\n"
        "    import pproxy\n"
        "\n"
        "CHAIN_URI = " + repr(chain_uri) + "\n"
        "PORT      = " + str(port) + "\n"
        "T         = 20\n"
        "\n"
        "proxy_chain = pproxy.Connection(CHAIN_URI) if CHAIN_URI else None\n"
        "N = [0]; NL = threading.Lock()\n"
        "\n"
        "def log(ok, host, port_, reason=''):\n"
        "    with NL: N[0] += 1; n = N[0]\n"
        "    ts = time.strftime('%H:%M:%S')\n"
        "    st = 'OK ' if ok else 'X  '\n"
        "    msg = '|DRIP| #' + f'{n:04d}' + ' ' + ts + ' ' + st + ' ' + str(host) + ':' + str(port_)\n"
        "    if reason: msg += ' (' + str(reason)[:70] + ')'\n"
        "    sys.stderr.write(msg + '\\n'); sys.stderr.flush()\n"
        "\n"
        "async def relay(src_r, dst_w):\n"
        "    try:\n"
        "        while True:\n"
        "            d = await src_r.read(65536)\n"
        "            if not d: break\n"
        "            dst_w.write(d); await dst_w.drain()\n"
        "    except: pass\n"
        "    finally:\n"
        "        try: dst_w.close()\n"
        "        except: pass\n"
        "\n"
        "async def rx(r, n):\n"
        "    return await asyncio.wait_for(r.readexactly(n), T)\n"
        "\n"
        "async def handle(cr, cw):\n"
        "    dest_host = '?'; dest_port = 0\n"
        "    try:\n"
        "        h = await rx(cr, 2)\n"
        "        if h[0] != 5: return\n"
        "        await rx(cr, h[1])\n"
        "        cw.write(bytes([5, 0])); await cw.drain()\n"
        "        req = await rx(cr, 4)\n"
        "        if req[1] != 1: return\n"
        "        atyp = req[3]\n"
        "        if   atyp == 1: dest_host = socket.inet_ntoa(await rx(cr, 4))\n"
        "        elif atyp == 3:\n"
        "            n_ = (await rx(cr, 1))[0]\n"
        "            dest_host = (await rx(cr, n_)).decode()\n"
        "        elif atyp == 4: dest_host = socket.inet_ntop(socket.AF_INET6, await rx(cr, 16))\n"
        "        else: return\n"
        "        dest_port = struct.unpack('>H', await rx(cr, 2))[0]\n"
        "        hops = len(CHAIN_URI.split('__')) if CHAIN_URI else 1\n"
        "        if proxy_chain:\n"
        "            r, w = await asyncio.wait_for(proxy_chain.tcp_connect(dest_host, dest_port), T * hops)\n"
        "        else:\n"
        "            r, w = await asyncio.wait_for(asyncio.open_connection(dest_host, dest_port), T)\n"
        "        cw.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()\n"
        "        log(True, dest_host, dest_port)\n"
        "        await asyncio.gather(relay(cr, w), relay(r, cw), return_exceptions=True)\n"
        "    except asyncio.TimeoutError:\n"
        "        log(False, dest_host, dest_port, 'timeout')\n"
        "        try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()\n"
        "        except: pass\n"
        "    except Exception as e:\n"
        "        log(False, dest_host, dest_port, str(e)[:70])\n"
        "        try: cw.write(bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); await cw.drain()\n"
        "        except: pass\n"
        "    finally:\n"
        "        try: cw.close()\n"
        "        except: pass\n"
        "\n"
        "async def main():\n"
        "    server = await asyncio.start_server(handle, '127.0.0.1', PORT)\n"
        "    sys.stderr.write('|DRIP_READY|\\n'); sys.stderr.flush()\n"
        "    async with server:\n"
        "        await server.serve_forever()\n"
        "\n"
        "asyncio.run(main())\n"
    )



    fw_path = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="drip_fw_"
    )
    fw_path.write(forwarder_code); fw_path.flush(); fw_path.close()

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    # Run as plain Python — no proxychains, no LD_PRELOAD, no -f flag confusion.
    # The forwarder handles all proxy chaining itself via asyncio.
    proc = subprocess.Popen(
        [sys.executable, "-u", fw_path.name],
        env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        text=True, bufsize=1
    )

    ready_event = threading.Event()
    ready_lines = []

    def _wait_ready():
        for raw in iter(proc.stderr.readline, ""):
            ready_lines.append(raw.strip())
            if "|DRIP_READY|" in raw:
                ready_event.set(); return
            if "Traceback" in raw or "Error" in raw:
                ready_event.set(); return

    threading.Thread(target=_wait_ready, daemon=True).start()
    ready_event.wait(timeout=4.0)

    for _ in range(3):
        try:
            s = _sock.create_connection(("127.0.0.1", port), timeout=1.5)
            s.close()
            return proc, port, ready_lines
        except Exception:
            time.sleep(0.4)

    proc.terminate()
    try: os.unlink(fw_path.name)
    except: pass
    return None, None, []

def warn_leaky_browser(tool_name):
    name = tool_name.lower().split("/")[-1]
    for browser, reason in LEAKY_BROWSERS.items():
        if name == browser or name.startswith(browser):
            msg = (
                "[bold #FF0000]YOUR ANONYMITY WILL BE COMPROMISED[/bold #FF0000]\n\n"
                f"  [bold white]{tool_name}[/bold white] leaks your real identity:\n"
                f"  [dim]{reason}[/dim]\n\n"
                "  [bold #FF0000]USE INSTEAD:[/bold #FF0000]\n"
                "  [bold white]python3 drip.py --browser[/bold white]\n"
                "  [dim](launches Tor Browser — zero leaks guaranteed)[/dim]\n\n"
                f"  [dim]continuing with {tool_name} in 5s... Ctrl+C to cancel[/dim]"
            )
            console.print()
            console.print(Panel(msg,
                title="[bold #FF0000]⚠️  BROWSER LEAK WARNING ⚠️[/bold #FF0000]",
                border_style="#FF0000", padding=(0,2)))
            console.print()
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                console.print("[#FF0000]cancelled.[/]"); sys.exit(0)
            return True
    return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BROWSER-MODE LOG THREAD
#  Reads from fw_proc.stderr (or Firefox's stderr in LD_PRELOAD mode)
#  and pretty-prints every proxychains/DRIP event.
#
#  FIX: extracted to module level so it can be used cleanly with
#       daemon=False and proper join() semantics.
#  FIX: wrapped in try/except so any exception is shown, not swallowed.
#  FIX: handles |DRIP_READY| startup message.
#  FIX: passes through unrecognized lines as dim text so you can always
#       see what's coming out of the process (crucial for LD_PRELOAD mode).
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _browser_log_thread(source_proc, proxies, countries, ok_count, fail_count,
                        pending_lines=None):
    """
    Read source_proc.stderr and pretty-print all connection events.

    source_proc  — the process whose stderr we read (fw_proc or Firefox)
    proxies      — list of proxy dicts (may be empty in Tor mode)
    countries    — geo lookup dict
    ok_count     — shared [int] list for OK count
    fail_count   — shared [int] list for fail count
    pending_lines — lines already read during startup (from |DRIP_READY| wait)
    """
    import re
    conn_lock = threading.Lock()
    conn_n    = [0]
    ip_info   = {p["host"]: countries.get(p["host"], {}) for p in proxies}

    def _fmt_ip(ip):
        ci = ip_info.get(ip, {})
        fl = ci.get("flag", "🌐"); cc = ci.get("code", "??")
        return f"{fl}[bold #00BFFF]{ip}[/bold #00BFFF][dim]({cc})[/dim]"

    def _chain_str(chain_ips, dest_ip, dest_port):
        hops = [_fmt_ip(ip) for ip in chain_ips]
        if dest_ip and dest_ip not in chain_ips:
            hops.append(f"[bold white]{dest_ip}:{dest_port}[/bold white]")
        return " [dim]→[/dim] ".join(hops) if hops else "[dim]chain[/dim]"

    def _process_line(line):
        """Parse one stderr line and print if relevant. Returns True if handled."""
        # ── startup marker ────────────────────────────────────────
        if "|DRIP_READY|" in line:
            console.print("  [bold #FF0000]✅ forwarder ready — connections will appear below[/bold #FF0000]")
            return True

        # ── proxychains chain line ────────────────────────────────
        # In browser mode we suppress |S-chain| lines entirely.
        # Each Firefox connection generates one |S-chain| line PER HOP (3-7
        # lines per request) which floods the output. The |DRIP| lines below
        # already give one clean summary line per connection with the full
        # chain shown — that's all we need.
        if "|S-chain|" in line:
            return True

        # ── DNS events ────────────────────────────────────────────
        if "|DNS-request|" in line:
            host = line.split("|DNS-request|")[-1].strip()
            console.print(f"  [dim]DNS  → {host}[/dim]")
            return True
        if "|DNS-response|" in line:
            info = line.split("|DNS-response|")[-1].strip()
            console.print(f"  [dim]DNS  ← {info}[/dim]")
            return True

        # ── our SOCKS5 forwarder marker ───────────────────────────
        if line.startswith("|DRIP|"):
            parts = line.split()
            if len(parts) < 5:
                return True
            ts    = parts[2]
            st_s  = parts[3]
            dest  = parts[4]
            # Show failure reason (parts[5:]) — e.g. "timeout", "hop2→hop3: conn refused"
            reason = " ".join(parts[5:]).strip("()") if len(parts) > 5 else ""
            ok    = (st_s == "OK")
            if ok: ok_count[0]   += 1
            else:  fail_count[0] += 1
            with conn_lock:
                conn_n[0] += 1; n = conn_n[0]
            st = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]✗  [/]"
            if proxies:
                sample  = proxies[:3]
                cparts  = []
                for p in sample:
                    ci  = ip_info.get(p["host"], {})
                    fl  = ci.get("flag", "🌐")
                    cc  = ci.get("code", "??")
                    cparts.append(
                        f"{fl}[bold #00BFFF]{p['host']}:{p['port']}[/bold #00BFFF]"
                        f"[dim]({cc})[/dim]"
                    )
                if len(proxies) > 3:
                    cparts.append(f"[dim]+{len(proxies)-3} more[/dim]")
                chain_s = " [dim]→[/dim] ".join(cparts)
            else:
                chain_s = "[dim]🧅 Tor[/dim]"
            line_out = (
                f"  [dim]#{n:04d} {ts}[/dim] {st}  "
                f"{chain_s} [dim]→[/dim] [bold white]{dest}[/bold white]"
            )
            if reason and not ok:
                line_out += f" [dim red]{reason}[/dim red]"
            console.print(line_out)
            return True

        # ── proxychains banner (suppress) ─────────────────────────
        if "ProxyChains" in line or "proxychains.sf.net" in line:
            return True

        # FIX: in LD_PRELOAD mode Firefox writes its own debug lines here.
        # Pass them through as dim text so the user can see something.
        # Filter out very noisy Firefox-specific spam lines.
        noisy = (
            "IPDL" in line or "GLib" in line or "dbus" in line or
            "Gtk" in line or "fontconfig" in line or "libGL" in line or
            "javascript" in line.lower() or "MOZ_" in line or
            "console.log" in line or "nss_" in line.lower() or
            len(line) > 300
        )
        if line and not noisy:
            console.print(f"  [dim]{line[:120]}[/dim]")
        return False

    # ── main read loop ────────────────────────────────────────────────
    try:
        # FIX: replay any lines captured during startup (before |DRIP_READY|)
        if pending_lines:
            for line in pending_lines:
                _process_line(line)

        for raw in iter(source_proc.stderr.readline, ""):
            line = raw.strip()
            _process_line(line)

    except Exception as e:
        # FIX: never swallow exceptions silently — show them so user can debug
        console.print(f"  [bold #FF0000]⚠️  log thread error: {e}[/bold #FF0000]")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    if len(sys.argv)<2 or sys.argv[1] in ("-h","--help"):
        print_usage(); sys.exit(0)

    if sys.argv[1] == "--browser":
        _BROWSER_MODE = True
        sys.argv = [sys.argv[0]] + ["firefox"] + sys.argv[2:]
    else:
        _BROWSER_MODE = False

    tool_args=sys.argv[1:]
    cfg=load_config()

    warn_leaky_browser(tool_args[0])

    pc_bin,is_v4=find_proxychains()
    if not pc_bin:
        console.print("[#FF0000]❌ proxychains not found![/]")
        console.print("[dim]  install: sudo apt install proxychains4[/dim]")
        sys.exit(1)

    if sys.stdin.isatty():
        tor_mode=True
        if not ensure_tor():
            console.print("[#FF0000]❌ Tor could not start.[/]")
            console.print("[dim]  sudo apt install tor && sudo systemctl start tor[/dim]")
            sys.exit(1)
        proxies=[]; lats={}; countries={}
    else:
        tor_mode=False
        raw=parse_proxies(sys.stdin.read(),cfg["ptype"])
        if not raw:
            console.print("[#FF0000]❌ no valid proxies[/]"); sys.exit(1)
        proxies,lats=fast_filter(raw,cfg["quick_ms"])
        if not proxies:
            console.print(f"[#FF0000]❌ no proxies passed {cfg['quick_ms']}ms filter[/]")
            sys.exit(1)
        countries={}
        if cfg["country"]:
            console.print("[dim]  looking up countries...[/dim]",end=" ")
            ips=list({p["host"] for p in proxies})
            try: countries=lookup_countries(ips); console.print("[#FF0000]done[/]")
            except: console.print("[dim]skipped[/dim]")

    pc_conf=write_pc_conf(proxies,cfg,tor_mode)

    print_banner(cfg,proxies,tool_args,tor_mode,pc_bin,pc_conf)

    ok,exit_ip=preflight(proxies,cfg,lats,countries,pc_bin,pc_conf,tor_mode,is_v4)
    if not ok: sys.exit(1)

    start=time.perf_counter()
    ok_count=[0]; fail_count=[0]

    console.print(Rule(style="#FF0000"))
    console.print("  [dim]#     time      result   YOUR-IP → PROXY-HOP(s) → DESTINATION[/dim]")
    console.print(Rule(style="#0055FF")); console.print()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  BROWSER MODE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if _BROWSER_MODE:
        ff = _find_firefox()
        if not ff:
            console.print("[#FF0000]❌ Firefox not found[/]")
            console.print("[dim]  install: sudo apt install firefox-esr[/dim]")
            sys.exit(1)

        # 1. Analyze proxy types, show warning, select optimal chain
        proxies_typed, type_counts = analyze_proxy_types(proxies)
        show_proxy_type_warning(type_counts, cfg.get("socks_only", False))
        browser_chain = select_browser_chain(proxies_typed, cfg)
        console.print(
            f"  [bold #FF0000]⛓️  browser chain: {len(browser_chain)} hop(s)[/bold #FF0000]  "
            f"[dim](from {len(proxies)} available — browser_chain_len={cfg['browser_len']})[/dim]"
        )
        console.print()

        # 2. Start SOCKS5 forwarder with the selected chain
        console.print("  [dim]starting SOCKS5 forwarder...[/dim]")
        fw_proc, fw_port, pending_lines = _start_local_socks5(browser_chain, cfg, tor_mode)

        fw_env = os.environ.copy()

        if fw_proc and fw_port:
            console.print(f"  [bold #FF0000]✅ SOCKS5 forwarder → 127.0.0.1:{fw_port}[/bold #FF0000]")
            patched = _patch_all_profiles(socks_port=fw_port)
            if patched:
                console.print(f"  [bold #FF0000]✅ patched {len(patched)} Firefox profile(s)[/bold #FF0000]")
                for p in patched[:2]:
                    console.print(f"     [dim]127.0.0.1:{fw_port} | socks_remote_dns=true | WebRTC=off[/dim]")
            else:
                console.print("  [#FF0000]⚠️  no Firefox profiles found — open Firefox once first[/]")
        else:
            console.print("  [bold #FF0000]❌ SOCKS5 forwarder failed to start[/bold #FF0000]")
            console.print("  [dim]  check: is Python 3.7+ installed? is port available?[/dim]")
            try: os.unlink(pc_conf)
            except: pass
            sys.exit(1)

        console.print()

        log_thread = None
        try:
            # Firefox connects to our local SOCKS5 forwarder (no proxychains needed)
            ff_proc = subprocess.Popen(
                [ff], env=fw_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            log_thread = threading.Thread(
                target=_browser_log_thread,
                args=(fw_proc, browser_chain, countries, ok_count, fail_count,
                      pending_lines),
                daemon=False,
                name="drip-log"
            )
            log_thread.start()

            ff_proc.wait()
            rc = ff_proc.returncode or 0

        except KeyboardInterrupt:
            rc = 0
        finally:
            try: fw_proc.terminate()
            except: pass
            try: os.unlink(pc_conf)
            except: pass

        if log_thread and log_thread.is_alive():
            log_thread.join(timeout=3.0)

        console.print(); console.print(Rule(style="#FF0000"))
        print_footer(
            time.perf_counter()-start, exit_ip,
            ok_count[0], fail_count[0], tor_mode, proxies
        )
        sys.exit(rc)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  REGULAR PROXYCHAINS MODE  (non-browser tools)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    env=os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"]=pc_conf
    env["PROXYCHAINS_QUIET_MODE"]="0"

    if is_v4:
        cmd=[pc_bin,"-f",pc_conf,"-q"]+tool_args
    else:
        cmd=[pc_bin]+tool_args

    try:
        proc=subprocess.Popen(
            cmd, env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, bufsize=1,
            preexec_fn=os.setsid,
        )

        stream_with_live_log(proc,proxies,countries,cfg)
        proc.wait()
        rc=proc.returncode or 0

    except FileNotFoundError:
        console.print(f"[#FF0000]❌ command not found: {tool_args[0]}[/]")
        rc=127
    except KeyboardInterrupt:
        try: os.killpg(os.getpgid(proc.pid),signal.SIGTERM)
        except: pass
        console.print("\n[#FF0000]⚠️  interrupted[/]")
        rc=130
    finally:
        try: os.unlink(pc_conf)
        except: pass

    console.print()
    console.print(Rule(style="#FF0000"))
    print_footer(
        time.perf_counter()-start,
        exit_ip,
        ok_count[0],fail_count[0],
        tor_mode,proxies
    )
    sys.exit(rc)


if __name__=="__main__":
    main()
