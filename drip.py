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
strict_chain:   F   # all proxies in order, fail if any dead
dynamic_chain:  T   # skip dead proxies automatically  ← default
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
        "strict":   b("strict_chain"),
        "dynamic":  b("dynamic_chain",True),
        "random":   b("random_chain"),
        "chain_len":max(1,int(cfg.get("chain_len",3))),
        "timeout":  max(1.0,float(cfg.get("timeout",8))),
        "quick_ms": max(50,int(cfg.get("quick_timeout",3000))),
        "ptype":    str(cfg.get("proxy_type","socks5")).lower().strip(),
        "proxy_dns":b("proxy_dns",True),
        "tcp_read": int(cfg.get("tcp_read_time",15000)),
        "tcp_conn": int(cfg.get("tcp_conn_time",8000)),
        "country":  b("country_lookup",True),
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
#  LIVE OUTPUT PARSER
#  proxychains v3 output format:
#    |DNS-request| google.com
#    |DNS-response| google.com --> 142.250.117.102
#    |S-chain|-<>-HOP1:PORT-<><>-HOP2:PORT-<><>-DEST:PORT-<><>-OK
#    |S-chain|-<>-HOP1:PORT-<><>-DEST:PORT-<><>-timeout
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
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ── browser config ──────────────────────────────────────────────────
# Tor Browser is the only recommended browser for anonymous browsing
TOR_BROWSER_CMDS = [
    "torbrowser-launcher",
    "tor-browser",
    "tor-browser-en",
    "/usr/bin/torbrowser-launcher",
    "/opt/tor-browser/Browser/start-tor-browser",
]

# Browsers that WILL leak DNS/WebRTC — warn user
LEAKY_BROWSERS = {
    # firefox handled by --browser flag with auto-config
    # firefox-esr handled by --browser flag with auto-config
    "chromium": "DNS and WebRTC leak — cannot be fully fixed with proxychains",
    "chrome":   "DNS and WebRTC leak — cannot be fully fixed with proxychains",
    "google-chrome": "DNS and WebRTC leak — cannot be fully fixed",
    "brave":    "DNS leak — has own DNS resolver that bypasses proxychains",
    "opera":    "DNS and WebRTC leak",
    "vivaldi":  "DNS leak",
    "microsoft-edge": "DNS and WebRTC leak",
}

# direct Tor Browser binary paths (skip the launcher, run browser directly)
TOR_BROWSER_DIRECT = [
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
    os.path.expanduser("~/.local/share/torbrowser/tbb/x86_64/tor-browser/start-tor-browser"),
    "/opt/tor-browser/Browser/start-tor-browser",
    "/usr/bin/tor-browser",
]

def _make_tor_wrapper(browser_dir):
    """
    Write wrapper that launches Tor Browser and BLOCKS until it closes.
    Uses wait on firefox PID directly so proxychains v3 sees a blocking process.
    """
    firefox   = os.path.join(browser_dir, "Browser", "firefox")
    profile   = os.path.join(browser_dir, "Browser", "TorBrowser", "Data", "Browser", "profile.default")
    tb_script = os.path.join(browser_dir, "start-tor-browser")

    wrapper = Path("/tmp/drip_torbrowser.sh")

    # browser_dir is already .../tor-browser/Browser/
    # so firefox is directly at browser_dir/firefox
    firefox_direct   = os.path.join(browser_dir, "firefox")
    profile_direct   = os.path.join(browser_dir, "TorBrowser", "Data", "Browser", "profile.default")

    if os.path.exists(firefox_direct):
        # run firefox directly — 100% blocks until user closes window
        wrapper.write_text(
            "#!/bin/bash\n"
            f"cd \"{browser_dir}\"\n"
            f"exec ./firefox --profile \"{profile_direct}\" --no-remote 2>/dev/null\n"
        )
    elif os.path.exists(tb_script):
        # start-tor-browser ignores --no-detach on some versions
        # launch it then find and wait on the actual firefox process
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

def _make_tb_launcher(browser_dir):
    """
    Write a tiny shell script to launch Tor Browser from its own directory.
    proxychains v3 can't handle 'bash -c cd ... && ...' with spaces/args.
    """
    script = f"""#!/bin/bash
cd "{browser_dir}"
exec ./start-tor-browser "$@"
"""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, prefix="drip_tb_"
    )
    tmp.write(script); tmp.flush(); tmp.close()
    os.chmod(tmp.name, 0o755)
    return [tmp.name]

def find_tor_browser():
    """Find Tor Browser — prefer direct binary over launcher."""
    # first try direct binary (no --detach, stays alive)
    for path in TOR_BROWSER_DIRECT:
        if os.path.exists(path):
            return path, True   # (path, is_direct)
    # fallback to launcher
    for cmd in TOR_BROWSER_CMDS:
        r = subprocess.run(["which", cmd], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip(), False
        if os.path.exists(cmd):
            return cmd, False
    return None, False

def launch_tor_browser_setup():
    """Install torbrowser-launcher if not present."""
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
    """Find Firefox binary."""
    for name in ["firefox-esr","firefox"]:
        r = subprocess.run(["which", name], capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None

def _get_all_firefox_profiles():
    """Return ALL Firefox profile directories found on this system."""
    import glob, configparser
    profiles = []

    # check multiple possible base dirs
    bases = [
        os.path.expanduser("~/.mozilla/firefox"),
        os.path.expanduser("~/.firefox"),
        "/root/.mozilla/firefox",
    ]

    for base in bases:
        if not os.path.exists(base):
            continue
        ini = os.path.join(base, "profiles.ini")
        if os.path.exists(ini):
            cfg = configparser.ConfigParser()
            cfg.read(ini)
            for section in cfg.sections():
                path = cfg.get(section, "Path", fallback=None)
                if not path:
                    continue
                if cfg.get(section, "IsRelative", fallback="0") == "1":
                    full = os.path.join(base, path)
                else:
                    full = path
                if os.path.isdir(full) and full not in profiles:
                    profiles.append(full)
        # also glob for any profile folders directly
        for pattern in ["*.default-esr","*.default","*.default-release","*.esr"]:
            for p in glob.glob(os.path.join(base, pattern)):
                if p not in profiles:
                    profiles.append(p)

    return profiles

def _find_firefox_profile():
    """Find default Firefox profile directory."""
    profiles = _get_all_firefox_profiles()
    return profiles[0] if profiles else None

def _patch_firefox_profile(profile_dir, socks_port=None):
    """
    Write privacy + proxy settings into Firefox profile.
    KEY: set network.proxy.type=1 + socks host/port so Firefox
    KNOWS it has a proxy — then socks_remote_dns actually works.
    """
    port = socks_port or 9150  # fallback to Tor
    user_js_content = (
        "// drip.py — proxy + DNS leak fix (auto-generated)\n"
        # ── EXPLICIT PROXY CONFIG — this is the key fix ──────────────
        # type 1 = manual proxy — Firefox now KNOWS about the proxy
        'user_pref("network.proxy.type", 1);\n'
        f'user_pref("network.proxy.socks", "127.0.0.1");\n'
        f'user_pref("network.proxy.socks_port", {port});\n'
        'user_pref("network.proxy.socks_version", 5);\n'
        # ── DNS through proxy — now actually works ───────────────────
        'user_pref("network.proxy.socks_remote_dns", true);\n'
        # ── kill ALL other DNS paths ─────────────────────────────────
        'user_pref("network.trr.mode", 5);\n'
        'user_pref("network.trr.uri", "");\n'
        'user_pref("network.trr.bootstrapAddr", "");\n'
        'user_pref("network.dns.disablePrefetch", true);\n'
        'user_pref("network.dns.disablePrefetchFromHTTPS", true);\n'
        'user_pref("network.predictor.enabled", false);\n'
        'user_pref("network.prefetch-next", false);\n'
        # ── kill WebRTC ──────────────────────────────────────────────
        'user_pref("media.peerconnection.enabled", false);\n'
        'user_pref("media.peerconnection.ice.default_address_only", true);\n'
        # ── no direct connections ────────────────────────────────────
        'user_pref("network.proxy.no_proxies_on", "");\n'
    )
    import re
    user_js = os.path.join(profile_dir, "user.js")
    Path(user_js).write_text(user_js_content)

    # patch prefs.js too
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
    """Patch ALL Firefox profiles found — ensures no profile is missed."""
    profiles = _get_all_firefox_profiles()
    if not profiles:
        return []
    patched = []
    for p in profiles:
        try:
            _patch_firefox_profile(p, socks_port)
            patched.append(p)
        except Exception as e:
            pass
    return patched

def _start_local_socks5(pc_bin, pc_conf, is_v4):
    """
    Start a local SOCKS5 server on a free port that chains through proxychains.
    Firefox connects to this port — so it KNOWS it has a proxy.
    Uses ssh -D trick: proxychains ssh -D port localhost (if ssh available).
    Fallback: Python asyncio SOCKS5 forwarder.
    """
    import socket as _sock
    # find free port
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]

    # try: proxychains dante/microsocks/3proxy
    # simplest: use Python to run a SOCKS5 forwarder through proxychains
    forwarder = f"""
import asyncio, socket, struct, sys, os, time, threading

N = [0]
L = threading.Lock()

def log(ok, host, port):
    with L:
        N[0] += 1; n = N[0]
    ts = time.strftime("%H:%M:%S")
    st = "OK " if ok else "✗  "
    # write to stderr so parent process can read it
    sys.stderr.write(f"|DRIP| #{{n:04d}} {{ts}} {{st}} {{host}}:{{port}}\n")
    sys.stderr.flush()

async def relay(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d: break
            w.write(d); await w.drain()
    except: pass
    finally:
        try: w.close()
        except: pass

async def handle(cr, cw):
    t = 10
    host = "?"; port = 0
    try:
        h = await asyncio.wait_for(cr.read(2), t)
        if h[0] != 5: return
        await asyncio.wait_for(cr.read(h[1]), t)
        cw.write(b"\x05\x00"); await cw.drain()
        req = await asyncio.wait_for(cr.read(4), t)
        if req[1] != 1: return
        at = req[3]
        if at == 1:
            raw = await asyncio.wait_for(cr.read(4), t)
            host = socket.inet_ntoa(raw)
        elif at == 3:
            l = (await asyncio.wait_for(cr.read(1), t))[0]
            host = (await asyncio.wait_for(cr.read(l), t)).decode()
        elif at == 4:
            raw = await asyncio.wait_for(cr.read(16), t)
            host = socket.inet_ntop(socket.AF_INET6, raw)
        port = struct.unpack(">H", await asyncio.wait_for(cr.read(2), t))[0]
        try:
            pr, pw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=t)
            cw.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"); await cw.drain()
            log(True, host, port)
            await asyncio.gather(relay(cr,pw), relay(pr,cw), return_exceptions=True)
        except:
            cw.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); await cw.drain()
            log(False, host, port)
    except: pass
    finally:
        try: cw.close()
        except: pass

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", {port})
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""
    fw_path = "/tmp/drip_socks5fw.py"
    Path(fw_path).write_text(forwarder)

    env = os.environ.copy()
    env["PROXYCHAINS_CONF_FILE"] = pc_conf

    if is_v4:
        cmd = [pc_bin, "-f", pc_conf, "-q", sys.executable, fw_path]
    else:
        cmd = [pc_bin, sys.executable, fw_path]

    proc = subprocess.Popen(cmd, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    time.sleep(1.5)   # let it start
    # verify it's listening
    try:
        s = _sock.create_connection(("127.0.0.1", port), timeout=2); s.close()
        return proc, port
    except Exception:
        proc.terminate()
        return None, None

def launch_firefox_setup():
    """Find Firefox, patch its profile, return launch args."""
    ff = _find_firefox()
    if not ff:
        console.print("[#FF0000]❌ Firefox not found![/]")
        console.print("[dim]  install: sudo apt install firefox-esr[/dim]")
        return None

    console.print(f"[dim]  found: {ff}[/dim]")

    # patch ALL profiles — ensures no profile is missed
    patched = _patch_all_profiles()
    if patched:
        console.print(f"[bold #FF0000]  ✅ patched {len(patched)} profile(s):[/bold #FF0000]")
        for p in patched:
            console.print(f"[dim]     {p}[/dim]")
        console.print(f"[dim]     → network.proxy.socks_remote_dns = true[/dim]")
        console.print(f"[dim]     → network.trr.mode = 5  (DoH off)[/dim]")
        console.print(f"[dim]     → WebRTC disabled[/dim]")
        console.print(f"[dim]     → DNS prefetch disabled[/dim]")
    else:
        console.print("[#FF0000]  ⚠️  no Firefox profiles found[/]")
        console.print("[dim]     open Firefox once, close it, then rerun --browser[/dim]")

    return [ff]

def warn_leaky_browser(tool_name):
    """Show warning if user tries to use a leaky browser."""
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

def main():
    if len(sys.argv)<2 or sys.argv[1] in ("-h","--help"):
        print_usage(); sys.exit(0)

    # ── --browser flag: launch Firefox with privacy settings auto-configured
    if sys.argv[1] == "--browser":
        # will be handled after proxychains config is written
        # mark it so we handle it in the run section
        _BROWSER_MODE = True
        sys.argv = [sys.argv[0]] + ["firefox"] + sys.argv[2:]
    else:
        _BROWSER_MODE = False

    tool_args=sys.argv[1:]
    cfg=load_config()

    # ── browser leak warning ─────────────────────────────────────────
    warn_leaky_browser(tool_args[0])

    # ── find proxychains ─────────────────────────────────────────────
    pc_bin,is_v4=find_proxychains()
    if not pc_bin:
        console.print("[#FF0000]❌ proxychains not found![/]")
        console.print("[dim]  install: sudo apt install proxychains4[/dim]")
        sys.exit(1)

    # ── proxy vs tor mode ────────────────────────────────────────────
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

    # ── write proxychains config ─────────────────────────────────────
    pc_conf=write_pc_conf(proxies,cfg,tor_mode)

    print_banner(cfg,proxies,tool_args,tor_mode,pc_bin,pc_conf)

    # ── preflight ────────────────────────────────────────────────────
    ok,exit_ip=preflight(proxies,cfg,lats,countries,pc_bin,pc_conf,tor_mode,is_v4)
    if not ok: sys.exit(1)

    start=time.perf_counter()
    ok_count=[0]; fail_count=[0]

    # ── live connection header ───────────────────────────────────────
    console.print(Rule(style="#FF0000"))
    console.print("  [dim]#     time      result   YOUR-IP → PROXY-HOP(s) → DESTINATION[/dim]")
    console.print(Rule(style="#0055FF")); console.print()

    # ── BROWSER MODE: start local SOCKS5 → tell Firefox → launch ────
    if _BROWSER_MODE:
        ff = _find_firefox()
        if not ff:
            console.print("[#FF0000]❌ Firefox not found[/]")
            sys.exit(1)

        # 1. start local SOCKS5 server that chains through proxychains
        fw_proc, fw_port = _start_local_socks5(pc_bin, pc_conf, is_v4)
        if fw_proc and fw_port:
            console.print(f"  [bold #FF0000]✅ local SOCKS5 forwarder on 127.0.0.1:{fw_port}[/]")
        else:
            # forwarder failed — patch without proxy type, launch via LD_PRELOAD
            fw_proc = None; fw_port = None
            console.print("  [dim]⚠️  forwarder failed — using LD_PRELOAD mode[/dim]")
            for prof in _get_all_firefox_profiles():
                try:
                    Path(os.path.join(prof,"user.js")).write_text(
                        "// drip.py dns patch\n"
                        'user_pref("network.trr.mode", 5);\n'
                        'user_pref("network.dns.disablePrefetch", true);\n'
                        'user_pref("media.peerconnection.enabled", false);\n'
                        'user_pref("network.proxy.type", 0);\n'
                    )
                except: pass

        if fw_port:
            # 2a. patch profiles to use our local SOCKS5 forwarder
            patched = _patch_all_profiles(socks_port=fw_port)
            console.print(f"  [bold #FF0000]✅ patched {len(patched)} Firefox profile(s)[/]")
            for p in patched:
                console.print(f"     [dim]proxy: 127.0.0.1:{fw_port} | socks_remote_dns: true | WebRTC: off[/dim]")
                break
        # 3. launch Firefox directly (no proxychains needed — uses our SOCKS5)
        # stream logs from the forwarder in background
        def _stream_fw_logs(fw_proc, proxies, countries):
            import re
            conn_lock = threading.Lock()
            ip_info = {p["host"]: countries.get(p["host"], {}) for p in proxies}
            n = [0]
            for raw in iter(fw_proc.stderr.readline, ""):
                raw = raw.strip()
                if not raw.startswith("|DRIP|"): continue
                # |DRIP| #0001 15:03:14 OK  host:port
                parts = raw.split()
                if len(parts) < 5: continue
                num = parts[1]; ts = parts[2]; st = parts[3]
                dest = parts[4] if len(parts)>4 else "?"
                ok = (st == "OK")
                status = "[bold #FF0000]OK [/]" if ok else "[bold #0055FF]✗  [/]"
                # show which proxies are in use
                if proxies:
                    sample = proxies[:2]
                    chain_parts = []
                    for p in sample:
                        ci = ip_info.get(p["host"],{}); fl=ci.get("flag","🌐"); cc=ci.get("code","??")
                        chain_parts.append(f"{fl}[bold #00BFFF]{p['host']}:{p['port']}[/][dim]({cc})[/dim]")
                    if len(proxies)>2: chain_parts.append(f"[dim]+{len(proxies)-2}[/dim]")
                    chain_s = " [dim]→[/dim] ".join(chain_parts)
                else:
                    chain_s = "[dim]chain[/dim]"
                console.print(
                    f"  [dim]{num} {ts}[/dim] {status}  "
                    f"{chain_s} [dim]→[/dim] [bold white]{dest}[/bold white]"
                )

        # find proxychains LD_PRELOAD lib for fallback mode
        pc_lib = None
        for lib in ["/usr/lib/x86_64-linux-gnu/libproxychains.so.3",
                    "/usr/lib/x86_64-linux-gnu/libproxychains.so.4",
                    "/usr/lib/libproxychains.so.3",
                    "/usr/lib/libproxychains.so.4"]:
            if os.path.exists(lib): pc_lib = lib; break

        ff_env = os.environ.copy()
        if not fw_proc and pc_lib:
            # no forwarder — inject proxychains into firefox directly
            ff_env["LD_PRELOAD"] = pc_lib
            ff_env["PROXYCHAINS_CONF_FILE"] = pc_conf
            console.print(f"  [dim]LD_PRELOAD: {pc_lib}[/dim]")

        try:
            proc = subprocess.Popen(
                [ff], env=ff_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            # stream forwarder logs while browser runs
            if fw_proc:
                log_thread = threading.Thread(
                    target=_stream_fw_logs,
                    args=(fw_proc, proxies, countries),
                    daemon=True
                )
                log_thread.start()
            proc.wait()
            rc = proc.returncode or 0
        except KeyboardInterrupt:
            rc = 0
        finally:
            if fw_proc:
                try: fw_proc.terminate()
                except: pass
            try: os.unlink(pc_conf)
            except: pass

        console.print(); console.print(Rule(style="#FF0000"))
        print_footer(time.perf_counter()-start, exit_ip, ok_count[0], fail_count[0], tor_mode, proxies)
        sys.exit(rc)

    # ── run proxychains ──────────────────────────────────────────────
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
        # clean up temp config
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
