#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════╗
║   🔥 PROXY VALIDATOR - GEN Z EDITION 🔥          ║
║   no cap, only valid proxies pass the vibe check ║
╚══════════════════════════════════════════════════╝
Usage: python example.py proxylist.txt
"""

import sys
import os
import time
import threading
import requests
from queue import Queue
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TaskProgressColumn, TimeRemainingColumn, MofNCompleteColumn
)
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.style import Style
from rich import box
from rich.columns import Columns
from rich.padding import Padding

console = Console()

# ── Color palette — RED & BLUE drip only ──────────────────────────
BLOOD_RED  = "bold #FF0000"
DARK_RED   = "bold #CC0000"
DEEP_RED   = "bold #990000"
DRIP_RED   = "#FF3333"
ICE_BLUE   = "bold #00BFFF"
DEEP_BLUE  = "bold #0055FF"
DARK_BLUE  = "bold #003399"
DRIP_BLUE  = "#66CCFF"
WHITE_BOLD = "bold white"
CORAL      = "bold #FF4444"   # kept for error msgs

# ── Proxy test settings ─────────────────────────────────────────────
TEST_URL     = "http://httpbin.org/ip"
TIMEOUT      = 8          # seconds
MAX_WORKERS  = 200        # threads — tweak for your machine
RETRY        = 1


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _drip_line(text: str, drips: list[int], frame: int) -> str:
    """Return rich markup for one banner line with animated drip drops."""
    result = ""
    for i, ch in enumerate(text):
        if ch in " \n":
            result += ch
            continue
        # alternate red/blue column-by-column
        if i % 2 == 0:
            # red side — pulse brightness with frame
            shade = ["#FF0000","#CC0000","#FF0000","#FF3333"][frame % 4]
            result += f"[bold {shade}]{ch}[/]"
        else:
            # blue side
            shade = ["#0055FF","#00BFFF","#0055FF","#3399FF"][frame % 4]
            result += f"[bold {shade}]{ch}[/]"
    return result


def print_banner():
    proxy_rows = [
        "██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗",
        "██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝",
        "██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ",
        "██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ",
        "██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ",
        "╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  ",
    ]
    validator_rows = [
        "██╗   ██╗ █████╗ ██╗     ██╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ ",
        "██║   ██║██╔══██╗██║     ██║██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗",
        "██║   ██║███████║██║     ██║██║  ██║███████║   ██║   ██║   ██║██████╔╝",
        "╚██╗ ██╔╝██╔══██║██║     ██║██║  ██║██╔══██║   ██║   ██║   ██║██╔══██╗",
        " ╚████╔╝ ██║  ██║███████╗██║██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║",
        "  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝",
    ]

    # drip chars that appear below letters
    DRIPS = ["▓", "▒", "░", "╲", "│", "╿", "╽", "╻"]

    # animate the banner dripping in (8 frames)
    for frame in range(8):
        console.clear()
        console.print()

        # PROXY word — red dominant early frames, blue dominant later
        for row_i, row in enumerate(proxy_rows):
            line = ""
            for col_i, ch in enumerate(row):
                if ch in " \n╗╔╝╚║═╟╠╡╞╪╬╫╦╩╤╧╣╢":
                    line += f"[dim]{ch}[/]"
                    continue
                red_weight = max(0, 8 - frame - row_i) / 8
                if red_weight > 0.5:
                    c = "#FF0000" if col_i % 3 != 1 else "#CC0000"
                else:
                    c = "#0055FF" if col_i % 3 != 1 else "#00BFFF"
                line += f"[bold {c}]{ch}[/]"
            console.print(Align.center(line))

        # drip drops between words
        drip_row = ""
        for d in range(0, 44, 3):
            dc = DRIPS[frame % len(DRIPS)]
            drip_row += f"[#FF0000]{dc}[/][#0055FF]{dc}[/] "
        console.print(Align.center(drip_row))
        console.print()

        # VALIDATOR word — blue dominant
        for row_i, row in enumerate(validator_rows):
            line = ""
            for col_i, ch in enumerate(row):
                if ch in " \n╗╔╝╚║═╟╠╡╞╪╬╫╦╩╤╧╣╢":
                    line += f"[dim]{ch}[/]"
                    continue
                if (row_i + col_i + frame) % 2 == 0:
                    c = "#FF0000"
                else:
                    c = "#0055FF"
                line += f"[bold {c}]{ch}[/]"
            console.print(Align.center(line))

        # bottom drips
        bot_drip = ""
        for d in range(0, 70, 2):
            dc = DRIPS[(frame + d) % len(DRIPS)]
            clr = "#FF0000" if d % 4 < 2 else "#0055FF"
            bot_drip += f"[{clr}]{dc}[/]"
        console.print(Align.center(bot_drip))
        console.print(Align.center(
            "[bold #FF0000]🩸 no cap only W proxies pass the drip check 🩸[/]"
        ))
        time.sleep(0.08)

    # final static frame — sharp red/blue split
    console.clear()
    console.print()
    for row in proxy_rows:
        line = ""
        for col_i, ch in enumerate(row):
            if ch == " ":
                line += " "
                continue
            line += f"[bold #FF0000]{ch}[/]" if col_i < len(row)//2 else f"[bold #0055FF]{ch}[/]"
        console.print(Align.center(line))

    console.print(Align.center("[bold #CC0000]▓▒░[/][bold #0055FF]░▒▓[/]" * 8))
    console.print()

    for row in validator_rows:
        line = ""
        for col_i, ch in enumerate(row):
            if ch == " ":
                line += " "
                continue
            line += f"[bold #0055FF]{ch}[/]" if col_i < len(row)//2 else f"[bold #FF0000]{ch}[/]"
        console.print(Align.center(line))

    console.print(Align.center("[bold #0055FF]▓▒░[/][bold #FF0000]░▒▓[/]" * 10))
    console.print()
    console.print(Align.center(
        "[bold #FF0000]🩸 no cap only W proxies pass the drip check 🩸[/]"
    ))
    console.print(Align.center(
        f"[dim]🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  •  "
        f"threads: {MAX_WORKERS}  •  timeout: {TIMEOUT}s[/dim]"
    ))
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PARSE PROXY LINE
#  Supports:
#    ip:port
#    ip:port:user:pass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_proxy(line: str):
    """Return (proxy_url_http, proxy_url_https, original_line) or None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(":")
    try:
        if len(parts) == 2:
            # ip:port
            ip, port = parts[0].strip(), parts[1].strip()
            proxy = f"http://{ip}:{port}"
            return {"http": proxy, "https": proxy}, line

        elif len(parts) == 4:
            # ip:port:user:pass
            ip, port, user, passwd = [p.strip() for p in parts]
            proxy = f"http://{user}:{passwd}@{ip}:{port}"
            return {"http": proxy, "https": proxy}, line

        else:
            return None
    except Exception:
        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TEST A SINGLE PROXY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def test_proxy(proxies_dict: dict, original: str):
    """Return (original_line, success: bool, latency_ms: float | None)."""
    for attempt in range(RETRY + 1):
        try:
            t0 = time.perf_counter()
            r = requests.get(
                TEST_URL,
                proxies=proxies_dict,
                timeout=TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            latency = (time.perf_counter() - t0) * 1000
            if r.status_code == 200:
                return original, True, round(latency, 1)
        except Exception:
            pass
    return original, False, None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  LOAD PROXIES FROM FILE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def load_proxies(filepath: str):
    path = Path(filepath)
    if not path.exists():
        console.print(f"[{CORAL}]💀 File not found: {filepath}[/]")
        sys.exit(1)

    raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    parsed = []
    skipped = 0
    for line in raw_lines:
        result = parse_proxy(line)
        if result:
            parsed.append(result)
        elif line.strip() and not line.startswith("#"):
            skipped += 1

    return parsed, skipped, path.stem   # (list of (proxies_dict, original), skipped, stem)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  STATS TABLE (printed at the end)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def print_results_table(working, dead, skipped, elapsed, out_file):
    total = working + dead
    pct   = (working / total * 100) if total else 0

    table = Table(
        title="[bold #FF0000]🩸 FINAL DRIP CHECK RESULTS 🩸[/]",
        box=box.DOUBLE_EDGE,
        border_style="#0055FF",
        show_header=True,
        header_style="bold #FF0000",
        title_style="bold",
        padding=(0, 2),
    )
    table.add_column("Stat",   style="#00BFFF bold", min_width=22)
    table.add_column("Value",  style="bold white",   min_width=18)
    table.add_column("Vibe",   style="bold",          min_width=14)

    table.add_row("✅  Working Proxies",  str(working),        f"[#FF0000]{pct:.1f}% W ratio[/]")
    table.add_row("❌  Dead Proxies",     str(dead),           f"[#0055FF]rip fr fr[/]")
    table.add_row("⚠️   Skipped Lines",   str(skipped),        f"[#FF0000]bad format[/]")
    table.add_row("📦  Total Tested",     str(total),          f"[#0055FF]all of them bestie[/]")
    table.add_row("⏱️   Time Elapsed",    f"{elapsed:.1f}s",   f"[#FF0000]{total/elapsed:.0f} p/s[/]" if elapsed > 0 else "")
    table.add_row("💾  Saved To",         out_file,            f"[#00BFFF]snatched 🩸[/]")

    console.print()
    console.print(Align.center(table))
    console.print()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    if len(sys.argv) < 2:
        console.print(Panel(
            "[bold #FF0000]Usage:[/]  [bold white]python example.py proxylist.txt[/]\n\n"
            "[dim]Supports formats:\n"
            "  • ip:port\n"
            "  • ip:port:username:password[/dim]",
            title="[bold #0055FF]🩸 PROXY VALIDATOR - HOW TO USE 🩸[/]",
            border_style="#FF0000",
            padding=(1, 4),
        ))
        sys.exit(0)

    filepath = sys.argv[1]
    print_banner()

    # ── Load ────────────────────────────────────────────────────────
    console.print(f"[bold #00BFFF]📂  Loading proxy list from:[/] [bold white]{filepath}[/]")
    proxies_list, skipped, filestem = load_proxies(filepath)
    total = len(proxies_list)

    if total == 0:
        console.print(f"[bold #FF0000]💀 No valid proxies found in file![/]")
        sys.exit(1)

    out_filename = f"successful_{filestem}.txt"

    # ── Info panel ──────────────────────────────────────────────────
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column(style="#00BFFF bold")
    info_table.add_column(style="bold white")
    info_table.add_row("🔢  Total proxies",   str(total))
    info_table.add_row("⚠️   Skipped lines",  str(skipped))
    info_table.add_row("🔥  Threads",         str(MAX_WORKERS))
    info_table.add_row("⏱️   Timeout",         f"{TIMEOUT}s each")
    info_table.add_row("💾  Output file",     out_filename)
    info_table.add_row("🌐  Test URL",        TEST_URL)

    console.print(Panel(
        info_table,
        title="[bold #FF0000]📋 MISSION BRIEFING 📋[/]",
        border_style="#0055FF",
        padding=(0, 2),
    ))
    console.print()

    # ── Validate ────────────────────────────────────────────────────
    working_lock    = threading.Lock()
    working_proxies = []
    dead_count      = [0]
    live_count      = [0]
    tested_count    = [0]
    MAX_LIVE_SHOW   = 60   # how many live proxies to show in the live panel

    start_time = time.perf_counter()

    from rich.console import Group as RichGroup

    progress = Progress(
        SpinnerColumn(spinner_name="dots12", style="#FF0000"),
        TextColumn("[bold #00BFFF]{task.description}[/]"),
        BarColumn(
            bar_width=38,
            style="#0055FF",
            complete_style="#FF0000",
            finished_style="#FF0000",
        ),
        MofNCompleteColumn(),
        TaskProgressColumn(style="#00BFFF bold"),
        TextColumn("[dim]•[/dim]"),
        TimeRemainingColumn(),
        TextColumn("[bold #FF0000]✅ {task.fields[hits]}[/] [bold #0055FF]❌ {task.fields[miss]}[/]"),
    )

    task = progress.add_task(
        "dripping thru proxies...",
        total=total,
        hits=0,
        miss=0,
    )

    def make_live_panel():
        """Build the live working-proxies panel."""
        with working_lock:
            snap = list(working_proxies[-MAX_LIVE_SHOW:])
            hits = live_count[0]
            miss = dead_count[0]
            done = tested_count[0]

        t = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold #FF0000",
            border_style="#0055FF",
            padding=(0, 1),
            expand=True,
        )
        t.add_column("#",           style="dim",          width=5)
        t.add_column("LIVE PROXY",  style="bold #00BFFF", min_width=38)
        t.add_column("LATENCY",     style="bold",          width=12, justify="right")
        t.add_column("STATUS",      width=14)

        for i, (proxy, latency) in enumerate(reversed(snap), 1):
            if latency < 500:
                lat_s  = f"[bold #FF0000]{latency} ms[/]"
                stat_s = "[bold #FF0000]⚡ FAST[/]"
            elif latency < 1500:
                lat_s  = f"[bold #0055FF]{latency} ms[/]"
                stat_s = "[bold #0055FF]🔥 OK[/]"
            else:
                lat_s  = f"[bold #003399]{latency} ms[/]"
                stat_s = "[bold #003399]🐢 SLOW[/]"
            t.add_row(str(hits - i + 1), proxy, lat_s, stat_s)

        elapsed_now = time.perf_counter() - start_time
        speed = done / elapsed_now if elapsed_now > 0 else 0

        header = (
            f"[bold #FF0000]🩸 LIVE HITS: {hits}[/]  "
            f"[bold #0055FF]💀 DEAD: {miss}[/]  "
            f"[dim]tested: {done}/{total}  speed: {speed:.0f}/s[/dim]"
        )

        return Panel(t, title=header, border_style="#FF0000", padding=(0, 1))

    def make_display():
        return RichGroup(progress, make_live_panel())

    with Live(
        make_display(),
        console=console,
        refresh_per_second=8,
        vertical_overflow="visible",
    ) as live:
        with open(out_filename, "w") as out_f:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(test_proxy, pd, orig): orig
                    for pd, orig in proxies_list
                }
                for future in as_completed(futures):
                    original, success, latency = future.result()
                    with working_lock:
                        tested_count[0] += 1
                        if success:
                            working_proxies.append((original, latency))
                            live_count[0] += 1
                            out_f.write(original + "\n")
                            out_f.flush()
                        else:
                            dead_count[0] += 1

                    progress.update(
                        task,
                        advance=1,
                        hits=live_count[0],
                        miss=dead_count[0],
                    )
                    live.update(make_display())

    elapsed = time.perf_counter() - start_time

    # ── Live proxies sample table ───────────────────────────────────
    if working_proxies:
        console.print(Rule(style="#FF0000"))
        sample_table = Table(
            title=f"[bold #FF0000]🩸 LIVE PROXIES SAMPLE (top {min(20, len(working_proxies))} hits)[/]",
            box=box.ROUNDED,
            border_style="#FF0000",
            header_style="bold #00BFFF",
            show_lines=True,
            padding=(0, 1),
        )
        sample_table.add_column("#",       style="dim",           width=4)
        sample_table.add_column("Proxy",   style="bold #00BFFF",  min_width=34)
        sample_table.add_column("Latency", style="bold #FF0000",  width=12, justify="right")
        sample_table.add_column("Status",  width=16)

        for i, (proxy, latency) in enumerate(working_proxies[:20], 1):
            if latency < 500:
                lat_str  = f"[bold #FF0000]{latency} ms[/]"
                status   = "[bold #FF0000]⚡ blazing[/]"
            elif latency < 1500:
                lat_str  = f"[bold #0055FF]{latency} ms[/]"
                status   = "[bold #0055FF]🔥 decent[/]"
            else:
                lat_str  = f"[bold #003399]{latency} ms[/]"
                status   = "[bold #003399]🐢 slow[/]"
            sample_table.add_row(str(i), proxy, lat_str, status)

        console.print(Align.center(sample_table))

    # ── Final stats ─────────────────────────────────────────────────
    print_results_table(
        live_count[0], dead_count[0], skipped, elapsed, out_filename
    )

    # ── Outro ───────────────────────────────────────────────────────
    if live_count[0] > 0:
        console.print(Align.center(Panel(
            f"[bold #FF0000]fr fr that's a W bestie 🩸\n"
            f"[bold white]{live_count[0]}[/] drip proxies saved to "
            f"[bold #00BFFF]{out_filename}[/][/]",
            border_style="#FF0000",
            padding=(1, 6),
        )))
    else:
        console.print(Align.center(Panel(
            "[bold #0055FF]💀 no proxies survived the drip check rip 💀\n"
            "[dim]try a different list or increase timeout[/dim]",
            border_style="#0055FF",
            padding=(1, 6),
        )))
    console.print()


if __name__ == "__main__":
    main()

