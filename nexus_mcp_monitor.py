#!/usr/bin/env python3
"""
nexus_mcp_monitor.py — NeXuS system monitoring MCP server
Exposes: services (OpenRC), logs, network, security events, system metrics
Register: claude mcp add nexus-monitor -- ~/.venv/nexus-mcp/bin/python ~/NeXuS/projects/nexus-mcp-monitor/nexus_mcp_monitor.py
"""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Literal

from mcp.server.mcpserver import MCPServer

app = MCPServer("nexus-monitor")

LOG_DIR = Path(os.environ.get("NEXUS_LOG_DIR", "/var/log"))

NEXUS_SERVICES = [
    "tor", "i2p", "privoxy", "wireguard", "fail2ban", "psad",
    "networkmanager", "sshd", "dbus", "syslog", "apparmor",
    "chrony", "unbound", "dnscrypt-proxy",
]


def _run(cmd: list[str], timeout: int = 5) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip(), r.returncode
    except subprocess.TimeoutExpired:
        return f"[timeout after {timeout}s]", 1
    except Exception as e:
        return f"[error: {e}]", 1


def _tail(path: str, lines: int) -> str:
    out, _ = _run(["tail", "-n", str(lines), path])
    return out


def _grep(path: str, pattern: str, limit: int) -> str:
    out, _ = _run(["grep", "-i", "-m", str(limit), pattern, path])
    return out or f"[no matches for '{pattern}' in {path}]"


def _resolve(path: str) -> Path:
    p = Path(path)
    return p if p.is_absolute() else LOG_DIR / path


# ── tools ──────────────────────────────────────────────────────────────────────

@app.tool()
def service_status(service: str = "") -> str:
    """Check OpenRC service status. Pass a service name for one service, or leave blank for all NeXuS services."""
    if service:
        out, code = _run(["rc-service", service, "status"])
        return f"[{service}] {'started' if code == 0 else 'stopped/error'}\n{out}"

    lines = []
    for svc in NEXUS_SERVICES:
        out, code = _run(["rc-service", svc, "status"], timeout=3)
        status = "✓ started" if code == 0 else "✗ stopped"
        uptime = ""
        m = re.search(r'\((\d+ (?:day|hour|minute|second)[^)]*)\)', out)
        if m:
            uptime = f"  [{m.group(1)}]"
        lines.append(f"  {status:<14} {svc}{uptime}")
    return "NeXuS Services:\n" + "\n".join(lines)


@app.tool()
def system_metrics() -> str:
    """CPU load averages, RAM usage, swap, disk, and uptime."""
    load_out, _ = _run(["cat", "/proc/loadavg"])
    parts = load_out.split()
    load = f"{parts[0]} {parts[1]} {parts[2]}" if len(parts) >= 3 else load_out

    meminfo = Path("/proc/meminfo").read_text()
    mem: dict[str, int] = {}
    for line in meminfo.splitlines():
        k, _, v = line.partition(":")
        mem[k.strip()] = int(v.strip().split()[0]) if v.strip() else 0

    total_mb = mem.get("MemTotal", 0) // 1024
    avail_mb = mem.get("MemAvailable", 0) // 1024
    used_mb  = total_mb - avail_mb
    swap_tot = mem.get("SwapTotal", 0) // 1024
    swap_use = swap_tot - mem.get("SwapFree", 0) // 1024

    df_out, _ = _run(["df", "-h", "/", "/home"])
    uptime_out, _ = _run(["uptime", "-p"])

    return (
        f"System Metrics — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Uptime   : {uptime_out}\n"
        f"  Load avg : {load} (1m 5m 15m)\n"
        f"  RAM      : {used_mb}MB used / {total_mb}MB total  ({avail_mb}MB free)\n"
        f"  Swap     : {swap_use}MB used / {swap_tot}MB total\n"
        f"\nDisk:\n{df_out}"
    )


@app.tool()
def network_interfaces() -> str:
    """Live rx/tx bytes, packets, and drops per network interface from /proc/net/dev."""
    lines = [f"Network Interfaces — {datetime.now().strftime('%H:%M:%S')}:"]
    dev_lines = Path("/proc/net/dev").read_text().splitlines()
    for line in dev_lines[2:]:
        fields = line.split()
        if not fields:
            continue
        iface = fields[0].rstrip(":")
        rx_bytes, rx_pkts, rx_drop = fields[1], fields[2], fields[4]
        tx_bytes, tx_pkts, tx_drop = fields[9], fields[10], fields[12]

        def fmt(b: str) -> str:
            n = int(b)
            if n > 1_000_000_000: return f"{n/1e9:.1f}GB"
            if n > 1_000_000:     return f"{n/1e6:.1f}MB"
            if n > 1_000:         return f"{n/1e3:.1f}KB"
            return f"{n}B"

        warn = f"  ⚠ drops rx={rx_drop} tx={tx_drop}" if int(rx_drop)+int(tx_drop) > 0 else ""
        lines.append(
            f"  {iface:<8}  rx={fmt(rx_bytes):>10} ({rx_pkts} pkts)  "
            f"tx={fmt(tx_bytes):>10} ({tx_pkts} pkts){warn}"
        )
    return "\n".join(lines)


@app.tool()
def list_logs(filter: str = "") -> str:
    """List available log files under /var/log. Optionally filter by substring."""
    results = []
    for f in sorted(LOG_DIR.rglob("*")):
        if not f.is_file():
            continue
        name = str(f.relative_to(LOG_DIR))
        if filter and filter.lower() not in name.lower():
            continue
        size = f.stat().st_size
        sz = f"{size//1024}KB" if size > 1024 else f"{size}B"
        results.append(f"  {name:<42} {sz:>8}")
    return f"Logs in {LOG_DIR}:\n" + "\n".join(results[:120])


@app.tool()
def read_log(path: str, lines: int = 50) -> str:
    """Tail the last N lines of a log file. Path can be absolute or relative to /var/log."""
    resolved = _resolve(path)
    if not resolved.exists():
        return f"[not found: {resolved}]"
    content = _tail(str(resolved), min(lines, 500))
    return f"[{resolved} — last {lines} lines]\n{content}"


@app.tool()
def search_log(path: str, pattern: str, limit: int = 100) -> str:
    """Grep a log file for a pattern (case-insensitive). Path can be absolute or relative to /var/log."""
    resolved = _resolve(path)
    if not resolved.exists():
        return f"[not found: {resolved}]"
    return f"[grep '{pattern}' in {resolved}]\n{_grep(str(resolved), pattern, limit)}"


@app.tool()
def security_events(
    source: Literal["all", "fail2ban", "psad", "auth", "messages"] = "all",
    limit: int = 30,
) -> str:
    """Pull recent security events from fail2ban, psad, auth.log, and messages."""
    source_map = {
        "fail2ban": ("fail2ban", "fail2ban.log"),
        "psad":     ("psad",     "messages"),
        "auth":     ("auth",     "auth.log"),
        "messages": ("messages", "messages"),
    }
    targets = source_map.items() if source == "all" else [(source, source_map.get(source, (source, source))[1])]

    parts = []
    for src_name, logfile in (targets if source == "all" else [(source, source_map[source][1])]):
        p = LOG_DIR / logfile
        if not p.exists():
            parts.append(f"[{src_name}] not found: {p}")
            continue
        if src_name == "psad":
            content = _grep(str(p), "psad", limit)
        else:
            content = _tail(str(p), limit)
        parts.append(f"── {src_name.upper()} ({logfile}) ──\n{content}")

    return "\n\n".join(parts)


@app.tool()
def running_processes(sort_by: Literal["cpu", "mem"] = "cpu", limit: int = 15) -> str:
    """Show top processes sorted by CPU or memory usage."""
    flag = "pcpu" if sort_by == "cpu" else "pmem"
    out, _ = _run(["ps", "aux", "--sort", f"-{flag}", "--no-headers", "--cols", "200"])
    header = f"{'USER':<12} {'PID':>7} {'%CPU':>5} {'%MEM':>5}  COMMAND"
    rows = []
    for line in out.splitlines()[:limit]:
        p = line.split(None, 10)
        if len(p) >= 11:
            rows.append(f"{p[0]:<12} {p[1]:>7} {p[2]:>5} {p[3]:>5}  {p[10][:80]}")
    return f"Processes (by {sort_by.upper()}):\n{header}\n" + "\n".join(rows)


@app.tool()
def nexus_snapshot() -> str:
    """Full NeXuS node health snapshot: services + network + metrics + recent security events in one call."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return "\n\n".join([
        f"╔══ NeXuS Node Snapshot — {ts} ══╗",
        system_metrics(),
        network_interfaces(),
        service_status(),
        "── Recent Security Events (fail2ban last 15) ──\n" + security_events("fail2ban", 15),
    ])


# ── entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run()
