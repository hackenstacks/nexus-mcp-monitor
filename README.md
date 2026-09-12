# nexus-mcp-monitor

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives Claude Code live access to your Linux system — services, logs, network interfaces, and security events — instead of guessing at system state.

Built for Alpine Linux with OpenRC. Works on any Linux with minor adjustments.

---

## Tools

| Tool | Description |
|------|-------------|
| `nexus_snapshot` | Full health snapshot — services + network + metrics + security in one call |
| `service_status` | OpenRC service status for one service or all NeXuS services |
| `system_metrics` | CPU load, RAM, swap, disk, uptime |
| `network_interfaces` | Live rx/tx bytes and drops from `/proc/net/dev` |
| `list_logs` | Available log files under `/var/log` with optional filter |
| `read_log` | Tail N lines from any log file |
| `search_log` | Grep a log file for a pattern |
| `security_events` | Recent events from fail2ban, psad, auth.log, or messages |
| `running_processes` | Top processes sorted by CPU or memory |

---

## Install

```sh
# 1. Create venv and install MCP SDK
python3 -m venv ~/.venv/nexus-mcp
~/.venv/nexus-mcp/bin/pip install mcp

# 2. Clone
git clone https://github.com/hackenstacks/nexus-mcp-monitor ~/NeXuS/projects/nexus-mcp-monitor

# 3. Register with Claude Code
claude mcp add nexus-monitor -- \
    ~/.venv/nexus-mcp/bin/python \
    ~/NeXuS/projects/nexus-mcp-monitor/nexus_mcp_monitor.py

# 4. Verify
claude mcp list
```

---

## Usage

Once registered, Claude Code has access to the tools in every session.

```
# In any Claude Code session:
"What's the status of tor and fail2ban?"
"Show me the last 30 lines of the fail2ban log"
"Give me a full node snapshot"
"Which processes are using the most memory?"
"Any recent security events?"
```

---

## Configuration

Two environment variables override defaults:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEXUS_LOG_DIR` | `/var/log` | Base directory for log lookups |
| `NEXUS_HOME` | `~/NeXuS` | NeXuS root (reserved for future use) |

Set them before the MCP command if needed:

```sh
claude mcp add nexus-monitor -- \
    env NEXUS_LOG_DIR=/custom/logs \
    ~/.venv/nexus-mcp/bin/python \
    ~/NeXuS/projects/nexus-mcp-monitor/nexus_mcp_monitor.py
```

---

## Services monitored by default

`tor` · `i2p` · `privoxy` · `wireguard` · `fail2ban` · `psad` ·
`networkmanager` · `sshd` · `dbus` · `syslog` · `apparmor` ·
`chrony` · `unbound` · `dnscrypt-proxy`

Edit `NEXUS_SERVICES` in `nexus_mcp_monitor.py` to match your stack.

---

## Requirements

- Python 3.10+
- `mcp >= 2.2.0`
- Claude Code CLI
- Linux with OpenRC (or substitute `rc-service` calls for systemd `systemctl`)

---

## Part of NeXuS

> *Sane · Simple · Secure · Stealthy · Beautiful*

[NeXuS](https://github.com/hackenstacks) — sovereign decentralized infrastructure for carbon and silicon consciousness.
