#!/usr/bin/env python3
"""
nexus_peewee_mcp.py — NeXuS Peewee intelligence layer MCP server
Wraps a small local model (Peewee) with live data from nexus-monitor as context.
Peewee reasons about system state; nexus-monitor is the data layer.

Register: claude mcp add nexus-peewee -- ~/.venv/nexus-mcp/bin/python \
              ~/NeXuS/projects/nexus-mcp-monitor/nexus_peewee_mcp.py

Env vars:
  PEEWEE_MODEL   — aichat model string (default: ollama:smollm2:360m-instruct-q4_K_M)
  AICHAT_BASE    — aichat --serve base URL (default: http://127.0.0.1:3030)
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Literal

# ── import data layer ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from nexus_mcp_monitor import (
    network_interfaces,
    running_processes,
    security_events,
    service_status,
    system_metrics,
)

from mcp.server.mcpserver import MCPServer

app = MCPServer("nexus-peewee")

PEEWEE_MODEL = os.environ.get("PEEWEE_MODEL", "ollama:smollm2:360m-instruct-q4_K_M")
AICHAT_BASE  = os.environ.get("AICHAT_BASE",  "http://127.0.0.1:3030")

SYSTEM_PROMPT = (
    "You are Peewee, the NeXuS node intelligence layer. "
    "Analyze the system data provided and give concise, actionable responses. "
    "Focus on anomalies, issues, and concrete recommendations. "
    "NeXuS is a sovereign privacy-first Linux node. Security and stability are top priority. "
    "Be brief. No filler."
)


# ── core inference ─────────────────────────────────────────────────────────────

def _ask(user: str, system: str = SYSTEM_PROMPT, model: str = PEEWEE_MODEL) -> str:
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        f"{AICHAT_BASE}/v1/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.URLError as e:
        return (
            f"[Peewee offline — aichat --serve not running at {AICHAT_BASE}]\n"
            f"Start it with: aichat --serve\n"
            f"Error: {e}"
        )
    except (KeyError, json.JSONDecodeError) as e:
        return f"[Peewee response parse error: {e}]"


def _trim(text: str, max_chars: int = 2000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n...[trimmed {len(text)-max_chars} chars]...\n" + text[-half:]


def _ctx(*layers: str) -> str:
    return "\n\n".join(f"=== {t} ===\n{d}" for t, d in layers if d)


# ── keyword → context auto-detection ──────────────────────────────────────────

def _auto_context(question: str) -> str:
    q = question.lower()
    parts = []

    if any(w in q for w in ["service", "tor", "i2p", "vpn", "wireguard", "fail2ban",
                              "running", "start", "stop", "status", "daemon"]):
        parts.append(("Services", _trim(service_status(), 1200)))

    if any(w in q for w in ["cpu", "memory", "ram", "disk", "load", "swap",
                              "slow", "performance", "resource", "uptime"]):
        parts.append(("System Metrics", _trim(system_metrics(), 800)))

    if any(w in q for w in ["network", "interface", "eth0", "wlan", "usb0",
                              "traffic", "bandwidth", "rx", "tx", "drop"]):
        parts.append(("Network", _trim(network_interfaces(), 600)))

    if any(w in q for w in ["security", "attack", "block", "ban", "fail2ban",
                              "psad", "auth", "ssh", "intrusion", "threat"]):
        parts.append(("Security Events", _trim(security_events("all", 20), 1500)))

    # fallback: nothing detected — give metrics + services
    if not parts:
        parts = [
            ("Services", _trim(service_status(), 800)),
            ("System Metrics", _trim(system_metrics(), 600)),
        ]

    return _ctx(*parts)


# ── tools ──────────────────────────────────────────────────────────────────────

@app.tool()
def ask_peewee(
    question: str,
    context: Literal["auto", "full", "none", "services", "network", "security", "metrics"] = "auto",
) -> str:
    """
    Ask Peewee a question about the NeXuS node. Peewee reasons from trained knowledge
    plus live system data. context='auto' injects relevant data based on the question;
    'full' injects everything; 'none' asks bare; or specify a data layer directly.
    """
    match context:
        case "auto":
            ctx = _auto_context(question)
        case "full":
            ctx = _ctx(
                ("Services",        _trim(service_status(), 1000)),
                ("System Metrics",  _trim(system_metrics(), 700)),
                ("Network",         _trim(network_interfaces(), 500)),
                ("Security Events", _trim(security_events("all", 20), 1200)),
            )
        case "none":
            ctx = ""
        case "services":
            ctx = _ctx(("Services", _trim(service_status(), 1500)))
        case "network":
            ctx = _ctx(("Network", _trim(network_interfaces(), 1000)))
        case "security":
            ctx = _ctx(("Security Events", _trim(security_events("all", 30), 2000)))
        case "metrics":
            ctx = _ctx(("System Metrics", _trim(system_metrics(), 1200)))

    prompt = f"{ctx}\n\n{question}" if ctx else question
    return _ask(prompt)


@app.tool()
def diagnose(symptom: str) -> str:
    """
    Describe a symptom or problem and Peewee diagnoses it with full live system context
    injected: services, metrics, network state, and recent security events.
    """
    ctx = _ctx(
        ("Services",        _trim(service_status(), 1000)),
        ("System Metrics",  _trim(system_metrics(), 700)),
        ("Network",         _trim(network_interfaces(), 500)),
        ("Security Events", _trim(security_events("all", 20), 1000)),
        ("Top Processes",   _trim(running_processes("cpu", 10), 600)),
    )
    prompt = (
        f"{ctx}\n\n"
        f"Symptom reported: {symptom}\n\n"
        f"Diagnose the most likely cause and give a specific fix."
    )
    return _ask(prompt)


@app.tool()
def node_brief() -> str:
    """
    Ask Peewee for a human-readable health brief of the current node state.
    Peewee reads the full snapshot and summarizes what matters.
    """
    ctx = _ctx(
        ("Services",        _trim(service_status(), 1000)),
        ("System Metrics",  _trim(system_metrics(), 700)),
        ("Network",         _trim(network_interfaces(), 500)),
        ("Security Events", _trim(security_events("fail2ban", 15), 600)),
    )
    prompt = (
        f"{ctx}\n\n"
        f"Give a brief node health summary. "
        f"What's healthy, what needs attention, any anomalies? "
        f"3-5 sentences max."
    )
    return _ask(prompt)


@app.tool()
def security_analysis(depth: Literal["quick", "full"] = "quick") -> str:
    """
    Peewee reads all security logs and gives a threat assessment.
    depth='quick' = fail2ban only; 'full' = fail2ban + psad + auth + messages.
    """
    if depth == "full":
        sec = security_events("all", 40)
    else:
        sec = security_events("fail2ban", 30)

    ctx = _ctx(
        ("Security Events", _trim(sec, 2500)),
        ("Services",        _trim(service_status(), 600)),
    )
    prompt = (
        f"{ctx}\n\n"
        f"Security threat assessment: What attacks or anomalies are present? "
        f"Rate severity (low/medium/high). Give 1-2 specific recommendations."
    )
    return _ask(prompt)


@app.tool()
def service_advice(service: str) -> str:
    """
    Check a specific service and ask Peewee whether it's healthy, what's wrong,
    and what to do. Injects service status + the service's log if it exists.
    """
    svc_status = service_status(service)

    # try to find and tail the service log
    log_sources = [
        f"/var/log/{service}.log",
        f"/var/log/{service}/{service}.log",
        f"/var/log/messages",
    ]
    svc_log = ""
    for lp in log_sources:
        p = Path(lp)
        if p.exists():
            from nexus_mcp_monitor import _tail, _grep
            if lp == "/var/log/messages":
                svc_log = _trim(_grep(lp, service, 20), 800)
            else:
                svc_log = _trim(_tail(lp, 30), 800)
            break

    layers = [("Service Status", svc_status)]
    if svc_log:
        layers.append((f"{service} log", svc_log))

    ctx = _ctx(*layers)
    prompt = (
        f"{ctx}\n\n"
        f"Is {service} healthy? If not, what's wrong and what's the fix? "
        f"Be specific — include the exact command to resolve it if applicable."
    )
    return _ask(prompt)


# ── entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run()
