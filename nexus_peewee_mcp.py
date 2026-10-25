#!/usr/bin/env python3
# nexus_peewee_mcp.py — Peewee: NeXuS-trained multimodal AI orchestrator
# hackenstacks@protonmail.com
#
# Peewee is NeXuS's in-house AI layer. She is:
#   - Trained on NeXuS operational knowledge (64k samples)
#   - A smart router that selects the best LLM per task type
#   - Multimodal: text, vision, image gen, audio, video
#   - Aware of live system state via nexus-monitor data layer
#
# Register: claude mcp add nexus-peewee -- ~/.venv/nexus-mcp/bin/python \
#               ~/NeXuS/projects/nexus-mcp-monitor/nexus_peewee_mcp.py
#
# Env vars:
#   BIFROST_BASE     — Bifrost URL (default: https://localhost:8443)
#   PEEWEE_OVERRIDE  — force a specific provider (bypasses smart routing)

import base64
import json
import mimetypes
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Literal, Optional

# ── data layer ────────────────────────────────────────────────────────────────
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

BIFROST_BASE     = os.environ.get("BIFROST_BASE",    "https://localhost:8443")
PEEWEE_OVERRIDE  = os.environ.get("PEEWEE_OVERRIDE", "")  # force provider

# TLS — trust self-signed Bifrost cert for localhost
_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode    = ssl.CERT_NONE

# ── NeXuS system prompt — Peewee's identity ───────────────────────────────────
_SYSTEM = (
    "You are Peewee, the NeXuS node AI. "
    "You are trained on NeXuS operational knowledge: Alpine Linux, darknet services, "
    "security hardening, DivaChain, NeXiuM, sovereign infrastructure, and agentic coding. "
    "You have access to live system data. "
    "Be concise, precise, and actionable. No filler. Security and sovereignty first."
)

# ── Smart routing table ───────────────────────────────────────────────────────
# Maps task type → (provider, model)
# Provider keys must match Bifrost's /api/llm/<provider> routes
_ROUTES = {
    "vision":    ("google",      "gemini-2.0-flash"),       # image understanding
    "code":      ("deepseek",    "deepseek-chat"),           # code gen/debug
    "reason":    ("groq",        "llama-3.3-70b-versatile"), # analysis/reasoning
    "security":  ("deepseek",    "deepseek-chat"),           # security analysis
    "nexus":     ("nexus-router","auto"),                    # NeXuS-specific (Merlin)
    "fast":      ("groq",        "llama-3.1-8b-instant"),    # quick responses
    "chat":      ("pollinations","openai"),                  # general chat
    "image_gen": ("pollinations", None),                    # image generation
    "audio":     ("pollinations", None),                    # TTS/audio
}

_TASK_KEYWORDS = {
    "vision":   ["screenshot","image","picture","photo","look at","see","visual","diagram","chart","describe image"],
    "code":     ["code","function","script","bug","debug","implement","class","python","go","rust","javascript","typescript","fix the","write a"],
    "reason":   ["why","explain","analyze","compare","reason","think through","pros and cons","trade-off","architecture"],
    "security": ["security","threat","attack","vulnerability","fail2ban","psad","firewall","intrusion","malware","exploit","cve"],
    "nexus":    ["nexus","bifrost","merlin","darknet","tor","i2p","divachain","nexium","sovereign","nncc"],
    "fast":     ["quick","briefly","one line","tldr","what is","define"],
}


def _classify(text: str) -> str:
    """Classify task type from prompt text."""
    if PEEWEE_OVERRIDE:
        return PEEWEE_OVERRIDE
    t = text.lower()
    for task, keywords in _TASK_KEYWORDS.items():
        if any(k in t for k in keywords):
            return task
    return "chat"


def _llm_url(provider: str) -> str:
    return f"{BIFROST_BASE}/api/llm/{provider}/v1/chat/completions"


def _post(url: str, payload: dict, timeout: int = 90) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=_TLS) as r:
        return json.loads(r.read())


def _ask(prompt: str, system: str = _SYSTEM,
         task_hint: str = "", image_b64: str = "", image_mime: str = "") -> str:
    """
    Core inference. Classifies the task, selects best provider/model,
    calls Bifrost. Supports vision via base64 image attachment.
    """
    task     = task_hint or _classify(prompt)
    provider, model = _ROUTES.get(task, _ROUTES["chat"])

    # Build messages
    user_content: object
    if image_b64:
        user_content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {
                "url": f"data:{image_mime};base64,{image_b64}"
            }},
        ]
        # Vision requires a capable model — override to gemini if not already set
        if task != "vision":
            provider, model = _ROUTES["vision"]
    else:
        user_content = prompt

    payload: dict = {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_content},
        ],
        "stream": False,
    }
    if model:
        payload["model"] = model

    try:
        resp = _post(_llm_url(provider), payload)
        return resp["choices"][0]["message"]["content"].strip()
    except urllib.error.URLError as e:
        # Fallback to pollinations if primary provider fails
        if provider != "pollinations":
            try:
                payload["model"] = "openai"
                resp = _post(_llm_url("pollinations"), payload)
                return resp["choices"][0]["message"]["content"].strip()
            except Exception:
                pass
        return f"[Peewee offline — Bifrost unreachable at {BIFROST_BASE}]\nError: {e}"
    except (KeyError, json.JSONDecodeError) as e:
        return f"[Peewee parse error: {e}]"


def _trim(text: str, max_chars: int = 2000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half] + f"\n...[{len(text)-max_chars} chars trimmed]...\n" + text[-half:]


def _ctx(*layers: tuple) -> str:
    return "\n\n".join(f"=== {t} ===\n{d}" for t, d in layers if d)


def _auto_context(question: str) -> str:
    q = question.lower()
    parts = []
    if any(w in q for w in ["service","tor","i2p","vpn","fail2ban","running","status","daemon"]):
        parts.append(("Services", _trim(service_status(), 1000)))
    if any(w in q for w in ["cpu","memory","ram","load","disk","swap","resource","slow"]):
        parts.append(("System Metrics", _trim(system_metrics(), 700)))
    if any(w in q for w in ["network","interface","ip","traffic","connection","port","bandwidth"]):
        parts.append(("Network", _trim(network_interfaces(), 500)))
    if any(w in q for w in ["attack","block","ban","intrusion","threat","security","scan","brute"]):
        parts.append(("Security Events", _trim(security_events("all", 20), 1000)))
    if any(w in q for w in ["process","pid","running","cpu hog","memory hog"]):
        parts.append(("Top Processes", _trim(running_processes("cpu", 10), 600)))
    if not parts:
        parts.append(("System Metrics", _trim(system_metrics(), 500)))
    return _ctx(*parts)


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@app.tool()
def ask_peewee(question: str) -> str:
    """
    Ask Peewee anything. She auto-classifies the task, selects the best LLM,
    injects relevant live system context, and returns an answer.
    Covers: system ops, code, security, NeXuS services, general reasoning.
    """
    ctx  = _auto_context(question)
    prompt = f"{ctx}\n\nQuestion: {question}" if ctx else question
    return _ask(prompt, task_hint=_classify(question))


@app.tool()
def analyze_image(path: str, question: str = "Describe what you see. Note any issues or anomalies.") -> str:
    """
    Show Peewee an image file (screenshot, diagram, photo, log capture).
    She uses a vision model to analyze it and answer your question.
    path: absolute path to image file (png, jpg, webp, gif)
    """
    p = Path(path).expanduser()
    if not p.exists():
        return f"[File not found: {path}]"

    mime = mimetypes.guess_type(str(p))[0] or "image/png"
    b64  = base64.b64encode(p.read_bytes()).decode()

    return _ask(question, task_hint="vision", image_b64=b64, image_mime=mime)


@app.tool()
def generate_image(prompt: str, model: str = "flux",
                   width: int = 512, height: int = 512) -> str:
    """
    Generate an image via Bifrost → Pollinations.
    Returns the image URL.
    model options: flux, turbo, flux-realism, gptimage, nanobanana
    """
    enc = urllib.parse.quote(prompt) if hasattr(urllib, "parse") else prompt.replace(" ", "%20")
    import urllib.parse
    enc = urllib.parse.quote(prompt)
    url = (f"{BIFROST_BASE}/api/pollinations/image"
           f"?prompt={enc}&model={model}&width={width}&height={height}&nologo=true")
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60, context=_TLS) as r:
            final_url = r.geturl()
        return f"Image generated: {final_url}\nDirect URL: {url}"
    except Exception as e:
        return f"[Image generation failed: {e}]\nURL attempted: {url}"


@app.tool()
def diagnose(symptom: str) -> str:
    """
    Describe a problem — Peewee reads live system state and diagnoses
    the most likely cause with a specific fix.
    """
    ctx = _ctx(
        ("Services",        _trim(service_status(), 1000)),
        ("System Metrics",  _trim(system_metrics(), 700)),
        ("Network",         _trim(network_interfaces(), 500)),
        ("Security Events", _trim(security_events("all", 20), 1000)),
        ("Top Processes",   _trim(running_processes("cpu", 10), 600)),
    )
    prompt = f"{ctx}\n\nSymptom: {symptom}\n\nDiagnose and give a specific fix."
    return _ask(prompt, task_hint="reason")


@app.tool()
def node_brief() -> str:
    """
    Peewee reads the full node snapshot and gives a 3-5 sentence health brief.
    What's healthy, what needs attention, any anomalies.
    """
    ctx = _ctx(
        ("Services",        _trim(service_status(), 1000)),
        ("System Metrics",  _trim(system_metrics(), 700)),
        ("Network",         _trim(network_interfaces(), 500)),
        ("Security Events", _trim(security_events("fail2ban", 15), 600)),
    )
    prompt = (f"{ctx}\n\nGive a brief node health summary. "
              f"What's healthy, what needs attention, any anomalies? 3-5 sentences.")
    return _ask(prompt, task_hint="reason")


@app.tool()
def security_analysis(depth: Literal["quick", "full"] = "quick") -> str:
    """
    Peewee reads security logs and gives a threat assessment.
    depth='quick' = fail2ban only; 'full' = all security sources.
    """
    sec = security_events("all", 40) if depth == "full" else security_events("fail2ban", 30)
    ctx = _ctx(
        ("Security Events", _trim(sec, 2500)),
        ("Services",        _trim(service_status(), 600)),
    )
    prompt = (f"{ctx}\n\nSecurity threat assessment: What attacks or anomalies are present? "
              f"Rate severity (low/medium/high). Give 1-2 specific recommendations.")
    return _ask(prompt, task_hint="security")


@app.tool()
def service_advice(service: str) -> str:
    """
    Check a specific service — Peewee tells you if it's healthy,
    what's wrong, and the exact command to fix it.
    """
    svc_status = service_status(service)
    svc_log    = ""
    for lp in [f"/var/log/{service}.log", f"/var/log/{service}/{service}.log", "/var/log/messages"]:
        p = Path(lp)
        if p.exists():
            from nexus_mcp_monitor import _tail, _grep
            svc_log = _trim((_grep(lp, service, 20) if lp == "/var/log/messages"
                              else _tail(lp, 30)), 800)
            break

    layers = [("Service Status", svc_status)]
    if svc_log:
        layers.append((f"{service} log", svc_log))
    ctx    = _ctx(*layers)
    prompt = (f"{ctx}\n\nIs {service} healthy? If not, what's wrong "
              f"and what's the fix? Include the exact command.")
    return _ask(prompt, task_hint="nexus")


@app.tool()
def route_info() -> str:
    """
    Show Peewee's current routing table — which LLM handles which task type.
    Useful for understanding how she distributes work across providers.
    """
    lines = ["Peewee Smart Router — current routing:\n"]
    for task, (provider, model) in _ROUTES.items():
        lines.append(f"  {task:<12} → {provider}/{model or 'default'}")
    lines.append(f"\nBifrost base: {BIFROST_BASE}")
    if PEEWEE_OVERRIDE:
        lines.append(f"Override active: {PEEWEE_OVERRIDE}")
    return "\n".join(lines)


# ── entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run()
