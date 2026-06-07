#!/usr/bin/env python3
"""
BrowserForensix — ai_engine.py
OpenRouter AI integration. Provides forensic intelligence across all pages.

FIX-9: urllib.request.urlopen now passes timeout=60 (was missing entirely).
        Without a timeout, a hung OpenRouter connection kept aiStreaming=true
        permanently, locking the send button for the entire browser session.
        60 s is generous for normal use; streaming routes will still yield
        incremental deltas well within that window.
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Generator, Optional
import logging
import threading

import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────────────────────

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
PRIMARY_MODEL   = os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")
FALLBACK_MODEL  = "mistralai/mistral-7b-instruct"
APP_URL         = "http://localhost:5000"
APP_NAME        = "BrowserForensix"

# Request timeout in seconds.
# FIX-9: was absent — urlopen blocked indefinitely on hung connections.
_REQUEST_TIMEOUT = 60

# Load .env if present — prefer python-dotenv if installed, else manual parse
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        for line in _env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _api_key() -> str:
    # Deprecated single-key accessor kept for compatibility.
    # New code should use the rotation helpers below.
    keys = _API_KEYS
    if not keys:
        raise EnvironmentError(
            "No OPENROUTER API keys found. Set OPENROUTER_API_KEY or OPENROUTER_API_KEY_1, ..."
        )
    # Return the first key without advancing rotation.
    return keys[0]


# ── API key rotation state ──────────────────────────────────────────────────
logger = logging.getLogger(__name__)
_API_KEY_LOCK = threading.Lock()
_API_KEYS: list[str] = []
_API_KEY_INDEX = 0


def _load_api_keys() -> None:
    """Load OPENROUTER API keys from environment variables.

    Supports: OPENROUTER_API_KEY (fallback) and OPENROUTER_API_KEY_1, _2, ...
    Keys are ordered by numeric suffix (no suffix sorts first).
    """
    global _API_KEYS
    pattern = re.compile(r"^OPENROUTER_API_KEY(?:_(\d+))?$")
    found: dict[int, str] = {}
    for name, val in os.environ.items():
        m = pattern.match(name)
        if m and val:
            suf = m.group(1)
            idx = int(suf) if suf is not None else 0
            found[idx] = val.strip()
    if not found:
        _API_KEYS = []
        return
    items = sorted(found.items(), key=lambda kv: kv[0])
    _API_KEYS = [v for _, v in items]
    logger.info("Loaded %d OPENROUTER API key(s)", len(_API_KEYS))


def _get_next_key() -> tuple[int, str]:
    """Return the next API key (index, key) and advance the round-robin index.

    Logs the key index but never logs key values.
    """
    global _API_KEY_INDEX
    if not _API_KEYS:
        raise EnvironmentError(
            "No OPENROUTER API keys found. Set OPENROUTER_API_KEY or OPENROUTER_API_KEY_1, ..."
        )
    with _API_KEY_LOCK:
        idx = _API_KEY_INDEX
        key = _API_KEYS[idx]
        _API_KEY_INDEX = (_API_KEY_INDEX + 1) % len(_API_KEYS)
    logger.info("Active OPENROUTER API key index %d", idx)
    return idx, key


# Initialize keys at module import time
_load_api_keys()


# ── Low-level HTTP ────────────────────────────────────────────────────────────

def _post(payload: dict, stream: bool = False, model: str = PRIMARY_MODEL) -> "dict | Generator":
    """
    POST to OpenRouter via stdlib urllib.
    Returns parsed JSON dict (non-stream) or a line generator (stream).

    FIX-9: timeout=_REQUEST_TIMEOUT passed to urlopen on every call.
    Previously timeout was omitted so a hung connection would block forever,
    keeping aiStreaming=True and locking the UI send button indefinitely.
    """
    payload = {**payload, "model": model}
    body = json.dumps(payload).encode()

    # Try each configured API key in round-robin order. If a key returns a
    # 429 (rate limit), fall back to the next key and retry until keys are
    # exhausted.
    if not _API_KEYS:
        raise EnvironmentError(
            "No OPENROUTER API keys found. Set OPENROUTER_API_KEY or OPENROUTER_API_KEY_1, ..."
        )

    last_exc: Optional[Exception] = None
    attempts = len(_API_KEYS)
    for attempt in range(attempts):
        idx, key = _get_next_key()
        req = urllib.request.Request(
            f"{OPENROUTER_BASE}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": APP_URL,
                "X-Title": APP_NAME,
            },
            method="POST",
        )

        try:
            resp = urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT)
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            # If rate-limited, try next key
            if e.code == 429 and attempt < attempts - 1:
                logger.warning("OpenRouter 429 for key index %d, falling back to next key", idx)
                last_exc = e
                continue
            raise RuntimeError(f"OpenRouter {e.code}: {body_text}") from e

        if stream:
            def _lines():
                for raw in resp:
                    line = raw.decode().strip()
                    if line.startswith("data: "):
                        chunk = line[6:]
                        if chunk == "[DONE]":
                            return
                        try:
                            yield json.loads(chunk)
                        except json.JSONDecodeError:
                            pass
            return _lines()

        return json.loads(resp.read().decode())

    # If we get here, all keys failed with 429 or other errors; propagate last
    # exception if present.
    if last_exc:
        raise RuntimeError("All OPENROUTER API keys were rate-limited") from last_exc
    raise RuntimeError("Failed to contact OpenRouter API with provided keys")


def _chat(system: str, user: str, max_tokens: int = 1200, temperature: float = 0.2) -> str:
    """Synchronous single-turn chat. Returns assistant content string."""
    result = _post({
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "max_tokens":  max_tokens,
        "temperature": temperature,
    })
    return result["choices"][0]["message"]["content"].strip()


def _chat_stream(system: str, user: str, max_tokens: int = 1200) -> Generator:
    """Streaming chat. Yields text delta strings."""
    chunks = _post(
        {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "stream": True,
        },
        stream=True,
    )
    for chunk in chunks:
        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
        if delta:
            yield delta


# ── Shared forensic system prompt ─────────────────────────────────────────────

_FORENSIC_SYSTEM = """You are an expert digital forensics analyst embedded in BrowserForensix,
a browser artifact analysis platform. You have deep knowledge of:
- Browser forensics (Chrome, Firefox, Edge, Safari)
- DFIR (Digital Forensics & Incident Response)
- Threat hunting and IOC analysis
- Privacy violations and insider threat patterns
- Malware delivery via browser

You receive structured JSON data extracted from a real browser profile.
Respond concisely and technically. Focus on what is INVESTIGATIVELY SIGNIFICANT.
Do not repeat obvious facts. Do not hedge unnecessarily.
Format findings as clear, numbered investigative observations.
Flag anything that warrants immediate follow-up with ⚠️.
Use plain language — your output will be read by investigators, not developers."""


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 1: Executive Summary
# ══════════════════════════════════════════════════════════════════════════════

def ai_executive_summary(analysis: dict) -> dict:
    summary   = analysis.get("summary", {})
    anomalies = analysis.get("anomalies", [])[:10]
    top_domains       = analysis.get("top_domains", [])[:15]
    flagged_history   = [h for h in analysis.get("history",   []) if h.get("risk_score", 0) >= 61][:10]
    flagged_downloads = [d for d in analysis.get("downloads", []) if d.get("risk_score", 0) >= 61][:5]

    user_prompt = f"""Analyze this browser forensic data and produce an executive summary.

ARTIFACT COUNTS:
{json.dumps(summary, indent=2)}

TOP ANOMALIES DETECTED:
{json.dumps([{"type": a["type"], "title": a["title"], "description": a["description"]} for a in anomalies], indent=2)}

TOP DOMAINS BY VISITS:
{json.dumps([{"domain": d["domain"], "visits": d["visits"], "risk_score": d["risk_score"]} for d in top_domains], indent=2)}

FLAGGED HISTORY ITEMS (risk >= 61):
{json.dumps([{"url": h["url"], "risk_score": h["risk_score"], "reasons": h.get("risk_reasons",[])} for h in flagged_history], indent=2)}

FLAGGED DOWNLOADS:
{json.dumps([{"filename": d["filename"], "source": d.get("source_url",""), "risk_score": d["risk_score"], "reasons": d.get("risk_reasons",[])} for d in flagged_downloads], indent=2)}

Write a 3-5 paragraph forensic executive summary covering:
1. Overall threat posture (1 sentence verdict)
2. Most significant findings
3. Behavioral patterns observed
4. Recommended investigative next steps
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=800)
    return {"summary": content, "model": PRIMARY_MODEL, "generated_at": time.time()}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 2: History Item Explainer
# ══════════════════════════════════════════════════════════════════════════════

def ai_explain_history_item(item: dict, context_items: list) -> dict:
    user_prompt = f"""A browser forensic tool flagged this history entry:

URL: {item.get("url", "")}
Title: {item.get("title", "")}
Last Visit: {item.get("last_visit", "")}
Visit Count: {item.get("visit_count", 1)}
Risk Score: {item.get("risk_score", 0)}/100
Risk Factors: {", ".join(item.get("risk_reasons", []))}

OTHER VISITS TO SAME DOMAIN (for context):
{json.dumps([{"url": c.get("url",""), "last_visit": c.get("last_visit",""), "visit_count": c.get("visit_count",1)} for c in context_items[:5]], indent=2)}

In 3-5 sentences, explain:
1. Why this URL is forensically significant
2. What the visit pattern suggests about user intent
3. What an investigator should look for next
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=400)
    return {"explanation": content, "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 3: Domain Profile
# ══════════════════════════════════════════════════════════════════════════════

def ai_domain_profile(domain: str, domain_data: dict) -> dict:
    user_prompt = f"""Analyze this domain's forensic profile from a browser investigation:

DOMAIN: {domain}

VISIT DATA:
- Total visits: {domain_data.get("total_visits", 0)}
- First seen: {domain_data.get("first_seen", "unknown")}
- Last seen: {domain_data.get("last_seen", "unknown")}
- In history: {domain_data.get("in_history", False)}
- Max risk score: {domain_data.get("max_risk_score", 0)}/100
- Risk factors: {", ".join(domain_data.get("risk_reasons", []))}

COOKIES ({len(domain_data.get("cookies", []))} total):
{json.dumps([{"name": c.get("name",""), "type": c.get("type",""), "expires": c.get("expires",""), "secure": c.get("secure",True)} for c in domain_data.get("cookies",[])[:8]], indent=2)}

DOWNLOADS ({len(domain_data.get("downloads", []))} total):
{json.dumps([{"filename": d.get("filename",""), "size": d.get("size_bytes",0), "risk": d.get("risk_score",0)} for d in domain_data.get("downloads",[])[:5]], indent=2)}

Provide:
1. What this domain likely is (service/tool/threat category)
2. Whether the usage pattern is suspicious or benign and why
3. Specific forensic observations (cookie types, download patterns, timing)
4. Investigative recommendation
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=500)
    return {"profile": content, "domain": domain, "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 4: Session Narrative (streaming)
# ══════════════════════════════════════════════════════════════════════════════

def ai_session_narrative_stream(session: dict) -> Generator:
    events = session.get("events", [])[:40]
    system_prompt = _FORENSIC_SYSTEM + "\nRespond in flowing prose, not lists. Tell the story of what happened."

    user_prompt = f"""Reconstruct the narrative of this browsing session for a forensic report:

Session Start: {session.get("start", "")}
Session End: {session.get("end", "")}
Total Events: {session.get("count", 0)}

EVENTS (chronological):
{json.dumps([{
    "time": e.get("time",""),
    "type": e.get("type",""),
    "domain": e.get("domain", e.get("host","")),
    "title": e.get("title",""),
    "filename": e.get("filename",""),
    "risk_score": e.get("risk_score",0)
} for e in events], indent=2)}

Write a 2-3 paragraph narrative describing:
- What the user appeared to be doing during this session
- Any suspicious transitions, downloads, or patterns
- The overall character of this session (research, exfiltration, browsing, etc.)
"""
    yield from _chat_stream(system_prompt, user_prompt, max_tokens=600)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 5: Download Threat Assessment
# ══════════════════════════════════════════════════════════════════════════════

def ai_download_threat(download: dict, all_downloads: list) -> dict:
    from urllib.parse import urlparse as _urlparse
    src_domain = _urlparse(download.get("source_url", "")).netloc
    related = [d for d in all_downloads
               if d.get("source_url","") != download.get("source_url","")
               and src_domain and src_domain in d.get("source_url","")][:3]

    user_prompt = f"""Assess this browser download for forensic significance:

DOWNLOAD:
- Filename: {download.get("filename", "")}
- Source URL: {download.get("source_url", "")}
- Downloaded: {download.get("start_time", "")}
- File size: {download.get("size_bytes", 0):,} bytes
- Still on disk: {download.get("file_exists", True)}
- In browser history: {download.get("in_history", True)}
- Chrome danger flag: {download.get("danger_type", 0)}
- Risk score: {download.get("risk_score", 0)}/100
- Risk factors: {", ".join(download.get("risk_reasons", []))}

RELATED DOWNLOADS FROM SAME SOURCE:
{json.dumps([{"filename": d.get("filename",""), "size": d.get("size_bytes",0), "time": d.get("start_time","")} for d in related], indent=2)}

Assess:
1. What this file likely is based on its name, extension, and source
2. Whether the download pattern is suspicious (timing, source legitimacy, history gap)
3. The significance of it being {"missing from disk" if not download.get("file_exists") else "still present on disk"}
4. Whether an investigator should prioritise recovering or examining this file
Keep response to 3-4 sentences.
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=350)
    return {"assessment": content, "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 6: Gap / Cleared History Analysis
# ══════════════════════════════════════════════════════════════════════════════

def ai_gap_analysis(gap_anomaly: dict, top_cookie_domains: list) -> dict:
    user_prompt = f"""A browser forensic tool detected history clearing. Analyze the pattern:

GAP ANOMALY:
{json.dumps(gap_anomaly, indent=2)}

DOMAINS WITH COOKIES BUT NO HISTORY (top 15):
{json.dumps(top_cookie_domains[:15], indent=2)}

Answer:
1. What does this pattern of surviving cookies suggest about WHEN history was cleared?
2. Do the surviving cookie domains suggest a specific activity that was being concealed?
3. What was likely being hidden?
4. What forensic steps should be taken to recover deleted history?
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=500)
    return {"analysis": content, "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 7: Narrative Report (streaming)
# ══════════════════════════════════════════════════════════════════════════════

def ai_narrative_report_stream(report_data: dict, case_meta: dict) -> Generator:
    flagged   = report_data.get("flagged", {})
    anomalies = report_data.get("anomalies", [])
    summary   = report_data.get("summary", {})
    meta      = report_data.get("meta", {})

    system_prompt = _FORENSIC_SYSTEM + (
        "\nWrite in formal forensic report style. Use section headers. "
        "Be precise and factual. Avoid speculation unless clearly labelled as such."
    )

    user_prompt = f"""Generate a professional forensic narrative report for this browser investigation.

CASE METADATA:
Case Number: {case_meta.get("case_number", "N/A")}
Examiner: {case_meta.get("examiner", "N/A")}
Acquisition Date: {case_meta.get("date", "N/A")}

SUBJECT BROWSER: {meta.get("browser","Chrome")} — {meta.get("profile_path","")}
EXTRACTION TIME: {meta.get("extraction_time","")}

ARTIFACT SUMMARY:
{json.dumps(summary, indent=2)}

ANOMALIES ({len(anomalies)} total):
{json.dumps([{"type": a["type"], "severity": a["severity"], "title": a["title"], "description": a["description"]} for a in anomalies[:8]], indent=2)}

FLAGGED HISTORY ({len(flagged.get("history",[]))} items):
{json.dumps([{"url": h["url"], "risk_score": h["risk_score"], "reasons": h.get("risk_reasons",[])} for h in flagged.get("history",[])[:8]], indent=2)}

FLAGGED DOWNLOADS ({len(flagged.get("downloads",[]))} items):
{json.dumps([{"filename": d["filename"], "source": d.get("source_url",""), "risk_score": d["risk_score"]} for d in flagged.get("downloads",[])[:5]], indent=2)}

Write a full forensic narrative report with these sections:
1. EXECUTIVE SUMMARY
2. SCOPE AND METHODOLOGY
3. KEY FINDINGS
4. ANOMALY ANALYSIS
5. RISK ASSESSMENT
6. INVESTIGATIVE RECOMMENDATIONS
"""
    yield from _chat_stream(system_prompt, user_prompt, max_tokens=1500)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 8: Anomaly Deep Dive
# ══════════════════════════════════════════════════════════════════════════════

def ai_anomaly_deep_dive(anomaly: dict, related_history: list, related_cookies: list) -> dict:
    user_prompt = f"""Deep-dive this browser forensic anomaly:

ANOMALY:
Type: {anomaly.get("type","")}
Severity: {anomaly.get("severity","")}
Title: {anomaly.get("title","")}
Description: {anomaly.get("description","")}

RELATED HISTORY ENTRIES ({len(related_history)} total, showing first 5):
{json.dumps([{"url": h.get("url",""), "last_visit": h.get("last_visit",""), "risk_score": h.get("risk_score",0)} for h in related_history[:5]], indent=2)}

RELATED COOKIES ({len(related_cookies)} total, showing first 5):
{json.dumps([{"host": c.get("host",""), "name": c.get("name",""), "type": c.get("type",""), "created": c.get("created","")} for c in related_cookies[:5]], indent=2)}

Provide:
1. Plain-language explanation of what this anomaly means
2. The most likely explanation (benign vs. suspicious)
3. Red flags that elevate concern
4. Specific follow-up actions for an investigator
Keep to 4-5 sentences total.
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=400)
    return {"deep_dive": content, "anomaly_type": anomaly.get("type",""), "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 9: AI Chat (streaming)
# ══════════════════════════════════════════════════════════════════════════════

def ai_chat_stream(user_message: str, conversation_history: list, analysis_snapshot: dict) -> Generator:
    system_prompt = _FORENSIC_SYSTEM + f"""

You have access to a browser forensic analysis with these key facts:
- Browser: {analysis_snapshot.get("browser", "Chrome")}
- Total artifacts: {analysis_snapshot.get("total_artifacts", 0)}
- Flagged items: {analysis_snapshot.get("flagged_count", 0)}
- Anomaly count: {analysis_snapshot.get("anomaly_count", 0)}
- Top risky domains: {", ".join(analysis_snapshot.get("top_risky_domains", []))}
- Key anomalies: {"; ".join(analysis_snapshot.get("anomaly_titles", [])[:5])}

Answer questions about this specific evidence. If asked about something not in
the data, say so clearly. Keep responses focused and investigatively useful."""

    messages = []
    for turn in conversation_history[-8:]:
        messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": user_message})

    chunks = _post(
        {
            "messages": [{"role": "system", "content": system_prompt}] + messages,
            "max_tokens": 800,
            "temperature": 0.3,
            "stream": True,
        },
        stream=True,
    )
    for chunk in chunks:
        delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
        if delta:
            yield delta


# ── Health check ──────────────────────────────────────────────────────────────

def check_connection() -> dict:
    """Verify API key is set and OpenRouter is reachable."""
    try:
        if not _API_KEYS:
            raise EnvironmentError("No OPENROUTER API keys found.")
        result = _post({
            "messages": [{"role": "user", "content": "Reply with only the word: OK"}],
            "max_tokens": 5,
            "temperature": 0,
        })
        reply = result["choices"][0]["message"]["content"].strip()
        return {"connected": True, "model": PRIMARY_MODEL, "reply": reply}
    except EnvironmentError as e:
        return {"connected": False, "error": str(e), "error_type": "no_api_key"}
    except Exception as e:
        return {"connected": False, "error": str(e), "error_type": "connection"}