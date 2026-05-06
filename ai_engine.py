#!/usr/bin/env python3
"""
BrowserForensix — ai_engine.py
OpenRouter AI integration. Provides forensic intelligence across all pages.

Architecture:
  - All AI calls go through OpenRouter (https://openrouter.ai/api/v1)
  - Model: meta-llama/llama-3.3-70b-instruct  (fast, cheap, forensics-capable)
  - Fallback: mistralai/mistral-7b-instruct    (if primary is unavailable)
  - Each function receives pre-structured data from analysis.json
  - Returns structured dicts so serve.py routes can JSON-encode them directly
  - Streaming supported on /api/ai/stream/* endpoints

Environment:
  OPENROUTER_API_KEY  — required. Set in .env or environment.
  OPENROUTER_MODEL    — optional override.
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Generator, Optional

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass

# ── Config ────────────────────────────────────────────────────────────────────

OPENROUTER_BASE   = "https://openrouter.ai/api/v1"
PRIMARY_MODEL     = os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct")
FALLBACK_MODEL    = "mistralai/mistral-7b-instruct"
APP_URL           = "http://localhost:5000"
APP_NAME          = "BrowserForensix"

# Load .env if present
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

def _api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        raise EnvironmentError(
            "OPENROUTER_API_KEY not set. Add it to your .env file or environment:\n"
            "  OPENROUTER_API_KEY=sk-or-..."
        )
    return key

# ── Low-level HTTP (no external deps beyond stdlib) ───────────────────────────

def _post(payload: dict, stream: bool = False, model: str = PRIMARY_MODEL) -> dict | Generator:
    """
    POST to OpenRouter. Uses stdlib urllib so no `requests` dependency.
    Returns parsed JSON dict (non-stream) or line generator (stream).
    """
    payload = {**payload, "model": model}
    body = json.dumps(payload).encode()

    req = urllib.request.Request(
        f"{OPENROUTER_BASE}/chat/completions",
        data=body,
        headers={
            "Authorization":   f"Bearer {_api_key()}",
            "Content-Type":    "application/json",
            "HTTP-Referer":    APP_URL,
            "X-Title":         APP_NAME,
        },
        method="POST",
    )

    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")
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
# FEATURE 1: Overview — Executive AI Summary
# Used by: /api/ai/summary
# Shows on: Overview page, right-hand panel
# ══════════════════════════════════════════════════════════════════════════════

def ai_executive_summary(analysis: dict) -> dict:
    """
    Generate a plain-English forensic executive summary of the entire profile.
    Covers: top risk findings, behavioral patterns, recommended next steps.
    """
    summary  = analysis.get("summary", {})
    anomalies = analysis.get("anomalies", [])[:10]
    top_domains = analysis.get("top_domains", [])[:15]
    flagged_history  = [h for h in analysis.get("history",  []) if h.get("risk_score", 0) >= 61][:10]
    flagged_downloads = [d for d in analysis.get("downloads", []) if d.get("risk_score", 0) >= 61][:5]

    user_prompt = f"""Analyze this browser forensic data and produce an executive summary.

ARTIFACT COUNTS:
{json.dumps(summary, indent=2)}

TOP ANOMALIES DETECTED:
{json.dumps([{"type": a["type"], "title": a["title"], "description": a["description"]} for a in anomalies], indent=2)}

TOP DOMAINS BY VISITS:
{json.dumps([{"domain": d["domain"], "visits": d["visits"], "risk_score": d["risk_score"]} for d in top_domains], indent=2)}

FLAGGED HISTORY ITEMS (risk ≥ 61):
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
# FEATURE 2: History — AI Risk Explainer
# Used by: /api/ai/explain/history/<url_hash>
# Shows on: History page, expand row
# ══════════════════════════════════════════════════════════════════════════════

def ai_explain_history_item(item: dict, context_items: list) -> dict:
    """
    Explain why a specific history item is risky and what it suggests forensically.
    Context items = other visits to the same domain for pattern recognition.
    """
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
# FEATURE 3: Investigate — AI Domain Profile
# Used by: /api/ai/domain/<domain>
# Shows on: Investigate page, Domain Inspector panel
# ══════════════════════════════════════════════════════════════════════════════

def ai_domain_profile(domain: str, domain_data: dict) -> dict:
    """
    Deep-dive analysis of a specific domain — what it is, why it matters,
    what the visit/cookie/download pattern reveals.
    """
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
# FEATURE 4: Investigate — AI Session Narrative (streaming)
# Used by: /api/ai/stream/session
# Shows on: Investigate > Session Viewer
# ══════════════════════════════════════════════════════════════════════════════

def ai_session_narrative_stream(session: dict) -> Generator:
    """
    Streaming narrative description of a reconstructed browsing session.
    Tells the story of what the user was doing during that session.
    """
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
# FEATURE 5: Downloads — AI Threat Assessment
# Used by: /api/ai/explain/download
# Shows on: Downloads page, per-row expand
# ══════════════════════════════════════════════════════════════════════════════

def ai_download_threat(download: dict, all_downloads: list) -> dict:
    """
    Assess a specific download's threat level — what the file likely is,
    whether the source is credible, and what the pattern suggests.
    """
    # Find other downloads from same domain for pattern context
    src_domain = download.get("source_url", "")
    related = [d for d in all_downloads
               if d.get("source_url","") != download.get("source_url","")
               and any(p in d.get("source_url","") for p in src_domain.split(".")[-2:])][:3]

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
# FEATURE 6: Investigate — Cleared History AI Analysis
# Used by: /api/ai/gap-analysis
# Shows on: Investigate > Cleared History Detector
# ══════════════════════════════════════════════════════════════════════════════

def ai_gap_analysis(gap_anomaly: dict, top_cookie_domains: list) -> dict:
    """
    Analyze the pattern of history clearing — when it happened, what survived,
    and what that tells us about intent.
    """
    user_prompt = f"""A browser forensic tool detected history clearing. Analyze the pattern:

GAP ANOMALY:
{json.dumps(gap_anomaly, indent=2)}

DOMAINS WITH COOKIES BUT NO HISTORY (top 15):
{json.dumps(top_cookie_domains[:15], indent=2)}

Answer:
1. What does this pattern of surviving cookies suggest about WHEN history was cleared?
2. Do the surviving cookie domains suggest a specific activity that was being concealed?
3. What was likely being hidden? (be direct — if it looks like personal browsing, say so; if it looks like data exfiltration, say so)
4. What forensic steps should be taken to recover deleted history?
"""
    content = _chat(_FORENSIC_SYSTEM, user_prompt, max_tokens=500)
    return {"analysis": content, "model": PRIMARY_MODEL}


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 7: Report — AI Narrative Report (streaming)
# Used by: /api/ai/stream/report
# Shows on: Report page, alongside the structured .txt report
# ══════════════════════════════════════════════════════════════════════════════

def ai_narrative_report_stream(report_data: dict, case_meta: dict) -> Generator:
    """
    Stream a full narrative forensic report — professional prose suitable
    for inclusion in a case file.
    """
    flagged = report_data.get("flagged", {})
    anomalies = report_data.get("anomalies", [])
    summary = report_data.get("summary", {})
    meta = report_data.get("meta", {})

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
# FEATURE 8: Anomaly — AI Anomaly Deep Dive
# Used by: /api/ai/anomaly
# Shows on: Overview anomaly list, expand per anomaly
# ══════════════════════════════════════════════════════════════════════════════

def ai_anomaly_deep_dive(anomaly: dict, related_history: list, related_cookies: list) -> dict:
    """
    Deep-dive a single anomaly — explain what it means, what caused it,
    and how serious it is in context.
    """
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
# FEATURE 9: AI Chat — Freeform Q&A about the evidence
# Used by: /api/ai/stream/chat
# Shows on: Dedicated AI Chat panel (new page: /ai)
# ══════════════════════════════════════════════════════════════════════════════

def ai_chat_stream(user_message: str, conversation_history: list, analysis_snapshot: dict) -> Generator:
    """
    Freeform forensic Q&A. The analyst can ask any question about the evidence.
    Full conversation history is passed for multi-turn coherence.
    analysis_snapshot = lightweight summary of key findings (not full data).
    """
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
    for turn in conversation_history[-8:]:  # last 8 turns for context window
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
        _api_key()  # raises if missing
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