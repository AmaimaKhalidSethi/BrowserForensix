# BrowserForensix CTF Challenge Writeup

## Introduction

BrowserForensix ships with a built-in Capture The Flag (CTF) challenge designed to sharpen your browser forensics skills. The challenge simulates a realistic investigation scenario: you are given a set of browser artifacts and must analyze them to uncover hidden flags, reconstruct user activity, and identify suspicious behavior.

This document serves as a **strategy guide and walkthrough template** — it will help you approach the challenges methodically without spoiling specific flag values. Use it as a companion while working through the CTF, and fill in your own findings as you go.

> **Note:** This writeup intentionally omits specific flag values. Discovering them is the challenge. If you are writing up your own solutions, fork this document and add your flags and evidence inline.

---

## Setup

Getting the CTF environment running requires two steps:

### Step 1 — Extract Browser Artifacts

Run the extraction script to parse and prepare the browser forensic data:

```bash
python extract.py
```

This script processes raw browser artifacts (history databases, cookie stores, download records, local storage, etc.) and outputs structured data files into the `data/` directory.

### Step 2 — Launch the Web Interface

Start the BrowserForensix analysis server:

```bash
python serve.py
```

The web interface will be available at `http://127.0.0.1:5000` by default. Open it in your browser to begin your investigation.

> **⚠️ Reminder:** The Flask development server is intended for local use only. Do not expose it to a network.

---

## General Strategy

The CTF challenges span multiple forensic artifact categories. Below is a structured approach to each.

### 1. Browsing History Analysis

The browsing history is your primary timeline of user activity. Focus on:

- **Suspicious URLs** — Look for URLs that stand out: unusual domains, IP addresses instead of hostnames, non-standard ports, data URIs, or paths containing encoded payloads.
- **Timing gaps** — Identify periods where browsing activity suddenly stops and resumes. These gaps may indicate private/incognito sessions, artifact deletion, or system downtime — all of which are investigatively significant.
- **Visit frequency** — Pages visited repeatedly in a short window may indicate data exfiltration staging, credential harvesting, or automated activity.
- **Referrer chains** — Trace how the user navigated between sites. Unexpected referrer relationships can reveal phishing redirects or watering-hole attacks.

### 2. Cookie Analysis

Cookies reveal tracking relationships, authentication state, and sometimes hidden data:

- **Tracking domains** — Identify third-party cookies from known advertising and analytics networks. An unusual volume or the presence of uncommon trackers may be relevant.
- **Ghost cookies** — These are cookies present in the cookie store that have **no corresponding entry in the browsing history**. Their existence suggests the user visited a site that was later scrubbed from history, or that cookies were planted programmatically.
- **Cookie values** — Examine cookie values for Base64-encoded data, JSON blobs, or suspiciously long opaque strings that may contain embedded information.
- **Expiration dates** — Cookies with unusually long expiration times or dates set far in the past can indicate persistence mechanisms or manipulation.

### 3. Download Analysis

The download record connects files on disk to their network origins:

- **Dangerous file types** — Flag downloads of executables (`.exe`, `.msi`, `.bat`, `.ps1`, `.sh`), archives (`.zip`, `.rar`, `.7z`), disk images (`.iso`, `.dmg`), and Office documents with macros (`.docm`, `.xlsm`).
- **Missing files** — Cross-reference the download path with the filesystem. A recorded download whose file no longer exists may indicate post-download cleanup — a common anti-forensics technique.
- **Source URLs** — Trace where downloaded files came from. Files downloaded from temporary file-sharing services, paste sites, or raw IP addresses are high-priority leads.
- **Download timing** — Correlate download timestamps with browsing history to reconstruct the full acquisition chain.

### 4. AI-Powered Analysis

BrowserForensix includes AI features that can accelerate your investigation:

- **Automated anomaly detection** — Use the AI analysis tools to scan for statistical outliers across all artifact categories. The AI can surface patterns that are difficult to spot manually in large datasets.
- **Deep-dive reports** — Trigger AI-generated deep-dives on specific artifacts or time ranges to get a narrative summary of what occurred.
- **Cross-artifact correlation** — The AI can identify connections between a suspicious cookie, a related history entry, and a contemporaneous download that you might miss when examining each category in isolation.

### 5. Local Storage Inspection

Browser local storage (`localStorage` and `sessionStorage`) can contain application state, cached data, and sometimes sensitive information:

- **Encoded values** — Look for Base64, hex-encoded, or URL-encoded strings stored as values. Decode them to reveal hidden content.
- **Suspicious keys** — Key names referencing tokens, sessions, flags, or debug data are worth investigating.
- **Large values** — Unusually large storage entries may contain exfiltrated data, cached credentials, or embedded files.
- **Cross-origin data** — Note which origins have local storage entries and whether any of them correspond to suspicious domains identified in other artifact categories.

### 6. Timeline Reconstruction

The timeline view aggregates events from all artifact sources into a single chronological stream:

- **Session reconstruction** — Group events into browsing sessions by identifying natural start/stop boundaries. Look for what the user did at the beginning and end of each session.
- **Temporal clustering** — Multiple artifact types (history, cookies, downloads) generating events in a tight time window often indicate a single coordinated action.
- **Chronological anomalies** — Events that appear out of logical order (e.g., a cookie created before its corresponding history entry) may indicate timestamp manipulation or artifact planting.

### 7. Relationship Graph

The relationship graph visualizes connections between domains, URLs, and artifacts:

- **Connected clusters** — Identify groups of domains that are linked through referrers, shared cookies, or download chains. Isolated clusters disconnected from the user's normal browsing pattern are investigatively interesting.
- **Central nodes** — Domains with a high number of connections (high degree centrality) may be command-and-control servers, tracking hubs, or pivot points in an attack chain.
- **Unexpected edges** — Connections between domains that have no obvious legitimate relationship warrant deeper investigation.

---

## Investigation Workflow

For a systematic approach, follow this workflow:

```
1.  Start with the TIMELINE to get a high-level overview of activity.
2.  Identify suspicious TIME RANGES or anomalies.
3.  Drill into HISTORY for those time ranges.
4.  Cross-reference with COOKIES (look for ghost cookies).
5.  Check DOWNLOADS for associated file transfers.
6.  Inspect LOCAL STORAGE for hidden or encoded data.
7.  Use the RELATIONSHIP GRAPH to map connected domains.
8.  Run AI ANALYSIS for automated deep-dives on flagged items.
9.  Document findings and capture flags.
```

---

## Tips

- **Take notes as you go.** Record timestamps, URLs, and artifact IDs for every lead. Forensic investigations are iterative — you will revisit earlier findings.
- **Decode everything.** If a value looks like Base64, hex, or any other encoding, decode it. Flags and hidden data are often encoded rather than encrypted.
- **Think like an attacker.** Consider what an adversary would do to cover their tracks, and look for the forensic traces those actions leave behind.
- **Use multiple artifact types.** A single artifact in isolation may look benign. The same artifact cross-referenced with two others may reveal a clear pattern of malicious activity.
- **Don't ignore metadata.** File sizes, timestamps, HTTP response codes, and MIME types all carry investigative value.

---

## Further Investigation Techniques

Once you have completed the CTF challenges, consider these advanced techniques to deepen your forensic analysis skills:

- **SQLite forensics** — Open the raw browser databases directly with a SQLite browser. Deleted records may still be recoverable from unallocated pages or the WAL (Write-Ahead Log) file.
- **LevelDB analysis** — Chrome's local storage uses LevelDB. Tools like `leveldb-dump` can reveal deleted or compacted entries not visible through the standard API.
- **Cache analysis** — Browser cache files can contain full copies of visited web pages, images, and scripts. Reconstruct cached pages to see exactly what the user saw.
- **Session restore files** — Browsers maintain session restore data that can reveal tabs and windows from prior sessions, even if history was cleared.
- **Memory forensics** — If a memory dump is available, browser process memory may contain decrypted credentials, session tokens, and DOM snapshots.
- **Network log correlation** — If network captures (PCAP files) are available, correlate them with browser artifacts to validate timestamps and identify activity not recorded by the browser.

---

*Good luck, and happy hunting.* 🔍
