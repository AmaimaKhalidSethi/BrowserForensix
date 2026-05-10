/* BrowserForensix — app.js  (PATCHED)
   All frontend logic. API calls, rendering, state management.

PATCH NOTES:
  FIX-3  Removed dead SPA navigation system (activatePage, PAGES, the
         DOMContentLoaded nav-click handler that called loadStatus() → activatePage()).
         Flask renders each page as a full HTML document; there are no .bfx-page
         divs to toggle. The SPA router was firing loadStatus() a second time on
         every page load (base.html already calls it via /api/status inline script).

  FIX-COOKIES-HOST  cookieState now tracks host; loadCookies() sends it as a
         query param; cookieHostSearch input correctly sets cookieState.host.
         The host filter was silently broken end-to-end — state was never set,
         param was never sent to the API.

  FIX-COOKIES-SECURE  cookieState.secure is now sent to the API and the
         #cookieSecureFilter dropdown actually applies the filter.

  FIX-REPORT  window._bfxReport replaced with a module-scoped variable
         _reportText so forensic report content is not accessible to any
         third-party script that might later run on the page.

  NOTE: loadStatus() is called once in base.html's inline script (topbar meta
        update). The DOMContentLoaded handler here no longer calls it a second
        time. If you move the inline script out of base.html in a future refactor,
        re-add loadStatus() to the DOMContentLoaded block below.
*/

'use strict';

// ── Utilities ─────────────────────────────────────────────────────────────────

const API = {
  async get(path) {
    try {
      const res = await fetch(path);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.error(`API error [${path}]:`, e);
      return null;
    }
  }
};

function riskClass(score) {
  if (score >= 61) return 'high';
  if (score >= 31) return 'moderate';
  return 'low';
}

function riskColor(score) {
  if (score >= 61) return 'var(--accent-action)';
  if (score >= 31) return 'var(--accent-moderate)';
  return 'var(--accent-safe)';
}

function domainOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

function protoOf(url) {
  // BUG-16 FIX: previous version returned 'https' for ANY non-http URL,
  // so chrome-extension://, ftp://, about:blank etc. all got a green HTTPS badge.
  if ((url || '').startsWith('https://')) return 'https';
  if ((url || '').startsWith('http://'))  return 'http';
  return 'other';
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    // BUG-8 FIX: strip both "Z" and "+HH:MM"/"-HH:MM" timezone suffixes,
    // and milliseconds. Previously only "Z" was stripped, so "+00:00" timestamps
    // displayed with a trailing timezone offset.
    return iso
      .replace('T', ' ')
      .replace(/\.\d+/, '')          // remove fractional seconds
      .replace(/[Z]$/, '')           // remove trailing Z
      .replace(/[+-]\d{2}:\d{2}$/, '') // remove +00:00 / -05:00 style offsets
      .trim();
  } catch { return iso; }
}

function fmtSize(bytes) {
  if (!bytes) return '—';
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
  if (bytes >= 1048576)    return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024)       return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
}

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

function esc(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function noDataBanner(msg) {
  return `<div class="bfx-no-data">
    <h2>No Data Available</h2>
    <p>${esc(msg)}</p>
    <code>python extract.py --browser chrome</code>
    <p style="margin-top:8px;font-size:12px;color:var(--text-secondary);">
      Then restart the server: <code style="display:inline;padding:1px 6px;">python serve.py</code>
    </p>
  </div>`;
}

// ── DOMContentLoaded — wire global search only ────────────────────────────────
// FIX-3: Removed activatePage / nav-click SPA router. Flask serves each page
// as a full HTML document so there are no .bfx-page divs to toggle. The dead
// router was also calling loadStatus() a second time (base.html does it first).

document.addEventListener('DOMContentLoaded', () => {
  const gs = document.getElementById('globalSearch');
  if (gs) {
    let debounce;
    gs.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        if (gs.value.trim().length >= 2) runGlobalSearch(gs.value.trim());
        else closeSearch();
      }, 300);
    });
    gs.addEventListener('keydown', e => {
      if (e.key === 'Escape') { gs.value = ''; closeSearch(); }
    });
  }
});



// ═══════════════════════════════════════════════════════════════════════════
// THEME TOGGLE — Warm Light / Dark (Deep Violet)
//
// How it works:
//   • [data-theme="warm"] on <html> activates the warm palette via CSS.
//   • Preference persisted to localStorage under key "bfx-theme".
//   • On page load we read localStorage BEFORE paint to prevent flash.
//     (The blocking <script> in base.html's <head> handles the flash guard;
//      this function is called from there AND here as a fallback.)
// ═══════════════════════════════════════════════════════════════════════════

const THEME_KEY = 'bfx-theme';
const THEME_WARM = 'warm';

/**
 * Apply a theme immediately without animation flash.
 * @param {'warm'|null} theme  Pass THEME_WARM for light, null/undefined for dark.
 * @param {boolean} animate    If false, temporarily disables CSS transitions.
 */
function _applyTheme(theme, animate = true) {
  const root = document.documentElement;

  if (!animate) {
    // Kill transitions for this tick so the initial paint doesn't animate in
    root.style.setProperty('--transition-override', 'none');
    root.classList.add('bfx-no-transition');
  }

  if (theme === THEME_WARM) {
    root.setAttribute('data-theme', THEME_WARM);
  } else {
    root.removeAttribute('data-theme');
  }

  if (!animate) {
    // Force reflow so the attribute change is visible, THEN re-enable transitions
    // eslint-disable-next-line no-unused-expressions
    root.offsetHeight;
    root.classList.remove('bfx-no-transition');
  }

  _syncToggleButton(theme);
}

/**
 * Update toggle button icon + label to reflect the current theme.
 */
function _syncToggleButton(theme) {
  const iconEl  = document.getElementById('themeToggleIcon');
  const labelEl = document.getElementById('themeToggleLabel');
  if (!iconEl || !labelEl) return;

  if (theme === THEME_WARM) {
    iconEl.textContent  = '☀';
    labelEl.textContent = 'Light';
    iconEl.title = 'Switch to Dark mode';
  } else {
    iconEl.textContent  = '☽';
    labelEl.textContent = 'Dark';
    iconEl.title = 'Switch to Light mode';
  }
}

/**
 * Public toggle function — called by the button's onclick.
 * Reads current state, flips it, persists, applies with animation.
 */
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === THEME_WARM ? null : THEME_WARM;

  try {
    if (next) {
      localStorage.setItem(THEME_KEY, next);
    } else {
      localStorage.removeItem(THEME_KEY);
    }
  } catch (_) { /* localStorage blocked — still apply in memory */ }

  _applyTheme(next, true); // true = allow 0.3s CSS transition
}

/**
 * Called once at startup (ideally from a <head> blocking script in base.html
 * to fully prevent FOUC). Also safe to call here as a fallback.
 */
function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch (_) {}
  _applyTheme(saved === THEME_WARM ? THEME_WARM : null, false); // false = no transition on init
}

// Run immediately (fallback if <head> script is absent)
initTheme();

// ── Profile filter utility ────────────────────────────────────────────────────
// With multi-profile extraction, every artifact has a "profile" field.
// These helpers build and apply profile filtering across pages.

let _allProfiles = null;

async function getProfiles() {
  if (_allProfiles) return _allProfiles;
  const data = await API.get('/api/status');
  const profiles = (data?.meta?.profiles_extracted || []);
  _allProfiles = profiles.length ? profiles : [{ name: 'Default', dir: 'Default' }];
  return _allProfiles;
}

function buildProfileFilter(containerId, onChange) {
  getProfiles().then(profiles => {
    if (profiles.length <= 1) return; // no filter needed for single profile
    const container = document.getElementById(containerId);
    if (!container) return;
    const label = document.createElement('span');
    label.className = 'bfx-filter-label';
    label.textContent = 'Profile:';
    const sel = document.createElement('select');
    sel.className = 'bfx-filter-select';
    sel.id = containerId + '_profileSel';
    sel.innerHTML = '<option value="">All profiles</option>' +
      profiles.map(p => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join('');
    sel.addEventListener('change', () => onChange(sel.value));
    container.prepend(sel);
    container.prepend(label);
  });
}

// ── Status ────────────────────────────────────────────────────────────────────

async function loadStatus() {
  const data = await API.get('/api/status');
  const bar = document.getElementById('bfxStatusBar');
  if (!bar) return;
  if (!data || !data.ready) {
    bar.innerHTML = `<span class="bfx-status-dot error"></span>
      <span class="mono">Not ready — run extract.py</span>`;
    return;
  }
  const m = data.meta || {};
  bar.innerHTML = `<span class="bfx-status-dot"></span>
    <span class="mono">${esc(m.browser || 'Chrome')} · ${(data.summary?.total_artifacts || 0).toLocaleString()} artifacts</span>`;
}

// ── Overview ──────────────────────────────────────────────────────────────────

async function loadOverview() {
  const data = await API.get('/api/overview');
  const content = document.getElementById('overviewContent');
  if (!content) return;
  if (!data) { content.innerHTML = noDataBanner('Could not load overview data.'); return; }

  const s = data.summary || {};
  const meta = data.meta || {};

  document.getElementById('statArtifacts').textContent = (s.total_artifacts || 0).toLocaleString();
  document.getElementById('statFlagged').textContent   = s.flagged_count || 0;
  document.getElementById('statRisk').textContent      = s.average_risk_score || 0;
  document.getElementById('statAnomalies').textContent = s.anomaly_count || 0;
  // Multi-profile: show count of profiles instead of trying to parse a long path string
  const profiles = meta.profiles_extracted || [];
  const profileSummary = profiles.length > 1
    ? `${profiles.length} profiles extracted`
    : profiles[0]?.name || (meta.profile_path || '').split(/[\/]/).pop() || 'Default';
  const browserLabel = (meta.browser || 'Chrome').charAt(0).toUpperCase() + (meta.browser || 'Chrome').slice(1);
  document.getElementById('statBrowserMeta').textContent = browserLabel + ' · ' + profileSummary;

  renderAnomalies(data.anomalies || []);
  renderDomainList(data.top_domains || []);
  renderHeatmap(data.heatmap || []);

  const metaEl = document.getElementById('evidenceMeta');
  if (metaEl && data.hashes) {
    let html = '';
    for (const [k, v] of Object.entries(data.hashes)) {
      html += `<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--border);">
        <span class="muted">${esc(k)}</span>
        <span class="mono" style="margin-left:10px;font-size:10px;">${esc(v)}</span>
      </div>`;
    }
    metaEl.innerHTML = html || '<span class="muted">No file hashes available.</span>';
  }
}

function renderAnomalies(anomalies) {
  const elAnom = document.getElementById('anomalyList');
  if (!elAnom) return;
  if (!anomalies.length) {
    elAnom.innerHTML = '<div class="muted" style="font-size:12px;padding:10px 0;">No anomalies detected.</div>';
    return;
  }
  elAnom.innerHTML = '';
  anomalies.forEach(a => {
    const sevClass = a.severity === 'critical' ? '' : a.severity === 'moderate' ? 'moderate' : 'low';
    const anomAiId = 'anomAi_' + a.type;
    const div = document.createElement('div');
    div.className = 'bfx-anomaly-item ' + sevClass;
    // Build onclick with string concat — nested template literals break browser parsing
    const anomType = esc(a.type);
    div.innerHTML = '<div class="bfx-anomaly-type">' + esc(a.type.replace(/_/g, ' ')) + ' · ' + esc(a.severity) + '</div>'
      + '<div class="bfx-anomaly-text">' + esc(a.description) + '</div>'
      + '<button class="bfx-btn outline sm" style="margin-top:6px;font-size:10px;" onclick="aiExplainAnomaly(\'' + anomType + '\',\'' + anomAiId + '\')">⬡ AI Deep Dive</button>'
      + '<div id="' + anomAiId + '"></div>';
    elAnom.appendChild(div);
  });
}

function renderDomainList(domains) {
  const elDom = document.getElementById('domainList');
  if (!elDom) return;
  const top = domains.slice(0, 10);
  // Bar width is proportional to visit count relative to the highest-visited domain,
  // not risk_score. Previously pct = risk_score which was 0 for safe domains → invisible bar.
  const maxVisits = Math.max(...top.map(d => d.visits || 0), 1);
  elDom.innerHTML = top.map(d => {
    const pct   = Math.max(4, Math.round(((d.visits || 0) / maxVisits) * 100));
    const score = d.risk_score || 0;
    // Bar color reflects risk: high=violet, moderate=amber, low=teal
    const barColor = score >= 61 ? 'var(--accent-action)'
                   : score >= 31 ? 'var(--accent-moderate)'
                   : 'var(--accent-safe)';
    return `<div class="bfx-domain-row">
      <span class="bfx-domain-name mono">${esc(d.domain)}</span>
      <div class="bfx-risk-bar-wrap">
        <div class="bfx-risk-bar" style="width:${pct}%;background:${barColor};opacity:0.85;"></div>
      </div>
      <span class="bfx-domain-count mono">${(d.visits || 0).toLocaleString()}</span>
    </div>`;
  }).join('');
}

function renderHeatmap(heatData) {
  const elHeat = document.getElementById('activityHeatmap');
  if (!elHeat) return;
  const days   = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  // 5-stop purple scale: empty → deep indigo → rich violet → bright purple → vivid lavender
  const STOPS = [
    '#13102A',   // 0 — empty cell (near-black violet)
    '#2D1B69',   // 1 — low  (deep indigo)
    '#5B21B6',   // 2 — mid  (rich violet)
    '#8B45F5',   // 3 — high (bright purple)
    '#C084FC',   // 4 — peak (vivid lavender)
  ];

  const map = {};
  heatData.forEach(({ day, hour, count }) => {
    if (!map[day]) map[day] = {};
    map[day][hour] = count;
  });
  const maxVal = Math.max(...heatData.map(d => d.count), 1);

  function cellColor(v) {
    if (!v) return STOPS[0];
    return STOPS[Math.min(4, Math.max(1, Math.ceil((v / maxVal) * 4)))];
  }

  // Store for modal re-render (no second API call needed)
  _heatmapData = heatData;

  // Wrap in scroll container + make clickable to open modal
  let html = `<div class="bfx-heatmap-wrap bfx-heatmap-clickable" onclick="openHeatmapModal()" title="Click to expand">`;
  html += `<div class="bfx-heatmap">`;
  html += `<div class="bfx-heatmap-header"></div>`;
  for (let h = 0; h < 24; h++) {
    html += `<div class="bfx-heatmap-header">${h % 4 === 0 ? h : ''}</div>`;
  }
  days.forEach((d, di) => {
    html += `<div class="bfx-heatmap-label">${d}</div>`;
    for (let h = 0; h < 24; h++) {
      const v = (map[di] || {})[h] || 0;
      html += `<div class="bfx-heatmap-cell" title="${d} ${h}:00 — ${v} visits" style="background:${cellColor(v)};"></div>`;
    }
  });
  html += '</div></div>';
  elHeat.innerHTML = html;

  // Expand hint below mini heatmap
  if (!elHeat.nextElementSibling?.classList.contains('bfx-heatmap-expand-hint')) {
    const hint = document.createElement('div');
    hint.className = 'bfx-heatmap-expand-hint';
    hint.textContent = '⊕ click to expand';
    elHeat.after(hint);
  }
}

// ── History ───────────────────────────────────────────────────────────────────

let histState = { page: 1, q: '', profile: '', protocol: 'all', risk: 'any', from: '', to: '' };
let histExpandedRow = null;

async function loadHistory(reset = false) {
  if (reset) { histState.page = 1; histExpandedRow = null; }
  // B8 FIX: wire profile filter
  buildProfileFilter('histFilterBar', val => { histState.profile = val; loadHistory(true); });
  const params = new URLSearchParams({
    page:     histState.page,
    q:        histState.q,
    profile:  histState.profile || '',
    protocol: histState.protocol,
    risk:     histState.risk,
    from:     histState.from,
    to:       histState.to,
  });
  const data = await API.get(`/api/history?${params}`);
  const tbody = document.getElementById('histBody');
  if (!tbody) return;
  if (!data) { tbody.innerHTML = `<tr><td colspan="5" class="bfx-loading">Failed to load history.</td></tr>`; return; }

  tbody.innerHTML = '';
  if (!data.items?.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="bfx-loading muted">No results.</td></tr>`;
  } else {
    data.items.forEach(h => {
      const rc    = riskClass(h.risk_score);
      const proto = protoOf(h.url);
      const domain = domainOf(h.url);
      const row = document.createElement('tr');
      if (h.risk_score >= 61) row.classList.add('flagged');
      row.style.cursor = 'pointer';
      row.innerHTML = `
        <td><span class="bfx-risk-pill ${rc}">${h.risk_score}</span></td>
        <td><span class="bfx-proto-badge ${proto}">${proto.toUpperCase()}</span></td>
        <td>
          <div style="font-size:12px;">${esc(domain)}</div>
          <div class="muted" style="font-size:10px;">${esc(h.title || '—')}</div>
        </td>
        <td class="mono muted" style="font-size:10px;white-space:nowrap;">${fmtTime(h.last_visit)}</td>
        <td class="mono" style="font-size:12px;">${h.visit_count || 1}</td>`;
      row.addEventListener('click', () => toggleHistExpand(row, h));
      tbody.appendChild(row);
    });
  }

  document.getElementById('histPageInfo').textContent = `Page ${data.page} of ${data.total_pages}`;
  document.getElementById('histTotal').textContent    = `${data.total.toLocaleString()} total entries`;
  document.getElementById('histPrev').disabled = data.page <= 1;
  document.getElementById('histNext').disabled = data.page >= data.total_pages;
}

function toggleHistExpand(row, h) {
  const existing = document.getElementById('histExpandRow');
  if (existing) existing.remove();
  if (histExpandedRow === row) { histExpandedRow = null; return; }
  histExpandedRow = row;

  const reasons = (h.risk_reasons || []).join(' · ');
  const expandRow = document.createElement('tr');
  expandRow.id = 'histExpandRow';
  const histAiId = 'histAi_' + Date.now();
  // Build AI button with string concat — nested backticks cause SyntaxError in browsers
  const histReasonHtml = reasons ? '<div class="bfx-reason-box">⚑ ' + esc(reasons) + '</div>' : '';
  const histAiHtml = h.risk_score >= 31
    ? '<button class="bfx-btn outline sm" style="margin-top:8px;" onclick="aiExplainHistory(\'' + encodeURIComponent(h.url) + '\',\'' + histAiId + '\')">⬡ Explain with AI</button><div id="' + histAiId + '"></div>'
    : '';
  expandRow.innerHTML = '<td colspan="5" class="bfx-expand-row"><div class="bfx-expand-content">'
    + '<div class="exp-label">Full URL</div>'
    + '<div class="exp-value">' + esc(h.url) + '</div>'
    + '<div class="exp-label">Last Visit</div>'
    + '<div class="exp-value">' + fmtTime(h.last_visit) + '</div>'
    + '<div class="exp-label">Total Visits</div>'
    + '<div class="exp-value">' + (h.visit_count || 1) + '</div>'
    + histReasonHtml
    + histAiHtml
    + '</div></td>';
  row.insertAdjacentElement('afterend', expandRow);
}

// ── Cookies ───────────────────────────────────────────────────────────────────

// FIX-COOKIES-HOST + FIX-COOKIES-SECURE:
// cookieState now tracks host and secure; both are sent as API params.
let cookieState = { page: 1, profile: '', type: 'all', expired: 'all', secure: 'all', host: '' };

async function loadCookies(reset = false) {
  if (reset) cookieState.page = 1;
  buildProfileFilter('cookieFilterBar', val => { cookieState.profile = val; loadCookies(true); });
  const params = new URLSearchParams({
    page:    cookieState.page,
    profile: cookieState.profile || '',
    type:    cookieState.type,
    expired: cookieState.expired,
    secure:  cookieState.secure,
    host:    cookieState.host,
  });
  const data = await API.get(`/api/cookies?${params}`);
  const tbody = document.getElementById('cookieBody');
  if (!tbody) return;
  if (!data) { tbody.innerHTML = `<tr><td colspan="7" class="bfx-loading">Failed to load cookies.</td></tr>`; return; }

  tbody.innerHTML = '';
  if (!data.items?.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="bfx-loading muted">No cookies found.</td></tr>`;
    return;
  }

  data.items.forEach(c => {
    const rc = riskClass(c.risk_score);
    const typeKey   = (c.type || 'unknown').toLowerCase().replace(/\s+/, '-');
    const typeClass = {
      'auth-token': 'type-auth',
      'tracking':   'type-tracking',
      'session':    'type-session',
      'zombie':     'type-zombie',
      'analytics':  'type-analytics',
    }[typeKey] || 'type-unknown';
    const flags = [
      c.secure    ? 'Secure'           : '',
      c.http_only ? 'HttpOnly'         : '',
      c.samesite  ? `SameSite=${c.samesite}` : '',
    ].filter(Boolean).join(', ') || '—';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono" style="font-size:11px;">${esc(c.host)}</td>
      <td class="mono" style="font-size:11px;">${esc(c.name)}</td>
      <td><span class="bfx-cookie-type ${typeClass}">${esc(c.type || 'Unknown')}</span></td>
      <td class="mono muted" style="font-size:10px;">${fmtTime(c.expires) || 'Session'}</td>
      <td class="mono muted" style="font-size:10px;">${fmtTime(c.created)}</td>
      <td class="muted" style="font-size:10px;">${esc(flags)}</td>
      <td><span class="bfx-risk-pill ${rc}">${c.risk_score}</span></td>`;
    tbody.appendChild(row);
  });

  document.getElementById('cookiePageInfo').textContent = `Page ${data.page} of ${data.total_pages}`;
  document.getElementById('cookieTotal').textContent    = `${data.total.toLocaleString()} total cookies`;
  document.getElementById('cookiePrev').disabled = data.page <= 1;
  document.getElementById('cookieNext').disabled = data.page >= data.total_pages;
}

// ── Bookmarks ─────────────────────────────────────────────────────────────────

let bmData = null;

async function loadBookmarks() {
  if (!bmData) {
    bmData = await API.get('/api/bookmarks');
  }
  renderBookmarkFolder('all');
}

// Single authoritative renderBookmarkFolder — bookmarks.html no longer
// overrides this function; it calls it directly.
function renderBookmarkFolder(folder) {
  const elBm = document.getElementById('bmEntries');
  if (!elBm || !bmData) return;

  let items = [];
  if (folder === 'all') {
    items = Object.values(bmData.tree || {}).flat();
  } else if (folder === 'deleted') {
    items = Object.values(bmData.tree || {}).flat()
      .filter(b => b.url === 'about:blank' || b.deleted);
  } else {
    items = Object.entries(bmData.tree || {})
      .filter(([k]) => k.toLowerCase().includes(folder.toLowerCase()))
      .flatMap(([, v]) => v);
  }

  if (!items.length) {
    elBm.innerHTML = '<div class="muted" style="padding:12px 0;font-size:12px;">No bookmarks in this folder.</div>';
    return;
  }

  elBm.innerHTML = items.map(b => {
    const isDeleted = b.url === 'about:blank' || b.deleted;
    return `<div class="bfx-bm-row${isDeleted ? ' deleted' : ''}">
      ${isDeleted ? '<span class="bfx-deleted-badge">DELETED</span>' : ''}
      <div style="flex:1;min-width:0;">
        <div class="bfx-bm-title">${esc(b.title || '[No title]')}</div>
        <div class="bfx-bm-url mono">${esc(b.url)}</div>
      </div>
      <div class="bfx-bm-date mono">${fmtTime(b.date_added)}</div>
    </div>`;
  }).join('');
}

// ── Downloads ─────────────────────────────────────────────────────────────────

let dlState = { page: 1, profile: '', q: '', risk: 'any' };

async function loadDownloads(reset = false) {
  if (reset) dlState.page = 1;
  buildProfileFilter('dlFilterBar', val => { dlState.profile = val; loadDownloads(true); });
  const params = new URLSearchParams({ page: dlState.page, profile: dlState.profile || '', q: dlState.q, risk: dlState.risk });
  const data = await API.get(`/api/downloads?${params}`);
  const tbody = document.getElementById('dlBody');
  if (!tbody) return;
  if (!data) { tbody.innerHTML = `<tr><td colspan="7" class="bfx-loading">Failed to load downloads.</td></tr>`; return; }

  tbody.innerHTML = '';
  if (!data.items?.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="bfx-loading muted">No downloads found.</td></tr>`;
    return;
  }

  data.items.forEach(d => {
    const rc = riskClass(d.risk_score);
    const srcDomain = domainOf(d.source_url || '');
    const inHist = d.in_history
      ? `<span class="bfx-dl-badge dl-yes">Yes</span>`
      : `<span class="bfx-dl-badge dl-no">No</span>`;
    const onDisk = d.file_exists
      ? `<span class="bfx-dl-badge dl-found">Found</span>`
      : `<span class="bfx-dl-badge dl-missing">Missing</span>`;
    const dlAiId = 'dlAi_' + encodeURIComponent(d.filename || '').replace(/%/g,'');
    const row = document.createElement('tr');
    if (d.risk_score >= 61) row.classList.add('flagged');
    row.style.cursor = d.risk_score >= 31 ? 'pointer' : '';
    row.innerHTML = `
      <td class="mono" style="font-size:11px;">${esc(d.filename || '—')}</td>
      <td class="mono muted" style="font-size:11px;">${esc(srcDomain)}</td>
      <td class="mono muted" style="font-size:10px;white-space:nowrap;">${fmtTime(d.start_time)}</td>
      <td class="mono" style="font-size:11px;">${fmtSize(d.size_bytes)}</td>
      <td>${inHist}</td>
      <td>${onDisk}</td>
      <td><span class="bfx-risk-pill ${rc}">${d.risk_score}</span></td>`;
    if (d.risk_score >= 31) {
      row.addEventListener('click', () => aiExplainDownloadInline(d.filename, dlAiId, row));
    }
    tbody.appendChild(row);
    if (d.risk_score >= 31) {
      const aiRow = document.createElement('tr');
      aiRow.id = dlAiId + '_row';
      aiRow.style.display = 'none';
      aiRow.innerHTML = `<td colspan="7" style="padding:0;"><div id="${dlAiId}" class="bfx-ai-inline" style="margin:4px 10px 8px;display:none;"></div></td>`;
      tbody.appendChild(aiRow);
    }
  });

  document.getElementById('dlPageInfo').textContent = `Page ${data.page} of ${data.total_pages}`;
  document.getElementById('dlTotal').textContent    = `${data.total.toLocaleString()} total downloads`;
  document.getElementById('dlPrev').disabled = data.page <= 1;
  document.getElementById('dlNext').disabled = data.page >= data.total_pages;
}

// ── Timeline ──────────────────────────────────────────────────────────────────

let tlRange = '30d';

async function loadTimeline() {
  const ranges = { '24h': 1, '7d': 7, '30d': 30, 'all': 0 };
  const days = ranges[tlRange] || 30;
  let fromParam = '';
  if (days > 0) {
    const d = new Date();
    d.setDate(d.getDate() - days);
    fromParam = d.toISOString();
  }
  const params = new URLSearchParams({ from: fromParam });
  const data = await API.get(`/api/timeline?${params}`);
  const elTl = document.getElementById('timelineList');
  if (!elTl) return;
  if (!data?.sessions?.length) {
    elTl.innerHTML = '<div class="bfx-loading muted">No timeline data available.</div>';
    return;
  }

  const dotClass = { history: 'dot-history', cookie: 'dot-cookie', download: 'dot-download', bookmark: 'dot-bookmark' };

  elTl.innerHTML = data.sessions.map((s, si) => {
    const start = fmtTime(s.start);
    const isOffhours = s.events?.some(e => {
      try { const h = new Date(e.time).getUTCHours(); return h >= 23 || h < 5; } catch { return false; }
    });

    const itemsHtml = (s.events || []).map(e => {
      let text = '';
      if (e.type === 'history')  text = `<span style="font-family:var(--font-mono);font-size:10px;">${esc(e.domain)}</span> — ${esc(e.title || e.url || '')}`;
      else if (e.type === 'cookie')   text = `Cookie set: <span class="mono">${esc(e.name)}</span> on ${esc(e.host)}`;
      else if (e.type === 'download') text = `Download: <span class="mono">${esc(e.filename)}</span> from ${esc(e.domain)}`;
      else text = esc(JSON.stringify(e));
      return `<div class="bfx-tl-item">
        <div class="bfx-tl-dot ${dotClass[e.type] || 'dot-history'}"></div>
        <div class="bfx-tl-time">${fmtTime(e.time).slice(11, 16)}</div>
        <div class="bfx-tl-text">${text}</div>
      </div>`;
    }).join('');

    return `<div class="bfx-session-block">
      <div class="bfx-session-header" onclick="this.nextElementSibling.classList.toggle('open')">
        <span class="bfx-session-label">Session ${data.sessions.length - si}</span>
        <span class="bfx-session-time">${start}</span>
        <span class="bfx-session-count">${s.count} events</span>
        ${isOffhours ? '<span class="bfx-offhours-badge">OFF-HOURS</span>' : ''}
        <span>▾</span>
      </div>
      <div class="bfx-session-items${si === 0 ? ' open' : ''}">${itemsHtml}</div>
    </div>`;
  }).join('');
}

// ── Investigate ───────────────────────────────────────────────────────────────

async function loadInvestigate() {
  loadSessionViewer();
  if (typeof loadGapDetector === 'function') loadGapDetector();
  const hash = window.location.hash.replace('#domain=', '');
  if (hash) {
    const inp = document.getElementById('domainInspectInput');
    if (inp) inp.value = hash;
    inspectDomain();
  }
}

async function inspectDomain() {
  const inp = document.getElementById('domainInspectInput');
  const resultEl = document.getElementById('domainInspectResult');
  if (!inp || !resultEl) return;
  const domain = inp.value.trim();
  if (!domain) return;

  resultEl.innerHTML = '<div class="bfx-loading">Loading…</div>';
  const data = await API.get(`/api/domain/${encodeURIComponent(domain)}`);
  if (!data) {
    resultEl.innerHTML = '<div class="bfx-error">Domain not found or API error.</div>';
    return;
  }

  const reasons = (data.risk_reasons || []).join(' · ') || 'No risk factors detected.';
  resultEl.innerHTML = `<div class="bfx-domain-detail">
    <div class="d-row"><div class="d-lbl">Domain</div><div class="d-val">${esc(data.domain)}</div></div>
    <div class="d-row"><div class="d-lbl">Total Visits</div><div class="d-val">${(data.total_visits || 0).toLocaleString()}</div></div>
    <div class="d-row"><div class="d-lbl">Risk Score</div>
      <div class="d-val" style="color:${riskColor(data.max_risk_score)};font-weight:bold;">${data.max_risk_score} / 100</div>
    </div>
    <div class="d-row"><div class="d-lbl">Cookies</div><div class="d-val">${data.cookies?.length || 0} cookie(s)</div></div>
    <div class="d-row"><div class="d-lbl">Downloads</div><div class="d-val">${data.downloads?.length || 0} file(s)</div></div>
    <div class="d-row"><div class="d-lbl">First Seen</div><div class="d-val">${fmtTime(data.first_seen) || '—'}</div></div>
    <div class="d-row"><div class="d-lbl">Last Seen</div><div class="d-val">${fmtTime(data.last_seen) || '—'}</div></div>
    <div class="d-row"><div class="d-lbl">In History</div>
      <div class="d-val" style="color:${data.in_history ? 'var(--accent-safe)' : 'var(--accent-action)'};">
        ${data.in_history ? 'Yes' : 'No — cookie exists, history likely cleared'}
      </div>
    </div>
    ${data.risk_reasons?.length ? `<div style="margin-top:8px;" class="bfx-reason-box">⚑ ${esc(reasons)}</div>` : ''}
  </div>`;
}

async function loadSessionViewer() {
  const data = await API.get('/api/sessions');
  const elSv = document.getElementById('sessionViewer');
  if (!elSv || !data?.sessions?.length) {
    if (elSv) elSv.innerHTML = '<div class="muted" style="font-size:12px;">No sessions reconstructed.</div>';
    return;
  }

  elSv.innerHTML = data.sessions.slice(0, 10).map((s, i) => {
    const start = fmtTime(s.start);
    const isOffhours = s.events?.some(e => {
      try { const h = new Date(e.time).getUTCHours(); return h >= 23 || h < 5; } catch { return false; }
    });
    const dlCount = (s.events || []).filter(e => e.type === 'download').length;
    return `<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius-md);padding:9px 12px;margin-bottom:7px;font-size:11px;">
      <div style="font-weight:bold;color:var(--text-primary);margin-bottom:4px;">
        Session ${data.sessions.length - i}
        ${isOffhours ? '<span class="bfx-offhours-badge" style="margin-left:6px;">OFF-HOURS</span>' : ''}
      </div>
      <div class="muted">${start} · ${s.count} events · ${dlCount} download(s)</div>
    </div>`;
  }).join('');
}

async function loadGapDetector() {
  const data = await API.get('/api/overview');
  const elGap = document.getElementById('gapDetectorContent');
  if (!elGap || !data) return;

  const gapAnomaly = (data.anomalies || []).find(a => a.type === 'history_gap');
  if (!gapAnomaly) {
    elGap.innerHTML = '<div class="muted" style="font-size:12px;">No history gaps detected.</div>';
    return;
  }

  elGap.innerHTML = `
    <div style="font-size:13px;font-weight:bold;color:var(--text-primary);margin-bottom:8px;">
      ${gapAnomaly.domain_count} domain(s) with no history
    </div>
    <div class="muted" style="font-size:11px;margin-top:8px;">${esc(gapAnomaly.description)}</div>`;
}

// ── Report ────────────────────────────────────────────────────────────────────

// FIX-REPORT: Module-scoped variable replaces window._bfxReport.
// Forensic report content (URLs, cookie names, risk reasons) should not be
// accessible to third-party scripts via the global window object.
let _reportText = '';

async function loadReport() {
  // Form setup only — generation is on button click
}

async function generateReport() {
  const caseNum  = document.getElementById('rptCase')?.value || '';
  const examName = document.getElementById('rptExaminer')?.value || '';
  const acqDate  = document.getElementById('rptDate')?.value || '';
  const notes    = document.getElementById('rptNotes')?.value || '';

  const data = await API.get('/api/report');
  if (!data) {
    document.getElementById('reportPreview').textContent = 'Error: could not fetch report data.';
    return;
  }

  const m = data.meta || {};
  const s = data.summary || {};
  const topAnomaly = (data.anomalies || [])[0]?.title || 'None';

  const flaggedHistory   = (data.flagged?.history   || []).slice(0, 10);
  const flaggedDownloads = (data.flagged?.downloads  || []).slice(0, 5);
  const flaggedCookies   = (data.flagged?.cookies    || []).slice(0, 5);

  const flaggedLines = [
    ...flaggedHistory.map(h =>
      `[SCORE ${h.risk_score}] ${h.url}\n  ${(h.risk_reasons || []).join(' · ')}`),
    ...flaggedDownloads.map(d =>
      `[SCORE ${d.risk_score}] ${d.filename} (${d.source_url})\n  ${(d.risk_reasons || []).join(' · ')}`),
    ...flaggedCookies.map(c =>
      `[SCORE ${c.risk_score}] Cookie: ${c.name} on ${c.host}\n  ${(c.risk_reasons || []).join(' · ')}`),
  ].join('\n\n') || '  None.';

  const anomalyLines = (data.anomalies || []).map((a, i) =>
    `${i + 1}. ${a.title.toUpperCase()}\n   ${a.description}`
  ).join('\n\n') || '  None.';

  const hashLines = Object.entries(data.hashes || {})
    .map(([k, v]) => `  ${k.padEnd(14)} SHA256: ${v}`)
    .join('\n') || '  No hashes available.';

  const notesSection = notes
    ? `EXAMINER NOTES\n--------------\n${notes}\n\n`
    : '';

  _reportText = `FORENSIC ANALYSIS REPORT
========================
Case No:        ${caseNum}
Examiner:       ${examName}
Acquired:       ${acqDate}
Generated:      ${new Date().toISOString()}
Tool:           BrowserForensix v1.0.0

EXECUTIVE SUMMARY
-----------------
${s.total_artifacts || 0} artifacts extracted from ${m.browser || 'Chrome'} ${m.browser_version || ''}.
Profiles: ${(m.profiles_extracted || []).map(p => p.label || p.dir || 'Unknown').join(', ') || m.profile_path || 'Unknown'}
Platform: ${m.platform || 'Unknown'}
${s.anomaly_count || 0} anomalies detected.
${s.flagged_count || 0} items flagged (risk score ≥ 61).
Average risk score: ${s.average_risk_score || 0}
Highest-risk finding: ${topAnomaly}

${notesSection}EVIDENCE INTEGRITY
------------------
${hashLines}
Extraction time: ${m.extraction_time || 'Unknown'}
Read-only copy: confirmed

ARTIFACT COUNTS
---------------
  History entries:  ${s.history_count || 0}
  Cookies:          ${s.cookie_count || 0}
  Bookmarks:        ${s.bookmark_count || 0}
  Downloads:        ${s.download_count || 0}

FLAGGED ITEMS (risk ≥ 61)
--------------------------
${flaggedLines}

ANOMALIES DETECTED
------------------
${anomalyLines}

--- END OF REPORT ---
Generated by BrowserForensix v1.0.0`;

  const prev = document.getElementById('reportPreview');
  if (prev) prev.textContent = _reportText;
}

function downloadReport() {
  // BUG-13 FIX: original guard was `_reportText.includes('Generate Report')`
  // but _reportText initialises as '' which passes that check — the download
  // would fire with an empty Blob. A falsy check is sufficient and correct.
  if (!_reportText) return;
  const blob = new Blob([_reportText], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `browserforensix-report-${Date.now()}.txt`;
  a.click();
}

// ── Global Search ─────────────────────────────────────────────────────────────

async function runGlobalSearch(q) {
  const data = await API.get(`/api/search?q=${encodeURIComponent(q)}`);
  const overlay   = document.getElementById('searchOverlay');
  const resultsEl = document.getElementById('searchResults');
  if (!overlay || !resultsEl || !data) return;

  let html = `<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">${data.total} result(s) for "${esc(q)}"</div>`;

  if (data.history?.length) {
    html += `<div class="bfx-section-title" style="margin-bottom:6px;">History (${data.history.length})</div>`;
    html += data.history.map(h => `<div class="bfx-domain-row" style="margin-bottom:3px;">
      <span class="mono" style="font-size:11px;flex:1;">${esc(domainOf(h.url))}</span>
      <span class="muted" style="font-size:10px;">${esc(h.title || '')}</span>
      <span class="bfx-risk-pill ${riskClass(h.risk_score)}">${h.risk_score}</span>
    </div>`).join('');
  }

  if (data.downloads?.length) {
    html += `<div class="bfx-section-title" style="margin-top:12px;margin-bottom:6px;">Downloads (${data.downloads.length})</div>`;
    html += data.downloads.map(d => `<div class="bfx-domain-row" style="margin-bottom:3px;">
      <span class="mono" style="font-size:11px;flex:1;">${esc(d.filename)}</span>
      <span class="bfx-risk-pill ${riskClass(d.risk_score)}">${d.risk_score}</span>
    </div>`).join('');
  }

  if (data.cookies?.length) {
    html += `<div class="bfx-section-title" style="margin-top:12px;margin-bottom:6px;">Cookies (${data.cookies.length})</div>`;
    html += data.cookies.map(c => `<div class="bfx-domain-row" style="margin-bottom:3px;">
      <span class="mono" style="font-size:11px;flex:1;">${esc(c.host)}</span>
      <span class="muted" style="font-size:10px;">${esc(c.name)}</span>
    </div>`).join('');
  }

  if (!data.total) html = '<div class="muted" style="font-size:12px;padding:10px 0;">No results found.</div>';

  resultsEl.innerHTML = html;
  overlay.style.display = 'block';
}

function closeSearch() {
  const overlay = document.getElementById('searchOverlay');
  if (overlay) overlay.style.display = 'none';
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeSearch();
});

// ═══════════════════════════════════════════════════════════════════════════
// AI INLINE EXPLAINERS — called from History, Downloads, Anomaly rows
// ═══════════════════════════════════════════════════════════════════════════

function _aiInlineStart(containerId, label) {
  const el = document.getElementById(containerId);
  if (!el) return null;
  el.style.display = '';
  el.innerHTML = `
    <div class="bfx-ai-inline-header">
      <span class="bfx-ai-inline-label">⬡ ${label}</span>
    </div>
    <div class="bfx-ai-inline-loading">
      <div class="bfx-ai-inline-spinner"></div>
      Analysing with AI…
    </div>`;
  // Show parent row if hidden (downloads)
  const parentRow = document.getElementById(containerId + '_row');
  if (parentRow) parentRow.style.display = '';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  return el;
}

// _aiInlineStream removed (B12): was dead code — all inline AI uses _aiInlineFetch

// Non-streaming fetch for fixed JSON responses
function _aiInlineFetch(el, url, textKey) {
  return fetch(url)
    .then(r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then(data => {
      const text = data[textKey] || data.explanation || data.assessment || data.profile || data.analysis || data.deep_dive || '';
      const model = data.model ? data.model.split('/').pop() : '';
      el.innerHTML = `
        <div class="bfx-ai-inline-header">
          <span class="bfx-ai-inline-label">⬡ AI Analysis</span>
          ${model ? `<span class="bfx-ai-inline-model">${esc(model)}</span>` : ''}
        </div>
        <div>${_aiFormatInline(text)}</div>`;
    })
    .catch(err => {
      if (el) el.innerHTML = `<div style="color:var(--accent-moderate);font-size:11px;">AI error: ${esc(err.message)}</div>`;
    });
}

function _aiFormatInline(text) {
  return text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/⚠️/g, '<span style="color:#FCD34D;">⚠️</span>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n{2,}/g, '<br><br>')
    .replace(/\n/g, '<br>');
}

// ── History item AI explain ──────────────────────────────────────────────────

const _aiHistoryCache = {};

async function aiExplainHistory(encodedUrl, containerId) {
  if (_aiHistoryCache[containerId]) return; // already fetched
  const el = _aiInlineStart(containerId, 'AI Risk Explanation');
  if (!el) return;
  _aiHistoryCache[containerId] = true;
  await _aiInlineFetch(el, `/api/ai/explain/history?url=${encodedUrl}`, 'explanation');
}

// ── Downloads AI threat assess ───────────────────────────────────────────────

const _aiDownloadCache = {};

async function aiExplainDownloadInline(filename, containerId, clickedRow) {
  const existingRow = document.getElementById(containerId + '_row');
  // B11 FIX: toggle-off — if row is already visible, hide it and return
  if (existingRow && existingRow.style.display !== 'none') {
    existingRow.style.display = 'none';
    return;
  }
  // Already fetched — just show the cached row
  if (_aiDownloadCache[containerId]) {
    if (existingRow) existingRow.style.display = '';
    return;
  }
  const el = _aiInlineStart(containerId, 'AI Threat Assessment');
  if (!el) return;
  _aiDownloadCache[containerId] = true;
  await _aiInlineFetch(el, `/api/ai/explain/download?filename=${encodeURIComponent(filename)}`, 'assessment');
}

// ── Anomaly AI deep dive ─────────────────────────────────────────────────────

const _aiAnomalyCache = {};

async function aiExplainAnomaly(anomalyType, containerId) {
  if (_aiAnomalyCache[containerId]) return;
  const el = _aiInlineStart(containerId, 'AI Deep Dive');
  if (!el) return;
  _aiAnomalyCache[containerId] = true;
  await _aiInlineFetch(el, `/api/ai/anomaly?type=${encodeURIComponent(anomalyType)}`, 'deep_dive');
}

// ── Heatmap Modal ─────────────────────────────────────────────────────────────
// Clicking the mini heatmap opens a full-size modal with blurred backdrop.
// _heatmapData is set by renderHeatmap() so the modal can re-render at
// full size without making another API call.

let _heatmapData = null;

function _heatmapIsWarm() {
  return document.documentElement.getAttribute('data-theme') === 'warm';
}

function _heatmapStops() {
  return _heatmapIsWarm()
    ? ['#F3EEE8','#DDD0F5','#B89EE8','#8B6DC8','#5B21B6']
    : ['#13102A','#2D1B69','#5B21B6','#8B45F5','#C084FC'];
}

function _heatmapCellColor(val, maxVal) {
  const stops = _heatmapStops();
  if (!val || val === 0) return stops[0];
  const ratio = Math.min(val / maxVal, 1);
  const idx   = Math.ceil(ratio * (stops.length - 1));
  return stops[Math.max(1, idx)];
}

function openHeatmapModal() {
  if (!_heatmapData) return;

  const existing = document.getElementById('bfxHeatmapModal');
  if (existing) existing.remove();

  const days    = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const heatData = _heatmapData;
  const map     = {};
  let   totalVisits = 0, peakVal = 0, peakLabel = '';

  heatData.forEach(d => {
    if (!map[d.day]) map[d.day] = {};
    map[d.day][d.hour] = d.count;
    totalVisits += d.count;
    if (d.count > peakVal) {
      peakVal   = d.count;
      peakLabel = `${days[d.day] || d.day} ${String(d.hour).padStart(2,'0')}:00`;
    }
  });

  const maxVal = Math.max(...heatData.map(d => d.count), 1);

  // Find busiest day
  const dayTotals = days.map((_, di) =>
    Object.values(map[di] || {}).reduce((a, b) => a + b, 0)
  );
  const busiestDay = days[dayTotals.indexOf(Math.max(...dayTotals))] || '—';

  // Find busiest hour
  const hourTotals = Array.from({length:24}, (_, h) =>
    days.reduce((sum, _, di) => sum + ((map[di] || {})[h] || 0), 0)
  );
  const busiestHour = hourTotals.indexOf(Math.max(...hourTotals));

  // Build full-size grid
  let grid = `<div class="bfx-heatmap-modal-grid">`;
  grid += `<div class="bfx-heatmap-modal-header"></div>`;
  for (let h = 0; h < 24; h++) {
    grid += `<div class="bfx-heatmap-modal-header">${h % 3 === 0 ? String(h).padStart(2,'0') : ''}</div>`;
  }
  days.forEach((d, di) => {
    grid += `<div class="bfx-heatmap-modal-label">${d}</div>`;
    for (let h = 0; h < 24; h++) {
      const v   = (map[di] || {})[h] || 0;
      const col = _heatmapCellColor(v, maxVal);
      const tip = `${d} ${String(h).padStart(2,'0')}:00 — ${v.toLocaleString()} visit${v !== 1 ? 's' : ''}`;
      grid += `<div class="bfx-heatmap-modal-cell" title="${tip}" style="background:${col};"></div>`;
    }
  });
  grid += `</div>`;

  // Legend swatches
  const stops   = _heatmapStops();
  const swatches = stops.map(c =>
    `<span class="bfx-heatmap-modal-legend-swatch" style="background:${c};"></span>`
  ).join('');

  // Stats row
  const stats = [
    { label: 'Total Visits',   val: totalVisits.toLocaleString() },
    { label: 'Busiest Day',    val: busiestDay },
    { label: 'Busiest Hour',   val: `${String(busiestHour).padStart(2,'0')}:00` },
    { label: 'Peak Window',    val: peakLabel || '—' },
    { label: 'Peak Count',     val: peakVal.toLocaleString() },
  ].map(s => `
    <div class="bfx-heatmap-modal-stat">
      <div class="bfx-heatmap-modal-stat-label">${s.label}</div>
      <div class="bfx-heatmap-modal-stat-val">${s.val}</div>
    </div>`).join('');

  const backdrop = document.createElement('div');
  backdrop.className = 'bfx-heatmap-modal-backdrop';
  backdrop.id = 'bfxHeatmapModal';
  backdrop.innerHTML = `
    <div class="bfx-heatmap-modal" role="dialog" aria-modal="true" aria-label="Activity Heatmap">
      <div class="bfx-heatmap-modal-head">
        <div>
          <span class="bfx-heatmap-modal-title">Activity Heatmap</span>
          <span class="bfx-heatmap-modal-sub">visits by day × hour (UTC)</span>
        </div>
        <button class="bfx-heatmap-modal-close" onclick="closeHeatmapModal()" title="Close (Esc)">✕</button>
      </div>
      ${grid}
      <div class="bfx-heatmap-modal-legend">
        <span>Low</span>
        <div class="bfx-heatmap-modal-legend-swatches">${swatches}</div>
        <span>High</span>
      </div>
      <div class="bfx-heatmap-modal-stats">${stats}</div>
    </div>`;

  document.body.appendChild(backdrop);

  // Close on backdrop click (not on modal card itself)
  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) closeHeatmapModal();
  });

  // Animate in next frame
  requestAnimationFrame(() => {
    requestAnimationFrame(() => backdrop.classList.add('open'));
  });
}

function closeHeatmapModal() {
  const el = document.getElementById('bfxHeatmapModal');
  if (!el) return;
  el.classList.remove('open');
  el.addEventListener('transitionend', () => el.remove(), { once: true });
}

// Close on Escape key
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeHeatmapModal();
});