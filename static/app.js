/* BrowserForensix — app.js
   All frontend logic. API calls, rendering, state management.
   No inline styles — all classes come from style.css.
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
  return (url || '').startsWith('http://') ? 'http' : 'https';
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    return iso.replace('T', ' ').replace(/\.\d+Z$/, '').replace('Z', '');
  } catch { return iso; }
}

function fmtSize(bytes) {
  if (!bytes) return '—';
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return bytes + ' B';
}

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
}

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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

// ── Navigation ────────────────────────────────────────────────────────────────

const PAGES = ['overview','history','cookies','bookmarks','downloads','timeline','investigate','report'];

function activatePage(pageId) {
  document.querySelectorAll('.bfx-nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.page === pageId);
  });
  document.querySelectorAll('.bfx-page').forEach(p => {
    p.classList.toggle('active', p.id === 'page-' + pageId);
  });
  const titles = {
    overview:    'Overview',
    history:     'History',
    cookies:     'Cookies',
    bookmarks:   'Bookmarks',
    downloads:   'Downloads',
    timeline:    'Timeline',
    investigate: 'Investigate',
    report:      'Report Generator',
  };
  const titleEl = document.getElementById('bfxPageTitle');
  if (titleEl) titleEl.textContent = titles[pageId] || pageId;

  // Lazy-load page data
  const loaders = {
    overview:    loadOverview,
    history:     loadHistory,
    cookies:     loadCookies,
    bookmarks:   loadBookmarks,
    downloads:   loadDownloads,
    timeline:    loadTimeline,
    investigate: loadInvestigate,
    report:      loadReport,
  };
  if (loaders[pageId]) loaders[pageId]();
}

document.addEventListener('DOMContentLoaded', () => {
  // Nav click
  document.querySelectorAll('.bfx-nav-item').forEach(item => {
    item.addEventListener('click', () => activatePage(item.dataset.page));
  });

  // Global search
  const gs = document.getElementById('globalSearch');
  if (gs) {
    let debounce;
    gs.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        if (gs.value.trim().length >= 2) runGlobalSearch(gs.value.trim());
      }, 300);
    });
    gs.addEventListener('keydown', e => {
      if (e.key === 'Escape') { gs.value = ''; }
    });
  }

  // Load status then initial page
  loadStatus().then(() => activatePage('overview'));
});

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

  // Stat cards
  document.getElementById('statArtifacts').textContent = (s.total_artifacts || 0).toLocaleString();
  document.getElementById('statFlagged').textContent = s.flagged_count || 0;
  document.getElementById('statRisk').textContent = s.average_risk_score || 0;
  document.getElementById('statAnomalies').textContent = s.anomaly_count || 0;
  document.getElementById('statBrowserMeta').textContent = (meta.browser || 'chrome') + ' · ' + (meta.profile_path || '').split('/').slice(-2).join('/');

  // Anomalies
  renderAnomalies(data.anomalies || []);

  // Top domains
  renderDomainList(data.top_domains || []);

  // Heatmap
  renderHeatmap(data.heatmap || []);

  // Evidence meta
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
  const el = document.getElementById('anomalyList');
  if (!el) return;
  if (!anomalies.length) {
    el.innerHTML = '<div class="muted" style="font-size:12px;padding:10px 0;">No anomalies detected.</div>';
    return;
  }
  el.innerHTML = anomalies.map(a => {
    const sevClass = a.severity === 'critical' ? '' : a.severity === 'moderate' ? 'moderate' : 'low';
    return `<div class="bfx-anomaly-item ${sevClass}">
      <div class="bfx-anomaly-type">${esc(a.type.replace(/_/g,' '))} · ${esc(a.severity)}</div>
      <div class="bfx-anomaly-text">${esc(a.description)}</div>
    </div>`;
  }).join('');
}

function renderDomainList(domains) {
  const el = document.getElementById('domainList');
  if (!el) return;
  el.innerHTML = domains.slice(0, 10).map(d => {
    const pct = Math.min(100, d.risk_score || 0);
    return `<div class="bfx-domain-row">
      <span class="bfx-domain-name mono">${esc(d.domain)}</span>
      <div class="bfx-risk-bar-wrap">
        <div class="bfx-risk-bar" style="width:${pct}%;background:${riskColor(d.risk_score)};"></div>
      </div>
      <span class="bfx-domain-count mono">${(d.visits || 0).toLocaleString()}</span>
    </div>`;
  }).join('');
}

function renderHeatmap(heatData) {
  const el = document.getElementById('activityHeatmap');
  if (!el) return;
  const days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
  const colors = ['#EAD9C4','#C9A882','#A47E64','#7A5C44','#B7410E'];

  // Build lookup: day → hour → count
  const map = {};
  heatData.forEach(({day, hour, count}) => {
    if (!map[day]) map[day] = {};
    map[day][hour] = count;
  });
  const maxVal = Math.max(...heatData.map(d => d.count), 1);

  function cellColor(v) {
    if (!v) return colors[0];
    const idx = Math.min(4, Math.floor((v / maxVal) * 5));
    return colors[idx];
  }

  let html = `<div class="bfx-heatmap">`;
  // Header row
  html += `<div class="bfx-heatmap-header"></div>`;
  for (let h = 0; h < 24; h++) {
    html += `<div class="bfx-heatmap-header">${h % 4 === 0 ? h : ''}</div>`;
  }
  // Data rows
  days.forEach((d, di) => {
    html += `<div class="bfx-heatmap-label">${d}</div>`;
    for (let h = 0; h < 24; h++) {
      const v = (map[di] || {})[h] || 0;
      html += `<div class="bfx-heatmap-cell" title="${d} ${h}:00 — ${v} visits" style="background:${cellColor(v)};"></div>`;
    }
  });
  html += '</div>';
  el.innerHTML = html;
}

// ── History ───────────────────────────────────────────────────────────────────

let histState = { page: 1, q: '', protocol: 'all', risk: 'any', from: '', to: '' };
let histExpandedRow = null;

async function loadHistory(reset = false) {
  if (reset) { histState.page = 1; histExpandedRow = null; }
  const params = new URLSearchParams({
    page: histState.page,
    q: histState.q,
    protocol: histState.protocol,
    risk: histState.risk,
    from: histState.from,
    to: histState.to,
  });
  const data = await API.get(`/api/history?${params}`);
  const tbody = document.getElementById('histBody');
  if (!tbody) return;
  if (!data) { tbody.innerHTML = `<tr><td colspan="5" class="bfx-loading">Failed to load history.</td></tr>`; return; }

  tbody.innerHTML = '';
  if (!data.items?.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="bfx-loading muted">No results.</td></tr>`;
  } else {
    data.items.forEach((h, i) => {
      const rc = riskClass(h.risk_score);
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

  // Pagination
  document.getElementById('histPageInfo').textContent = `Page ${data.page} of ${data.total_pages}`;
  document.getElementById('histTotal').textContent = `${data.total.toLocaleString()} total entries`;
  document.getElementById('histPrev').disabled = data.page <= 1;
  document.getElementById('histNext').disabled = data.page >= data.total_pages;
}

function toggleHistExpand(row, h) {
  // Remove previous expand row
  const existing = document.getElementById('histExpandRow');
  if (existing) existing.remove();
  if (histExpandedRow === row) { histExpandedRow = null; return; }
  histExpandedRow = row;

  const reasons = (h.risk_reasons || []).join(' · ');
  const expandRow = document.createElement('tr');
  expandRow.id = 'histExpandRow';
  expandRow.innerHTML = `<td colspan="5" class="bfx-expand-row">
    <div class="bfx-expand-content">
      <div class="exp-label">Full URL</div>
      <div class="exp-value">${esc(h.url)}</div>
      <div class="exp-label">Last Visit</div>
      <div class="exp-value">${fmtTime(h.last_visit)}</div>
      <div class="exp-label">Total Visits</div>
      <div class="exp-value">${h.visit_count || 1}</div>
      ${reasons ? `<div class="bfx-reason-box">⚑ ${esc(reasons)}</div>` : ''}
    </div>
  </td>`;
  row.insertAdjacentElement('afterend', expandRow);
}

// History filter/search events wired in base.html via IDs

// ── Cookies ───────────────────────────────────────────────────────────────────

let cookieState = { page: 1, type: 'all', expired: 'all', secure: 'all' };

async function loadCookies(reset = false) {
  if (reset) cookieState.page = 1;
  const params = new URLSearchParams({
    page: cookieState.page,
    type: cookieState.type,
    expired: cookieState.expired,
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
    const typeKey = (c.type || 'unknown').toLowerCase().replace(/\s+/, '-');
    const typeClass = {
      'auth-token': 'type-auth',
      'tracking': 'type-tracking',
      'session': 'type-session',
      'zombie': 'type-zombie',
      'analytics': 'type-analytics',
    }[typeKey] || 'type-unknown';
    const flags = [
      c.secure ? 'Secure' : '',
      c.http_only ? 'HttpOnly' : '',
      c.samesite ? `SameSite=${c.samesite}` : '',
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
  document.getElementById('cookieTotal').textContent = `${data.total.toLocaleString()} total cookies`;
  document.getElementById('cookiePrev').disabled = data.page <= 1;
  document.getElementById('cookieNext').disabled = data.page >= data.total_pages;
}

// ── Bookmarks ─────────────────────────────────────────────────────────────────

let bmData = null;
let bmCurrentFolder = 'all';

async function loadBookmarks() {
  if (!bmData) {
    bmData = await API.get('/api/bookmarks');
  }
  renderBookmarkFolder(bmCurrentFolder);
}

function renderBookmarkFolder(folder) {
  bmCurrentFolder = folder;
  document.querySelectorAll('.bfx-folder-item').forEach(f => {
    f.classList.toggle('active', f.dataset.folder === folder);
  });

  const el = document.getElementById('bmEntries');
  if (!el || !bmData) return;

  let items = [];
  if (folder === 'all') {
    items = Object.values(bmData.tree || {}).flat();
  } else if (folder === 'deleted') {
    items = Object.values(bmData.tree || {}).flat()
      .filter(b => b.url === 'about:blank' || b.deleted);
  } else {
    items = Object.entries(bmData.tree || {})
      .filter(([k]) => k.toLowerCase().includes(folder))
      .flatMap(([, v]) => v);
  }

  if (!items.length) {
    el.innerHTML = '<div class="muted" style="padding:12px 0;font-size:12px;">No bookmarks in this folder.</div>';
    return;
  }

  el.innerHTML = items.map(b => {
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

let dlState = { page: 1, q: '', risk: 'any' };

async function loadDownloads(reset = false) {
  if (reset) dlState.page = 1;
  const params = new URLSearchParams({ page: dlState.page, q: dlState.q, risk: dlState.risk });
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
    const row = document.createElement('tr');
    if (d.risk_score >= 61) row.classList.add('flagged');
    row.innerHTML = `
      <td class="mono" style="font-size:11px;">${esc(d.filename || '—')}</td>
      <td class="mono muted" style="font-size:11px;">${esc(srcDomain)}</td>
      <td class="mono muted" style="font-size:10px;white-space:nowrap;">${fmtTime(d.start_time)}</td>
      <td class="mono" style="font-size:11px;">${fmtSize(d.size_bytes)}</td>
      <td>${inHist}</td>
      <td>${onDisk}</td>
      <td><span class="bfx-risk-pill ${rc}">${d.risk_score}</span></td>`;
    tbody.appendChild(row);
  });

  document.getElementById('dlPageInfo').textContent = `Page ${data.page} of ${data.total_pages}`;
  document.getElementById('dlTotal').textContent = `${data.total.toLocaleString()} total downloads`;
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
  const el = document.getElementById('timelineList');
  if (!el) return;
  if (!data?.sessions?.length) {
    el.innerHTML = '<div class="bfx-loading muted">No timeline data available.</div>';
    return;
  }

  el.innerHTML = data.sessions.map((s, si) => {
    const start = fmtTime(s.start);
    const end = fmtTime(s.end);
    const isOffhours = s.events?.some(e => {
      try {
        const h = new Date(e.time).getUTCHours();
        return h >= 23 || h < 5;
      } catch { return false; }
    });
    const dotClass = { history: 'dot-history', cookie: 'dot-cookie', download: 'dot-download', bookmark: 'dot-bookmark' };

    const itemsHtml = (s.events || []).map(e => {
      let text = '';
      if (e.type === 'history') text = `<span style="font-family:var(--font-mono);font-size:10px;">${esc(e.domain)}</span> — ${esc(e.title || e.url || '')}`;
      else if (e.type === 'cookie') text = `Cookie set: <span class="mono">${esc(e.name)}</span> on ${esc(e.host)}`;
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
  // loadGapDetector is defined in investigate.html's script block.
  // Guard the call so navigating via app.js on other pages doesn't throw.
  if (typeof loadGapDetector === "function") {
    loadGapDetector();
  }
  // Domain inspector pre-populated if hash present
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
    ${data.risk_reasons?.length ? `
    <div style="margin-top:8px;" class="bfx-reason-box">⚑ ${esc(reasons)}</div>` : ''}
  </div>`;
}

async function loadSessionViewer() {
  const data = await API.get('/api/sessions');
  const el = document.getElementById('sessionViewer');
  if (!el || !data?.sessions?.length) {
    if (el) el.innerHTML = '<div class="muted" style="font-size:12px;">No sessions reconstructed.</div>';
    return;
  }

  el.innerHTML = data.sessions.slice(0, 10).map((s, i) => {
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
  const el = document.getElementById('gapDetectorContent');
  if (!el || !data) return;

  const gapAnomaly = (data.anomalies || []).find(a => a.type === 'history_gap');
  if (!gapAnomaly) {
    el.innerHTML = '<div class="muted" style="font-size:12px;">No history gaps detected.</div>';
    return;
  }

  el.innerHTML = `
    <div style="font-size:13px;font-weight:bold;color:var(--text-primary);margin-bottom:8px;">
      ${gapAnomaly.domain_count} domain(s) with no history
    </div>
    <div class="bfx-gap-bar-wrap">
      <div class="bfx-gap-segment" style="width:35%;background:var(--accent-safe);">History present</div>
      <div class="bfx-gap-segment" style="width:20%;background:var(--accent-action);">Gap</div>
      <div class="bfx-gap-segment" style="width:45%;background:var(--accent-safe);">History present</div>
    </div>
    <div class="bfx-gap-legend">
      <span><span class="bfx-gap-dot" style="background:var(--accent-safe);"></span>History present</span>
      <span><span class="bfx-gap-dot" style="background:var(--accent-action);"></span>Cleared</span>
    </div>
    <div class="muted" style="font-size:11px;margin-top:8px;">${esc(gapAnomaly.description)}</div>`;
}

// ── Report ────────────────────────────────────────────────────────────────────

async function loadReport() {
  // Just set up the form — generation is on button click
}

async function generateReport() {
  const caseNum = document.getElementById('rptCase')?.value || '';
  const examName = document.getElementById('rptExaminer')?.value || '';
  const acqDate = document.getElementById('rptDate')?.value || '';

  const data = await API.get('/api/report');
  if (!data) {
    document.getElementById('reportPreview').textContent = 'Error: could not fetch report data.';
    return;
  }

  const m = data.meta || {};
  const s = data.summary || {};
  const topAnomaly = (data.anomalies || [])[0]?.title || 'None';

  const flaggedHistory = (data.flagged?.history || []).slice(0, 10);
  const flaggedDownloads = (data.flagged?.downloads || []).slice(0, 5);
  const flaggedCookies = (data.flagged?.cookies || []).slice(0, 5);

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

  const report = `FORENSIC ANALYSIS REPORT
========================
Case No:        ${caseNum}
Examiner:       ${examName}
Acquired:       ${acqDate}
Generated:      ${new Date().toISOString()}
Tool:           BrowserForensix v1.0.0

EXECUTIVE SUMMARY
-----------------
${s.total_artifacts || 0} artifacts extracted from ${m.browser || 'Chrome'} ${m.browser_version || ''}.
Profile path: ${m.profile_path || 'Unknown'}
Platform: ${m.platform || 'Unknown'}
${s.anomaly_count || 0} anomalies detected.
${s.flagged_count || 0} items flagged (risk score ≥ 61).
Average risk score: ${s.average_risk_score || 0}
Highest-risk finding: ${topAnomaly}

EVIDENCE INTEGRITY
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
  if (prev) prev.textContent = report;

  // Store for download
  window._bfxReport = report;
}

function downloadReport() {
  const text = window._bfxReport || document.getElementById('reportPreview')?.textContent || '';
  if (!text || text.includes('Generate Report')) return;
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `browserforensix-report-${Date.now()}.txt`;
  a.click();
}

// ── Global Search ─────────────────────────────────────────────────────────────

async function runGlobalSearch(q) {
  const data = await API.get(`/api/search?q=${encodeURIComponent(q)}`);
  const overlay = document.getElementById('searchOverlay');
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