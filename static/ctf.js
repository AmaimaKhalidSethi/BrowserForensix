/* BrowserForensix — ctf.js
   CTF analysis frontend. Loaded only on /ctf and as a lightweight
   injector on other pages. Never modifies app.js or any existing global.

   All functions are namespaced under ctf* to avoid collisions.
   Relies on: esc(), fmtTime(), riskClass(), riskColor() from app.js.
*/

'use strict';

// ── Tab switching ─────────────────────────────────────────────────────────────

const _CTF_TABS = ['flags', 'decode', 'params', 'cookie'];

function ctfShowTab(name) {
  _CTF_TABS.forEach(t => {
    const panel = document.getElementById('ctfTab' + t.charAt(0).toUpperCase() + t.slice(1));
    const btn   = document.getElementById('ctfTab' + t.charAt(0).toUpperCase() + t.slice(1) + 'Btn');
    if (!panel || !btn) return;
    const active = (t === name);
    panel.style.display = active ? '' : 'none';
    btn.className = active ? 'bfx-btn sm' : 'bfx-btn outline sm';
  });
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function _ctfLoading(elId, msg) {
  const el = document.getElementById(elId);
  if (el) el.innerHTML = `<div class="bfx-loading">${esc(msg || 'Loading…')}</div>`;
}

function _ctfSetBtnLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? '…' : btn.dataset.label || btn.textContent;
}

function _ctfEmpty(elId, msg) {
  const el = document.getElementById(elId);
  if (el) el.innerHTML = `<div class="muted" style="font-size:12px;padding:8px 0;">${esc(msg)}</div>`;
}

function _ctfCopy(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).catch(() => {});
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }
}

function _ctfCopyBtn(text) {
  const id = 'ctfCopy_' + Math.random().toString(36).slice(2, 8);
  setTimeout(() => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', () => {
      _ctfCopy(text);
      btn.textContent = '✓ Copied';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
  }, 0);
  return `<button id="${id}" class="bfx-btn outline sm" style="font-size:9px;padding:1px 7px;">Copy</button>`;
}

function _ctfArtifactBadge(type) {
  const colors = {
    history:  'var(--accent-safe)',
    cookie:   'var(--accent-moderate)',
    download: 'var(--accent-action)',
    bookmark: 'var(--accent-dim)',
  };
  return `<span style="display:inline-block;font-size:9px;font-weight:bold;text-transform:uppercase;
    letter-spacing:.06em;padding:2px 6px;border-radius:3px;
    background:${colors[type] || 'var(--border-mid)'};
    color:var(--bg-base);margin-right:6px;">${esc(type)}</span>`;
}

function _ctfMatchBadge(matchText) {
  return `<span class="mono" style="display:inline-block;font-size:10px;padding:2px 8px;
    border-radius:3px;background:rgba(176,110,255,0.15);
    border:1px solid var(--border-vivid);color:var(--accent-ultra);
    margin:2px 3px 2px 0;">${esc(matchText)}</span>`;
}

function _ctfDecodingTable(decodings) {
  if (!decodings || !Object.keys(decodings).length) return '';
  const rows = Object.entries(decodings).map(([enc, val]) =>
    `<tr>
      <td style="font-size:10px;color:var(--text-secondary);padding:3px 8px 3px 0;white-space:nowrap;">${esc(enc)}</td>
      <td class="mono" style="font-size:10px;word-break:break-all;">${esc(val)}</td>
      <td style="padding-left:6px;">${_ctfCopyBtn(val)}</td>
    </tr>`
  ).join('');
  return `<table style="margin-top:6px;width:100%;border-collapse:collapse;">${rows}</table>`;
}

// ── Flag Scanner ──────────────────────────────────────────────────────────────

async function ctfRunFlagScan() {
  const typeFilter = document.getElementById('ctfFlagTypeFilter')?.value || '';
  const custom     = document.getElementById('ctfCustomPattern')?.value.trim() || '';
  const btn        = document.getElementById('ctfFlagScanBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
  _ctfLoading('ctfFlagResults', 'Scanning all artifacts for flag patterns…');

  const params = new URLSearchParams();
  if (typeFilter) params.set('artifact_type', typeFilter);
  if (custom)     params.set('custom', custom);

  try {
    const res  = await fetch(`/api/ctf/scan/flags?${params}`);
    const data = await res.json();
    _ctfRenderFlagResults(data);
  } catch (e) {
    _ctfEmpty('ctfFlagResults', 'Error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan'; }
  }
}

function _ctfRenderFlagResults(data) {
  const el = document.getElementById('ctfFlagResults');
  if (!el) return;

  if (!data.results?.length) {
    el.innerHTML = `<div style="padding:14px;background:var(--bg-surface);border:1px solid var(--border);
      border-radius:var(--radius-md);font-size:12px;color:var(--text-secondary);">
      No flag patterns detected across ${data.total !== undefined ? data.total : '0'} scanned fields.
      Try adding a custom pattern if you know the challenge's flag format.
    </div>`;
    return;
  }

  let html = `<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">
    ${data.results.length} field(s) with flag matches
    ${data.custom_pattern ? `<span class="mono" style="margin-left:8px;font-size:10px;">+ custom: ${esc(data.custom_pattern)}</span>` : ''}
  </div>`;

  data.results.forEach(r => {
    const matchBadges = (r.matches || []).map(m => _ctfMatchBadge(m.match)).join('');
    html += `<div style="background:var(--bg-surface);border:1px solid var(--border-mid);
      border-left:3px solid var(--accent-action);
      border-radius:var(--radius-md);padding:10px 13px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
        ${_ctfArtifactBadge(r.artifact_type)}
        <span style="font-size:10px;color:var(--text-secondary);">field: <span class="mono">${esc(r.field)}</span></span>
        <span style="font-size:10px;color:var(--text-secondary);margin-left:auto;">
          risk: <span style="color:${riskColor(r.artifact?.risk_score || 0)};font-weight:bold;">${r.artifact?.risk_score ?? 0}</span>
        </span>
      </div>
      <div style="font-size:11px;margin-bottom:6px;">
        <span class="muted">Matches: </span>${matchBadges}
      </div>
      <div class="mono" style="font-size:10px;word-break:break-all;color:var(--text-secondary);
        background:var(--bg-panel);padding:5px 7px;border-radius:var(--radius-sm);margin-bottom:6px;">
        ${esc(r.value)}
      </div>
      <div style="font-size:10px;color:var(--text-secondary);">
        ${r.artifact?.label ? esc(r.artifact.label.slice(0, 120)) : ''}
        ${r.artifact?.time  ? ' · ' + fmtTime(r.artifact.time) : ''}
      </div>
    </div>`;
  });

  el.innerHTML = html;
}

// ── Encoding Detector ─────────────────────────────────────────────────────────

async function ctfRunDecoder() {
  const typeFilter = document.getElementById('ctfDecodeTypeFilter')?.value || '';
  const btn        = document.getElementById('ctfDecodeRunBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Detecting…'; }
  _ctfLoading('ctfDecodeResults', 'Attempting decoding across all artifact fields…');

  const params = new URLSearchParams();
  if (typeFilter) params.set('artifact_type', typeFilter);

  try {
    const res  = await fetch(`/api/ctf/decode?${params}`);
    const data = await res.json();
    _ctfRenderDecodeResults(data);
  } catch (e) {
    _ctfEmpty('ctfDecodeResults', 'Error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Detect'; }
  }
}

function _ctfRenderDecodeResults(data) {
  const el = document.getElementById('ctfDecodeResults');
  if (!el) return;

  if (!data.results?.length) {
    el.innerHTML = `<div style="padding:14px;background:var(--bg-surface);border:1px solid var(--border);
      border-radius:var(--radius-md);font-size:12px;color:var(--text-secondary);">
      No encoded values detected. Fields with values shorter than 8 characters are skipped.
    </div>`;
    return;
  }

  let html = `<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">
    ${data.results.length} field(s) with decodable content
  </div>`;

  data.results.forEach(r => {
    html += `<div style="background:var(--bg-surface);border:1px solid var(--border-mid);
      border-radius:var(--radius-md);padding:10px 13px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
        ${_ctfArtifactBadge(r.artifact_type)}
        <span style="font-size:10px;color:var(--text-secondary);">field: <span class="mono">${esc(r.field)}</span></span>
      </div>
      <div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
        <span class="muted" style="font-size:10px;white-space:nowrap;">Original:</span>
        <span class="mono" style="font-size:10px;word-break:break-all;">${esc(r.original)}</span>
        ${_ctfCopyBtn(r.original)}
      </div>
      ${_ctfDecodingTable(r.decodings)}
      <div style="font-size:10px;color:var(--text-secondary);margin-top:6px;">
        ${r.artifact?.label ? esc(r.artifact.label.slice(0, 120)) : ''}
        ${r.artifact?.time  ? ' · ' + fmtTime(r.artifact.time) : ''}
      </div>
    </div>`;
  });

  el.innerHTML = html;
}

// ── URL Parameter Decomposer ──────────────────────────────────────────────────

async function ctfRunParams() {
  const q   = document.getElementById('ctfParamSearch')?.value.trim() || '';
  const btn = document.getElementById('ctfParamsRunBtn');
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  _ctfLoading('ctfParamsResults', 'Decomposing URL query strings…');

  const params = new URLSearchParams();
  if (q) params.set('q', q);

  try {
    const res  = await fetch(`/api/ctf/url/params?${params}`);
    const data = await res.json();
    _ctfRenderParamResults(data);
  } catch (e) {
    _ctfEmpty('ctfParamsResults', 'Error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Decompose'; }
  }
}

function _ctfRenderParamResults(data) {
  const el = document.getElementById('ctfParamsResults');
  if (!el) return;

  if (!data.results?.length) {
    el.innerHTML = `<div style="padding:14px;background:var(--bg-surface);border:1px solid var(--border);
      border-radius:var(--radius-md);font-size:12px;color:var(--text-secondary);">
      No URLs with query parameters found${data.total !== undefined ? ` (${data.total} checked)` : ''}.
    </div>`;
    return;
  }

  let html = `<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">
    ${data.results.length} URL(s) with query parameters
  </div>`;

  data.results.forEach(r => {
    const hasFlagHits = r.params.some(p => p.flag_hits?.length);
    const borderColor = hasFlagHits ? 'var(--accent-action)' : 'var(--border-mid)';

    const paramRows = r.params.map(p => {
      const flagBadges = (p.flag_hits || []).map(f => _ctfMatchBadge(f.match)).join('');
      return `<tr style="${p.suspicious ? 'background:rgba(176,110,255,0.05);' : ''}">
        <td class="mono" style="font-size:10px;padding:4px 8px 4px 0;color:var(--text-secondary);
          white-space:nowrap;vertical-align:top;">${esc(p.key)}</td>
        <td class="mono" style="font-size:10px;word-break:break-all;padding:4px 8px;vertical-align:top;">
          ${esc(p.value)}
          ${flagBadges ? `<div style="margin-top:3px;">${flagBadges}</div>` : ''}
        </td>
        <td style="vertical-align:top;padding:4px 0;white-space:nowrap;">
          ${_ctfCopyBtn(p.value)}
        </td>
        <td style="vertical-align:top;padding:4px 0 4px 8px;font-size:10px;color:var(--text-secondary);">
          ${Object.keys(p.decodings || {}).length ? '⇌ ' + Object.keys(p.decodings).join(', ') : ''}
        </td>
      </tr>`;
    }).join('');

    html += `<div style="background:var(--bg-surface);border:1px solid ${borderColor};
      border-radius:var(--radius-md);padding:10px 13px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
        <span class="mono" style="font-size:11px;word-break:break-all;">${esc(r.url)}</span>
        <span class="muted" style="font-size:10px;margin-left:auto;white-space:nowrap;">${fmtTime(r.last_visit)}</span>
      </div>
      ${r.title ? `<div style="font-size:10px;color:var(--text-secondary);margin-bottom:6px;">${esc(r.title)}</div>` : ''}
      <table style="width:100%;border-collapse:collapse;border-top:1px solid var(--border);">
        <thead><tr>
          <th style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;padding:4px 8px 4px 0;
            color:var(--text-secondary);text-align:left;white-space:nowrap;">Key</th>
          <th style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;padding:4px 8px;
            color:var(--text-secondary);text-align:left;">Value</th>
          <th></th>
          <th style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;
            color:var(--text-secondary);text-align:left;">Encodings</th>
        </tr></thead>
        <tbody>${paramRows}</tbody>
      </table>
    </div>`;
  });

  el.innerHTML = html;
}

// ── Cookie Inspector ──────────────────────────────────────────────────────────

async function ctfRunCookieInspect() {
  const host = document.getElementById('ctfCookieHost')?.value.trim() || '';
  const name = document.getElementById('ctfCookieName')?.value.trim() || '';
  const btn  = document.getElementById('ctfCookieRunBtn');
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  _ctfLoading('ctfCookieResults', 'Loading cookie values…');

  const params = new URLSearchParams();
  if (host) params.set('host', host);
  if (name) params.set('name', name);

  try {
    const res  = await fetch(`/api/ctf/cookie/inspect?${params}`);
    const data = await res.json();
    _ctfRenderCookieResults(data);
  } catch (e) {
    _ctfEmpty('ctfCookieResults', 'Error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Inspect'; }
  }
}

function _ctfRenderCookieResults(data) {
  const el = document.getElementById('ctfCookieResults');
  if (!el) return;

  if (!data.results?.length) {
    el.innerHTML = `<div style="padding:14px;background:var(--bg-surface);border:1px solid var(--border);
      border-radius:var(--radius-md);font-size:12px;color:var(--text-secondary);">
      No readable (non-encrypted) cookie values found matching the filter.
      Chrome encrypts most cookie values using DPAPI/Keychain — those appear as [ENCRYPTED]
      and cannot be decoded without the OS master key.
    </div>`;
    return;
  }

  let html = `<div style="font-size:11px;color:var(--text-secondary);margin-bottom:10px;">
    ${data.results.length} cookie(s) with readable values
  </div>`;

  data.results.forEach(r => {
    const hasFlagHits = r.flag_hits?.length > 0;
    const borderColor = hasFlagHits ? 'var(--accent-action)' : 'var(--border-mid)';
    const flagBadges  = (r.flag_hits || []).map(f => _ctfMatchBadge(f.match)).join('');

    html += `<div style="background:var(--bg-surface);border:1px solid ${borderColor};
      border-radius:var(--radius-md);padding:10px 13px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap;">
        <span class="mono" style="font-size:12px;font-weight:bold;">${esc(r.name)}</span>
        <span style="font-size:10px;color:var(--text-secondary);">@ ${esc(r.host)}</span>
        <span class="bfx-cookie-type type-${(r.type||'unknown').toLowerCase().replace(/\s+/,'-')}"
              style="font-size:9px;">${esc(r.type)}</span>
        <span style="margin-left:auto;font-size:10px;
          color:${riskColor(r.risk_score)};font-weight:bold;">${r.risk_score}</span>
      </div>

      <!-- Raw value -->
      <div style="margin-bottom:8px;">
        <div style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;
          color:var(--text-secondary);margin-bottom:3px;">Raw Value</div>
        <div class="mono" style="font-size:10px;word-break:break-all;
          background:var(--bg-panel);padding:5px 7px;border-radius:var(--radius-sm);">
          ${esc(r.value)}
        </div>
        ${flagBadges ? `<div style="margin-top:5px;">${flagBadges}</div>` : ''}
      </div>

      <!-- Hex dump -->
      <div style="margin-bottom:8px;">
        <div style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;
          color:var(--text-secondary);margin-bottom:3px;">Hex Dump (first 64 bytes)</div>
        <div class="mono" style="font-size:10px;word-break:break-all;
          background:var(--bg-panel);padding:5px 7px;border-radius:var(--radius-sm);
          color:var(--text-secondary);">${esc(r.hex_dump)}</div>
      </div>

      <!-- Decodings -->
      ${Object.keys(r.decodings || {}).length ? `
        <div>
          <div style="font-size:9px;text-transform:uppercase;letter-spacing:.06em;
            color:var(--text-secondary);margin-bottom:3px;">Decoded Forms</div>
          ${_ctfDecodingTable(r.decodings)}
        </div>` : ''}

      <div style="font-size:10px;color:var(--text-secondary);margin-top:7px;">
        Created: ${fmtTime(r.created)} · Expires: ${fmtTime(r.expires) || 'Session'}
      </div>

      <div style="margin-top:6px;">${_ctfCopyBtn(r.value)}</div>
    </div>`;
  });

  el.innerHTML = html;
}