/* BrowserForensix — graph.js
   Force-directed domain relationship graph for the Investigate page.
   Zero external dependencies — pure JS physics simulation on an SVG element.
   Loaded only on /investigate via a script tag in investigate.html.
*/

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let _gNodes = [], _gEdges = [], _gSim = null, _gSvg = null;
let _gDragging = null, _gTransform = { x: 0, y: 0, k: 1 };
let _gWidth = 0, _gHeight = 0;

const NODE_R   = { flagged: 18, moderate: 14, normal: 10 };
const NODE_COL = {
  flagged:  { fill: 'rgba(239,68,68,0.85)',  stroke: '#EF4444' },
  moderate: { fill: 'rgba(245,158,11,0.80)', stroke: '#F59E0B' },
  normal:   { fill: 'rgba(139,69,245,0.70)', stroke: '#8B45F5' },
};
const EDGE_COL = {
  shared_cookie: 'rgba(139,69,245,0.35)',
  same_session:  'rgba(52,211,153,0.25)',
  download:      'rgba(239,68,68,0.30)',
};

// ── Physics ───────────────────────────────────────────────────────────────────

function _forceStep() {
  const REPEL   = 3200;
  const ATTRACT = 0.04;
  const CENTER  = 0.012;
  const DAMP    = 0.82;
  const cx = _gWidth / 2, cy = _gHeight / 2;

  // Reset forces
  _gNodes.forEach(n => { n.fx = 0; n.fy = 0; });

  // Repulsion between all node pairs
  for (let i = 0; i < _gNodes.length; i++) {
    for (let j = i + 1; j < _gNodes.length; j++) {
      const a = _gNodes[i], b = _gNodes[j];
      const dx = b.x - a.x || 0.01;
      const dy = b.y - a.y || 0.01;
      const dist2 = dx * dx + dy * dy;
      const f = REPEL / Math.max(dist2, 100);
      const fx = f * dx / Math.sqrt(dist2);
      const fy = f * dy / Math.sqrt(dist2);
      a.fx -= fx; a.fy -= fy;
      b.fx += fx; b.fy += fy;
    }
  }

  // Attraction along edges
  _gEdges.forEach(e => {
    const a = _gNodes.find(n => n.id === e.source);
    const b = _gNodes.find(n => n.id === e.target);
    if (!a || !b) return;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const ideal = e.type === 'shared_cookie' ? 120 : 180;
    const f = ATTRACT * (dist - ideal);
    a.fx += f * dx / dist;
    a.fy += f * dy / dist;
    b.fx -= f * dx / dist;
    b.fy -= f * dy / dist;
  });

  // Centre gravity
  _gNodes.forEach(n => {
    n.fx += CENTER * (cx - n.x);
    n.fy += CENTER * (cy - n.y);
  });

  // Integrate
  _gNodes.forEach(n => {
    if (n.pinned) return;
    n.vx = (n.vx + n.fx) * DAMP;
    n.vy = (n.vy + n.fy) * DAMP;
    n.x += n.vx;
    n.y += n.vy;
    // Soft boundary
    const r = NODE_R[n.group] || 10;
    n.x = Math.max(r + 4, Math.min(_gWidth  - r - 4, n.x));
    n.y = Math.max(r + 4, Math.min(_gHeight - r - 4, n.y));
  });
}

// ── SVG rendering ─────────────────────────────────────────────────────────────

function _gRender() {
  if (!_gSvg) return;
  const ns = 'http://www.w3.org/2000/svg';

  // Update edge lines
  _gSvg.querySelectorAll('.g-edge').forEach(el => {
    const e = _gEdges.find(ed => el.dataset.id === `${ed.source}__${ed.target}__${ed.type}`);
    if (!e) return;
    const a = _gNodes.find(n => n.id === e.source);
    const b = _gNodes.find(n => n.id === e.target);
    if (!a || !b) return;
    el.setAttribute('x1', a.x); el.setAttribute('y1', a.y);
    el.setAttribute('x2', b.x); el.setAttribute('y2', b.y);
  });

  // Update node positions
  _gSvg.querySelectorAll('.g-node-group').forEach(g => {
    const n = _gNodes.find(nd => nd.id === g.dataset.id);
    if (!n) return;
    g.setAttribute('transform', `translate(${n.x},${n.y})`);
  });
}

function _gBuild() {
  if (!_gSvg) return;
  const ns = 'http://www.w3.org/2000/svg';
  _gSvg.innerHTML = '';

  // Defs: arrowhead marker
  const defs = document.createElementNS(ns, 'defs');
  defs.innerHTML = `
    <marker id="gArrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L0,6 L6,3 z" fill="rgba(139,69,245,0.5)"/>
    </marker>`;
  _gSvg.appendChild(defs);

  // Edge layer
  const edgeG = document.createElementNS(ns, 'g');
  edgeG.setAttribute('class', 'g-edges');
  _gEdges.forEach(e => {
    const a = _gNodes.find(n => n.id === e.source);
    const b = _gNodes.find(n => n.id === e.target);
    if (!a || !b) return;
    const line = document.createElementNS(ns, 'line');
    line.setAttribute('class', 'g-edge');
    line.dataset.id = `${e.source}__${e.target}__${e.type}`;
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    line.setAttribute('stroke', EDGE_COL[e.type] || 'rgba(139,69,245,0.2)');
    line.setAttribute('stroke-width', e.type === 'shared_cookie' ? '1.5' : '1');
    if (e.type === 'same_session') line.setAttribute('stroke-dasharray', '4 3');
    edgeG.appendChild(line);
  });
  _gSvg.appendChild(edgeG);

  // Node layer
  const nodeG = document.createElementNS(ns, 'g');
  nodeG.setAttribute('class', 'g-nodes');
  _gNodes.forEach(n => {
    const g = document.createElementNS(ns, 'g');
    g.setAttribute('class', 'g-node-group');
    g.dataset.id = n.id;
    g.setAttribute('transform', `translate(${n.x},${n.y})`);
    g.style.cursor = 'grab';

    const r    = NODE_R[n.group] || 10;
    const col  = NODE_COL[n.group];

    // Glow ring for flagged nodes
    if (n.group === 'flagged') {
      const glow = document.createElementNS(ns, 'circle');
      glow.setAttribute('r', r + 6);
      glow.setAttribute('fill', 'rgba(239,68,68,0.12)');
      g.appendChild(glow);
    }

    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('r', r);
    circle.setAttribute('fill', col.fill);
    circle.setAttribute('stroke', col.stroke);
    circle.setAttribute('stroke-width', '1.5');
    g.appendChild(circle);

    // Cookie indicator dot
    if (n.has_cookie) {
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('r', 3);
      dot.setAttribute('cx', r - 2);
      dot.setAttribute('cy', -(r - 2));
      dot.setAttribute('fill', '#60A5FA');
      g.appendChild(dot);
    }

    // Download indicator dot
    if (n.has_download) {
      const dot = document.createElementNS(ns, 'circle');
      dot.setAttribute('r', 3);
      dot.setAttribute('cx', -(r - 2));
      dot.setAttribute('cy', -(r - 2));
      dot.setAttribute('fill', '#F87171');
      g.appendChild(dot);
    }

    // Label
    const label = document.createElementNS(ns, 'text');
    label.setAttribute('y', r + 11);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '9');
    label.setAttribute('font-family', 'Courier New, monospace');
    label.setAttribute('fill', 'var(--text-secondary)');
    label.setAttribute('pointer-events', 'none');
    // Truncate long domain names
    const shortLabel = n.id.length > 22 ? n.id.slice(0, 20) + '…' : n.id;
    label.textContent = shortLabel;
    g.appendChild(label);

    // Visit count badge (only for nodes with significant visits)
    if (n.visits >= 5) {
      const badge = document.createElementNS(ns, 'text');
      badge.setAttribute('y', 3);
      badge.setAttribute('text-anchor', 'middle');
      badge.setAttribute('font-size', n.visits > 99 ? '7' : '8');
      badge.setAttribute('font-weight', 'bold');
      badge.setAttribute('font-family', 'Courier New, monospace');
      badge.setAttribute('fill', 'rgba(255,255,255,0.9)');
      badge.setAttribute('pointer-events', 'none');
      badge.textContent = n.visits > 999 ? '999+' : n.visits;
      g.appendChild(badge);
    }

    // Drag events
    g.addEventListener('mousedown', ev => {
      ev.preventDefault();
      _gDragging = n;
      n.pinned = true;
      g.style.cursor = 'grabbing';
    });

    // Click to inspect domain
    g.addEventListener('click', ev => {
      if (Math.abs(n.vx) < 0.5 && Math.abs(n.vy) < 0.5) {
        const inp = document.getElementById('domainInspectInput');
        if (inp) {
          inp.value = n.id;
          inspectDomain();
          // Scroll to inspector
          inp.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      }
    });

    nodeG.appendChild(g);
  });
  _gSvg.appendChild(nodeG);

  // Tooltip overlay
  const tooltip = document.createElementNS(ns, 'g');
  tooltip.setAttribute('id', 'gTooltip');
  tooltip.style.display = 'none';
  tooltip.setAttribute('pointer-events', 'none');
  const tRect = document.createElementNS(ns, 'rect');
  tRect.setAttribute('rx', '4');
  tRect.setAttribute('fill', 'var(--bg-raised)');
  tRect.setAttribute('stroke', 'var(--border-mid)');
  tRect.setAttribute('stroke-width', '1');
  const tText = document.createElementNS(ns, 'text');
  tText.setAttribute('font-size', '10');
  tText.setAttribute('font-family', 'Courier New, monospace');
  tText.setAttribute('fill', 'var(--text-primary)');
  tooltip.appendChild(tRect);
  tooltip.appendChild(tText);
  _gSvg.appendChild(tooltip);
}

// ── Mouse events ──────────────────────────────────────────────────────────────

function _gAttachSvgEvents() {
  if (!_gSvg) return;

  _gSvg.addEventListener('mousemove', ev => {
    const rect = _gSvg.getBoundingClientRect();
    const mx   = ev.clientX - rect.left;
    const my   = ev.clientY - rect.top;

    if (_gDragging) {
      _gDragging.x  = mx;
      _gDragging.y  = my;
      _gDragging.vx = 0;
      _gDragging.vy = 0;
      return;
    }

    // Hover tooltip
    let hovered = null;
    for (const n of _gNodes) {
      const r = NODE_R[n.group] || 10;
      const dx = n.x - mx, dy = n.y - my;
      if (dx * dx + dy * dy < (r + 4) * (r + 4)) { hovered = n; break; }
    }
    const tip = document.getElementById('gTooltip');
    if (!tip) return;
    if (hovered) {
      const lines = [
        hovered.id,
        `Visits: ${hovered.visits}  Risk: ${hovered.risk}`,
        hovered.has_cookie   ? '● Cookie present'    : '',
        hovered.has_download ? '▼ Download detected' : '',
      ].filter(Boolean);
      const tText = tip.querySelector('text');
      const tRect = tip.querySelector('rect');
      tText.innerHTML = '';
      lines.forEach((l, i) => {
        const ts = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
        ts.setAttribute('x', '8');
        ts.setAttribute('dy', i === 0 ? '14' : '14');
        ts.textContent = l;
        if (i === 0) ts.setAttribute('font-weight', 'bold');
        tText.appendChild(ts);
      });
      const tw = Math.max(...lines.map(l => l.length)) * 6.2 + 16;
      const th = lines.length * 14 + 8;
      tRect.setAttribute('width',  tw);
      tRect.setAttribute('height', th);
      const tx = Math.min(mx + 14, _gWidth  - tw - 8);
      const ty = Math.min(my - 8,  _gHeight - th - 8);
      tip.setAttribute('transform', `translate(${tx},${ty})`);
      tip.style.display = '';
    } else {
      tip.style.display = 'none';
    }
  });

  _gSvg.addEventListener('mouseup', () => {
    if (_gDragging) {
      _gDragging.pinned = false;
      _gDragging = null;
      _gSvg.querySelectorAll('.g-node-group').forEach(g => g.style.cursor = 'grab');
    }
  });

  _gSvg.addEventListener('mouseleave', () => {
    if (_gDragging) { _gDragging.pinned = false; _gDragging = null; }
    const tip = document.getElementById('gTooltip');
    if (tip) tip.style.display = 'none';
  });

  // Zoom / pan with wheel
  _gSvg.addEventListener('wheel', ev => {
    ev.preventDefault();
    const factor = ev.deltaY < 0 ? 1.1 : 0.91;
    const rect = _gSvg.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    _gNodes.forEach(n => {
      n.x = mx + (n.x - mx) * factor;
      n.y = my + (n.y - my) * factor;
    });
  }, { passive: false });
}

// ── Animation loop ────────────────────────────────────────────────────────────

let _gAnimFrame = null;
let _gTick = 0;

function _gLoop() {
  _gTick++;
  // Run physics for 300 ticks then slow down, stop after 2000 ticks to prevent infinite loop
  if (_gTick < 300 || _gDragging) _forceStep();
  _gRender();
  if (_gTick < 2000) {
    _gAnimFrame = requestAnimationFrame(_gLoop);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

async function loadRelationshipGraph() {
  const container = document.getElementById('relationshipGraph');
  if (!container) return;

  container.innerHTML = '<div class="bfx-loading">Building relationship graph…</div>';

  try {
    const data = await API.get('/api/graph');
    if (!data || !data.nodes?.length) {
      container.innerHTML = '<div class="muted" style="padding:14px;font-size:12px;">No domain relationship data available.</div>';
      return;
    }

    _gEdges = data.edges || [];

    // Initial positions: spread nodes in a circle
    _gWidth  = container.offsetWidth  || 700;
    _gHeight = container.offsetHeight || 480;
    const cx = _gWidth / 2, cy = _gHeight / 2;
    _gNodes = data.nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / data.nodes.length;
      const r     = Math.min(_gWidth, _gHeight) * 0.35;
      return {
        ...n,
        x:  cx + r * Math.cos(angle) + (Math.random() - 0.5) * 30,
        y:  cy + r * Math.sin(angle) + (Math.random() - 0.5) * 30,
        vx: 0, vy: 0, fx: 0, fy: 0,
        pinned: false,
      };
    });

    // Build SVG
    container.innerHTML = '';
    _gSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    _gSvg.setAttribute('width',  '100%');
    _gSvg.setAttribute('height', '100%');
    _gSvg.style.display = 'block';
    container.appendChild(_gSvg);

    _gBuild();
    _gAttachSvgEvents();

    // Cancel any previous loop
    if (_gAnimFrame) cancelAnimationFrame(_gAnimFrame);
    _gTick = 0;
    _gLoop();

    // Update legend counts
    const flagged  = _gNodes.filter(n => n.group === 'flagged').length;
    const moderate = _gNodes.filter(n => n.group === 'moderate').length;
    const normal   = _gNodes.filter(n => n.group === 'normal').length;
    const legendEl = document.getElementById('graphLegendCounts');
    if (legendEl) legendEl.textContent =
      `${_gNodes.length} domains · ${_gEdges.length} edges · ${flagged} flagged · ${moderate} moderate`;
  } catch (e) {
    console.error('Error loading relationship graph:', e);
    container.innerHTML = '<div class="muted" style="padding:14px;font-size:12px;">Error loading relationship graph. Check console for details.</div>';
  }
}

function resetGraphLayout() {
  if (!_gNodes.length) return;
  const cx = _gWidth / 2, cy = _gHeight / 2;
  _gNodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / _gNodes.length;
    const r = Math.min(_gWidth, _gHeight) * 0.35;
    n.x  = cx + r * Math.cos(angle) + (Math.random() - 0.5) * 30;
    n.y  = cy + r * Math.sin(angle) + (Math.random() - 0.5) * 30;
    n.vx = 0; n.vy = 0;
  });
  _gTick = 0;
}