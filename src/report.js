const { formatBytes } = require('./insights');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const PALETTE = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#06b6d4', '#a855f7', '#84cc16', '#ec4899', '#14b8a6', '#f97316'];

function renderTreeNode(node, depth = 0) {
  if (!node) return '';
  if (node.type === 'file') {
    return `<div class="tnode file" style="--depth:${depth}">
      <span class="tname">${esc(node.name)}</span>
      <span class="tsize">${esc(formatBytes(node.size))}</span>
    </div>`;
  }
  if (node.type === 'dir-excluded') {
    return `<div class="tnode dir excluded" style="--depth:${depth}">
      <span class="tname">${esc(node.name)}/ <em>(excluded from tree, size counted)</em></span>
      <span class="tsize">${esc(formatBytes(node.size))}</span>
    </div>`;
  }
  const children = node.children.map((c) => renderTreeNode(c, depth + 1)).join('');
  return `<details class="tnode dir" style="--depth:${depth}" ${depth < 2 ? 'open' : ''}>
    <summary><span class="tname">${esc(node.name)}/</span><span class="tsize">${esc(formatBytes(node.size))}</span></summary>
    ${children}
  </details>`;
}

function renderLangBars(languageStats, totalSize) {
  const entries = Object.entries(languageStats).sort((a, b) => b[1].size - a[1].size).slice(0, 10);
  return entries.map(([lang, stats], i) => {
    const pct = totalSize ? (stats.size / totalSize) * 100 : 0;
    const color = PALETTE[i % PALETTE.length];
    return `<div class="langrow">
      <div class="langlabel"><span class="dot" style="background:${color}"></span>${esc(lang)} <span class="muted">(${stats.count})</span></div>
      <div class="langbar-track"><div class="langbar-fill" style="width:${pct.toFixed(1)}%;background:${color}"></div></div>
      <div class="langpct">${pct.toFixed(1)}%</div>
    </div>`;
  }).join('');
}

function renderLargestFiles(files) {
  const max = files.length ? files[0].size : 1;
  return files.map((f) => {
    const pct = max ? (f.size / max) * 100 : 0;
    return `<div class="filerow">
      <div class="filepath">${esc(f.path)}</div>
      <div class="filebar-track"><div class="filebar-fill" style="width:${pct.toFixed(1)}%"></div></div>
      <div class="filesize">${esc(formatBytes(f.size))}</div>
    </div>`;
  }).join('');
}

function severityBadge(sev) {
  const cls = { critical: 'sev-critical', high: 'sev-high', moderate: 'sev-moderate', low: 'sev-low', info: 'sev-info' }[sev] || 'sev-info';
  return `<span class="badge ${cls}">${esc(sev || 'info')}</span>`;
}

function renderSecurity(security) {
  const { npm, manifests } = security;
  let html = `<div class="manifests">${manifests.length ? manifests.map((m) => `<span class="chip">${esc(m)}</span>`).join('') : '<span class="muted">No recognized package manifests found.</span>'}</div>`;

  if (!npm.available) {
    html += `<p class="muted">npm audit unavailable - ${esc(npm.reason || 'unknown reason')}.</p>`;
    return html;
  }

  const v = npm.vulnerabilities;
  html += `<div class="sevcards">
    ${['critical', 'high', 'moderate', 'low'].map((s) => `<div class="sevcard ${'sev-' + s}"><div class="sevcount">${v[s] || 0}</div><div class="sevlabel">${s}</div></div>`).join('')}
  </div>`;

  if (npm.advisories.length) {
    html += `<table class="datatable"><thead><tr><th>Package</th><th>Severity</th><th>Details</th><th>Fix</th></tr></thead><tbody>`;
    for (const a of npm.advisories.slice(0, 30)) {
      html += `<tr><td>${esc(a.name)}</td><td>${severityBadge(a.severity)}</td><td class="muted">${esc((a.via || []).join(', ') || '-')}</td><td>${a.fixAvailable ? 'available' : 'manual'}</td></tr>`;
    }
    html += `</tbody></table>`;
  } else {
    html += `<p class="ok">No known vulnerabilities found.</p>`;
  }

  if (npm.outdated.length) {
    html += `<h3>Outdated packages</h3><table class="datatable"><thead><tr><th>Package</th><th>Current</th><th>Wanted</th><th>Latest</th></tr></thead><tbody>`;
    for (const o of npm.outdated.slice(0, 40)) {
      html += `<tr><td>${esc(o.name)}</td><td>${esc(o.current)}</td><td>${esc(o.wanted)}</td><td>${esc(o.latest)}</td></tr>`;
    }
    html += `</tbody></table>`;
  } else {
    html += `<p class="ok">All dependencies up to date.</p>`;
  }

  return html;
}

function buildHtmlReport({ scanResult, security, insights }) {
  const { root, totalFiles, totalSize, languageStats, largestFiles, scannedAt } = scanResult;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CodeScope Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    --bg: #0b0d12; --panel: #12151c; --panel2: #171b24; --border: #262b36;
    --text: #e8eaf0; --muted: #8b93a7; --accent: #6366f1;
    --ok: #22c55e; --warn: #f59e0b; --bad: #ef4444;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f5f6f9; --panel:#ffffff; --panel2:#f0f1f5; --border:#e2e4ea; --text:#161923; --muted:#5c6272; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif; line-height:1.5; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 80px; }
  header h1 { font-size: 1.6rem; margin:0 0 4px; }
  header .sub { color: var(--muted); font-size: 0.9rem; margin-bottom: 28px; word-break: break-all; }
  .cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap:14px; margin-bottom:32px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; }
  .card .n { font-size:1.6rem; font-weight:700; }
  .card .l { color:var(--muted); font-size:0.8rem; text-transform:uppercase; letter-spacing:.04em; }
  section { margin-bottom: 36px; }
  section h2 { font-size:1.1rem; border-bottom:1px solid var(--border); padding-bottom:10px; margin-bottom:16px; }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px; }
  .langrow { display:grid; grid-template-columns: 200px 1fr 60px; align-items:center; gap:10px; margin-bottom:8px; font-size:0.85rem; }
  .langlabel { display:flex; align-items:center; gap:8px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .dot { width:9px; height:9px; border-radius:50%; flex-shrink:0; }
  .langbar-track { background:var(--panel2); border-radius:6px; height:10px; overflow:hidden; }
  .langbar-fill { height:100%; border-radius:6px; }
  .langpct { text-align:right; color:var(--muted); }
  .filerow { display:grid; grid-template-columns: 1fr 200px 90px; align-items:center; gap:10px; margin-bottom:7px; font-size:0.82rem; }
  .filepath { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .filebar-track { background:var(--panel2); border-radius:6px; height:8px; overflow:hidden; }
  .filebar-fill { height:100%; background: var(--accent); border-radius:6px; }
  .filesize { text-align:right; color:var(--muted); font-variant-numeric: tabular-nums; }
  .muted { color: var(--muted); }
  .ok { color: var(--ok); }
  .insights { list-style:none; padding:0; margin:0; }
  .insights li { padding:12px 14px; background:var(--panel2); border-radius:10px; margin-bottom:8px; font-size:0.92rem; border-left:3px solid var(--accent); }
  .manifests { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px; }
  .chip { background:var(--panel2); border:1px solid var(--border); padding:4px 10px; border-radius:999px; font-size:0.78rem; }
  .sevcards { display:grid; grid-template-columns: repeat(4,1fr); gap:10px; margin:16px 0 20px; }
  .sevcard { text-align:center; padding:14px 8px; border-radius:10px; background:var(--panel2); }
  .sevcard .sevcount { font-size:1.4rem; font-weight:700; }
  .sevcard .sevlabel { color:var(--muted); font-size:0.75rem; text-transform:uppercase; }
  .sev-critical .sevcount, .badge.sev-critical { color:#fff; }
  .badge { padding:2px 8px; border-radius:6px; font-size:0.75rem; text-transform:capitalize; }
  .badge.sev-critical { background:#dc2626; }
  .badge.sev-high { background:#f97316; color:#fff; }
  .badge.sev-moderate { background:#f59e0b; color:#1a1a1a; }
  .badge.sev-low { background:#84cc16; color:#1a1a1a; }
  .badge.sev-info { background:#64748b; color:#fff; }
  .sevcard.sev-critical { border-left:3px solid #dc2626; } .sevcard.sev-high { border-left:3px solid #f97316; }
  .sevcard.sev-moderate { border-left:3px solid #f59e0b; } .sevcard.sev-low { border-left:3px solid #84cc16; }
  table.datatable { width:100%; border-collapse:collapse; font-size:0.82rem; margin-top:8px; }
  table.datatable th, table.datatable td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); }
  table.datatable th { color:var(--muted); font-weight:600; text-transform:uppercase; font-size:0.7rem; letter-spacing:.03em; }
  .tree { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:0.82rem; max-height:520px; overflow:auto; }
  .tnode { padding: 3px 0 3px calc(var(--depth) * 16px); display:flex; justify-content:space-between; gap:10px; }
  .tnode.dir > summary { cursor:pointer; display:flex; justify-content:space-between; padding:3px 0; list-style:none; }
  .tnode.dir > summary::-webkit-details-marker { display:none; }
  .tnode.dir > summary::before { content:'▸ '; color:var(--muted); }
  .tnode.dir[open] > summary::before { content:'▾ '; }
  .tnode.excluded .tname em { color: var(--muted); font-style:normal; font-size:0.78em; }
  .tsize { color:var(--muted); white-space:nowrap; }
  footer { text-align:center; color:var(--muted); font-size:0.78rem; margin-top:40px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>CodeScope Report</h1>
    <div class="sub">${esc(root)} &middot; generated ${esc(new Date(scannedAt).toLocaleString())}</div>
  </header>

  <div class="cards">
    <div class="card"><div class="n">${totalFiles.toLocaleString()}</div><div class="l">Files scanned</div></div>
    <div class="card"><div class="n">${formatBytes(totalSize)}</div><div class="l">Total size</div></div>
    <div class="card"><div class="n">${Object.keys(languageStats).length}</div><div class="l">Languages / types</div></div>
    <div class="card"><div class="n">${security.npm.available ? (security.npm.vulnerabilities.total ?? Object.values(security.npm.vulnerabilities).reduce((a,b)=>a+b,0)) : '-'}</div><div class="l">Vulnerabilities</div></div>
  </div>

  <section>
    <h2>AI-Generated Insights</h2>
    <ul class="insights">
      ${insights.map((i) => `<li>${esc(i)}</li>`).join('') || '<li>No notable findings.</li>'}
    </ul>
  </section>

  <section>
    <h2>Language / File-Type Breakdown</h2>
    <div class="panel">${renderLangBars(languageStats, totalSize)}</div>
  </section>

  <section>
    <h2>Largest Files</h2>
    <div class="panel">${renderLargestFiles(largestFiles)}</div>
  </section>

  <section>
    <h2>File Tree Map</h2>
    <div class="panel tree">${renderTreeNode(scanResult.tree)}</div>
  </section>

  <section>
    <h2>Dependency Security &amp; Freshness</h2>
    <div class="panel">${renderSecurity(security)}</div>
  </section>

  <footer>Generated by CodeScope - a local static analysis tool. No data leaves your machine.</footer>
</div>
</body>
</html>`;
}

module.exports = { buildHtmlReport };
