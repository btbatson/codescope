(() => {
  const svg = document.getElementById('graphSvg');
  const viewport = document.getElementById('viewport');
  const graphArea = document.getElementById('graphArea');
  const panel = document.getElementById('panel');
  const legend = document.getElementById('legend');
  const loadingEl = document.getElementById('loading');

  const MAX_VISIBLE_CHILDREN = 14;

  let data = null;
  let stack = [];
  let selected = null;
  let zoom = 1;
  let pan = { x: 0, y: 0 };
  let dragging = null;
  let currentNodes = [];
  let animHandle = null;
  let currentProjectId = null;
  let aiKeyConfigured = false;

  function apiUrl(pathAndQuery) {
    if (!currentProjectId) return pathAndQuery;
    const sep = pathAndQuery.includes('?') ? '&' : '?';
    return `${pathAndQuery}${sep}project=${encodeURIComponent(currentProjectId)}`;
  }

  const NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs = {}) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  // ---------- file-type icons (24x24 grid, straight-line glyphs) ----------
  const ICON_GENERIC = { color: '#6b7280', d: 'M6 2 L15 2 L20 7 L20 22 L6 22 Z M15 2 L15 7 L20 7' };
  const ICON_CATEGORIES = [
    {
      exts: ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp'],
      color: '#f59e0b',
      d: 'M4 5 L20 5 L20 19 L4 19 Z M9 9 L10 9 L10 10 L9 10 Z M4 17 L9 12 L12 15 L15 11 L20 16',
    },
    {
      exts: ['.js', '.jsx', '.mjs', '.ts', '.tsx', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift', '.c', '.h', '.cpp', '.hpp', '.cs', '.php', '.vue', '.sh'],
      color: '#6366f1',
      d: 'M9 6 L3 12 L9 18 M15 6 L21 12 L15 18',
    },
    {
      exts: ['.css', '.scss', '.less'],
      color: '#ec4899',
      d: 'M9 3 L7 21 M17 3 L15 21 M4 9 L20 9 M3 15 L19 15',
    },
    {
      exts: ['.json', '.yaml', '.yml', '.toml', '.csv', '.sql'],
      color: '#10b981',
      d: 'M10 4 L8 4 L8 10 L6 12 L8 14 L8 20 L10 20 M14 4 L16 4 L16 10 L18 12 L16 14 L16 20 L14 20',
    },
    {
      exts: ['.md', '.txt', '.pdf', '.rst'],
      color: '#0ea5e9',
      d: 'M5 3 L19 3 L19 21 L5 21 Z M8 8 L16 8 M8 12 L16 12 M8 16 L13 16',
    },
    {
      exts: ['.zip', '.tar', '.gz', '.rar', '.7z'],
      color: '#a855f7',
      d: 'M4 6 L20 6 L20 20 L4 20 Z M4 6 L4 3 L20 3 L20 6 M10 10 L14 10 M10 14 L14 14',
    },
  ];
  const CONFIG_NAMES = new Set(['.gitignore', '.editorconfig', '.npmrc', '.env', '.env.example', 'dockerfile', 'makefile', '.gitattributes']);
  const ICON_CONFIG = { color: '#94a3b8', d: 'M4 6 L20 6 M4 12 L20 12 M4 18 L20 18' };

  function iconFor(node) {
    const nameLower = (node.name || '').toLowerCase();
    if (CONFIG_NAMES.has(nameLower) || /\.(lock|config)\./.test(nameLower) || nameLower.includes('config')) {
      return ICON_CONFIG;
    }
    const ext = (node.ext || '').toLowerCase();
    for (const cat of ICON_CATEGORIES) {
      if (cat.exts.includes(ext)) return cat;
    }
    return ICON_GENERIC;
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
  }

  function formatDate(ms) {
    if (!ms) return '-';
    return new Date(ms).toLocaleString();
  }

  // ---------- data fetch ----------
  let searchIndex = [];

  function buildSearchIndex(node, out = []) {
    if (!node) return out;
    out.push(node);
    if (node.type === 'dir') {
      for (const child of node.children) buildSearchIndex(child, out);
    }
    return out;
  }

  // ---------- security flagging ----------
  let flaggedPaths = new Set(); // exact file paths with a direct issue
  let flaggedVulnManifests = new Set(); // manifest files implicated by dependency vulnerabilities

  function computeFlagging() {
    flaggedPaths = new Set((data.secrets && data.secrets.findings || []).map((f) => f.file));

    flaggedVulnManifests = new Set();
    const hasNpmVulns = data.security.npm && data.security.npm.available
      && Object.values(data.security.npm.vulnerabilities).some((v) => v > 0);
    const hasComposerVulns = data.security.composer && data.security.composer.available
      && data.security.composer.advisories.length > 0;
    if (hasNpmVulns || hasComposerVulns) {
      const manifestNames = new Set(['package.json', 'package-lock.json', 'composer.json', 'composer.lock']);
      searchIndex.forEach((n) => {
        if (n.type === 'file' && manifestNames.has(n.name)) flaggedVulnManifests.add(n.path);
      });
    }
  }

  // True for the exact flagged file/manifest, or any folder containing one beneath it.
  function isPathFlagged(nodePath) {
    if (flaggedPaths.has(nodePath) || flaggedVulnManifests.has(nodePath)) return true;
    const prefix = nodePath + '/';
    for (const p of flaggedPaths) if (p.startsWith(prefix)) return true;
    for (const p of flaggedVulnManifests) if (p.startsWith(prefix)) return true;
    return false;
  }

  async function loadProjectData() {
    const res = await fetch(apiUrl('/api/data'));
    data = await res.json();
    if (data.empty) {
      loadingEl.classList.add('hidden');
      showEmptyState();
      return;
    }
    const hint = document.getElementById('graphHint');
    if (hint) hint.textContent = 'Click a folder to explore. Click a file for details.';
    stack = [data.scanResult.tree];
    selected = data.scanResult.tree;
    searchIndex = buildSearchIndex(data.scanResult.tree);
    computeFlagging();
    loadingEl.classList.add('hidden');
    render();
  }

  // Shown on a fresh no-local-project deployment (e.g. the hosted Vercel
  // demo) before any repo has been added - points the user at "Add repo"
  // instead of leaving a blank graph.
  function showEmptyState() {
    const hint = document.getElementById('graphHint');
    if (hint) {
      hint.textContent = 'No project loaded yet - add a repository to analyze it.';
      hint.classList.remove('hidden');
    }
    const addRepoModal = document.getElementById('addRepoModal');
    if (addRepoModal) addRepoModal.classList.remove('hidden');
  }

  // ---------- project switcher ----------
  const projectSwitcherWrap = document.getElementById('projectSwitcherWrap');
  const projectSwitcherBtn = document.getElementById('projectSwitcherBtn');
  const projectSwitcherLabel = document.getElementById('projectSwitcherLabel');
  const projectSwitcherMenu = document.getElementById('projectSwitcherMenu');

  let knownProjects = [];
  let switcherWired = false;

  function renderProjectMenu() {
    projectSwitcherLabel.textContent = (knownProjects.find((p) => p.id === currentProjectId) || {}).name || 'Project';
    projectSwitcherMenu.innerHTML = '';
    knownProjects.forEach((p) => {
      const btn = document.createElement('button');
      btn.textContent = p.mode === 'live' ? `${p.name} (live)` : p.name;
      btn.title = p.mode === 'live' ? 'Fetched live from GitHub - no local clone' : '';
      btn.className = p.id === currentProjectId ? 'active' : '';
      btn.addEventListener('click', async () => {
        if (p.id === currentProjectId) { projectSwitcherMenu.classList.add('hidden'); return; }
        currentProjectId = p.id;
        projectSwitcherMenu.classList.add('hidden');
        loadingEl.classList.remove('hidden');
        await loadProjectData();
        renderProjectMenu();
      });
      projectSwitcherMenu.appendChild(btn);
    });
  }

  // Re-fetches the project list. Safe to call repeatedly (e.g. after adding
  // a repo) - doesn't reset the current selection unless told to, and only
  // wires up the switcher's own toggle/outside-click listeners once.
  async function loadProjects({ selectId } = {}) {
    const res = await fetch('/api/projects');
    knownProjects = await res.json();

    if (selectId) currentProjectId = selectId;
    else if (!currentProjectId && knownProjects.length) currentProjectId = knownProjects[0].id;

    projectSwitcherWrap.classList.toggle('hidden', knownProjects.length <= 1);
    renderProjectMenu();

    if (!switcherWired) {
      switcherWired = true;
      projectSwitcherBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        projectSwitcherMenu.classList.toggle('hidden');
      });
      document.addEventListener('click', () => projectSwitcherMenu.classList.add('hidden'));
    }
  }

  async function load() {
    await loadProjects();
    await loadProjectData();
  }

  document.getElementById('rescanBtn').addEventListener('click', async () => {
    loadingEl.classList.remove('hidden');
    const res = await fetch(apiUrl('/api/rescan'), { method: 'POST' });
    data = await res.json();
    stack = [data.scanResult.tree];
    selected = data.scanResult.tree;
    searchIndex = buildSearchIndex(data.scanResult.tree);
    computeFlagging();
    loadingEl.classList.add('hidden');
    render();
  });

  document.getElementById('panelCollapse').addEventListener('click', () => {
    panel.classList.toggle('collapsed');
    const btn = document.getElementById('panelCollapse');
    btn.innerHTML = panel.classList.contains('collapsed') ? '&lsaquo;' : '&rsaquo;';
  });

  // ---------- settings modal ----------
  const settingsModal = document.getElementById('settingsModal');
  const settingsDot = document.getElementById('settingsDot');
  const settingsStatus = document.getElementById('settingsStatus');
  const apiKeyInput = document.getElementById('apiKeyInput');
  const apiKeyRemove = document.getElementById('apiKeyRemove');

  const webhookStatus = document.getElementById('webhookStatus');
  const webhookInput = document.getElementById('webhookInput');
  const webhookRemove = document.getElementById('webhookRemove');

  function renderSettingsStatus(status) {
    const keyStateChanged = aiKeyConfigured !== status.hasApiKey;
    aiKeyConfigured = status.hasApiKey;
    if (keyStateChanged && selected) renderDetails(selected);

    settingsDot.classList.toggle('hidden', !status.hasApiKey && !status.hasWebhook);
    apiKeyRemove.classList.toggle('hidden', !status.hasApiKey);
    settingsStatus.classList.remove('error');
    if (status.hasApiKey) {
      settingsStatus.textContent = `Active key: ${status.keyPreview}`;
      settingsStatus.classList.add('active');
    } else {
      settingsStatus.textContent = 'No API key configured - summaries use the local analysis engine.';
      settingsStatus.classList.remove('active');
    }

    webhookRemove.classList.toggle('hidden', !status.hasWebhook);
    webhookStatus.classList.remove('error');
    if (status.hasWebhook) {
      webhookStatus.textContent = `Active webhook: ${status.webhookPreview}`;
      webhookStatus.classList.add('active');
    } else {
      webhookStatus.textContent = 'No webhook configured - rescans stay local-only.';
      webhookStatus.classList.remove('active');
    }
  }

  function renderSettingsError(message) {
    settingsStatus.textContent = message;
    settingsStatus.classList.remove('active');
    settingsStatus.classList.add('error');
  }

  async function refreshSettingsStatus() {
    const res = await fetch('/api/settings');
    renderSettingsStatus(await res.json());
  }

  document.getElementById('settingsBtn').addEventListener('click', () => {
    settingsModal.classList.remove('hidden');
    apiKeyInput.value = '';
    refreshSettingsStatus();
  });
  document.getElementById('settingsClose').addEventListener('click', () => {
    settingsModal.classList.add('hidden');
  });
  settingsModal.addEventListener('click', (e) => {
    if (e.target === settingsModal) settingsModal.classList.add('hidden');
  });

  document.getElementById('apiKeySave').addEventListener('click', async () => {
    const apiKey = apiKeyInput.value.trim();
    if (!apiKey) return;
    const saveBtn = document.getElementById('apiKeySave');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving…';
    try {
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey }),
      });
      const json = await res.json();
      if (!res.ok) {
        renderSettingsError(json.error || 'Could not save that key.');
      } else {
        renderSettingsStatus(json);
        apiKeyInput.value = '';
      }
    } catch {
      renderSettingsError('Could not reach the server to save the key.');
    }
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save key';
  });

  apiKeyRemove.addEventListener('click', async () => {
    const res = await fetch('/api/settings', { method: 'DELETE' });
    renderSettingsStatus(await res.json());
  });

  document.getElementById('webhookSave').addEventListener('click', async () => {
    const webhookUrl = webhookInput.value.trim();
    if (!webhookUrl) return;
    const saveBtn = document.getElementById('webhookSave');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving…';
    try {
      const res = await fetch('/api/settings/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ webhookUrl }),
      });
      const json = await res.json();
      if (!res.ok) {
        webhookStatus.textContent = json.error || 'Could not save that webhook.';
        webhookStatus.classList.add('error');
      } else {
        renderSettingsStatus(json);
        webhookInput.value = '';
      }
    } catch {
      webhookStatus.textContent = 'Could not reach the server to save the webhook.';
      webhookStatus.classList.add('error');
    }
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save webhook';
  });

  webhookRemove.addEventListener('click', async () => {
    const res = await fetch('/api/settings/webhook', { method: 'DELETE' });
    renderSettingsStatus(await res.json());
  });

  refreshSettingsStatus();

  // ---------- search ----------
  const searchInput = document.getElementById('searchInput');
  const searchResults = document.getElementById('searchResults');

  function findAncestorChain(root, targetPath) {
    if (root.path === targetPath) return [root];
    if (root.type !== 'dir') return null;
    for (const child of root.children) {
      const chain = findAncestorChain(child, targetPath);
      if (chain) return [root, ...chain];
    }
    return null;
  }

  function navigateToNode(node) {
    const chain = findAncestorChain(data.scanResult.tree, node.path);
    if (!chain) return;
    stack = node.type === 'dir' ? chain : chain.slice(0, -1);
    selected = node;
    render();
    switchToDetailsTab();
    const match = currentNodes.find((n) => n.data && n.data.path === node.path);
    if (match) pulseElement(match.el);
  }

  function renderSearchResults(query) {
    if (!query) {
      searchResults.classList.add('hidden');
      searchResults.innerHTML = '';
      return;
    }
    const q = query.toLowerCase();
    const matches = searchIndex
      .filter((n) => n.type !== 'dir-excluded' && n.name.toLowerCase().includes(q))
      .slice(0, 20);

    searchResults.innerHTML = '';
    if (!matches.length) {
      const empty = document.createElement('div');
      empty.className = 'search-empty';
      empty.textContent = 'No matches.';
      searchResults.appendChild(empty);
    } else {
      matches.forEach((n) => {
        const row = document.createElement('div');
        row.className = 'search-result';
        row.innerHTML = `<div class="search-result-name">${esc(n.name)}</div><div class="search-result-path">${esc(n.path)}</div>`;
        row.addEventListener('click', () => {
          navigateToNode(n);
          searchResults.classList.add('hidden');
          searchInput.value = '';
        });
        searchResults.appendChild(row);
      });
    }
    searchResults.classList.remove('hidden');
  }

  searchInput.addEventListener('input', () => renderSearchResults(searchInput.value.trim()));
  searchInput.addEventListener('focus', () => {
    if (searchInput.value.trim()) searchResults.classList.remove('hidden');
  });
  document.addEventListener('click', (e) => {
    if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
      searchResults.classList.add('hidden');
    }
  });

  // ---------- keyboard shortcuts ----------
  document.addEventListener('keydown', (e) => {
    const tag = document.activeElement && document.activeElement.tagName;
    const typing = tag === 'INPUT' || tag === 'TEXTAREA';

    if (e.key === '/' && !typing) {
      e.preventDefault();
      searchInput.focus();
      return;
    }
    if (e.key === 'Escape') {
      if (!settingsModal.classList.contains('hidden')) settingsModal.classList.add('hidden');
      if (!securityModal.classList.contains('hidden')) securityModal.classList.add('hidden');
      if (!searchResults.classList.contains('hidden')) {
        searchResults.classList.add('hidden');
        searchInput.blur();
      }
    }
  });

  // ---------- tabs ----------
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach((p) => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ---------- appearance ----------
  const appearanceBtn = document.getElementById('appearanceBtn');
  const appearanceMenu = document.getElementById('appearanceMenu');
  const appearanceLabel = document.getElementById('appearanceLabel');
  appearanceBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    appearanceMenu.classList.toggle('hidden');
  });
  document.addEventListener('click', () => appearanceMenu.classList.add('hidden'));
  appearanceMenu.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => setTheme(btn.dataset.theme));
  });
  function setTheme(mode) {
    localStorage.setItem('codescope-theme', mode);
    applyTheme(mode);
  }
  function applyTheme(mode) {
    if (mode === 'system') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', mode);
    }
    appearanceLabel.textContent = 'Appearance: ' + mode[0].toUpperCase() + mode.slice(1);
    appearanceMenu.querySelectorAll('button').forEach((b) => b.classList.toggle('active', b.dataset.theme === mode));
  }
  applyTheme(localStorage.getItem('codescope-theme') || 'system');

  // ---------- breadcrumb ----------
  function renderBreadcrumb() {
    const bc = document.getElementById('breadcrumb');
    bc.innerHTML = '';

    const brand = document.createElement('span');
    brand.className = 'brand';
    brand.textContent = (data.stack && data.stack.name) || stack[0].name;
    brand.addEventListener('click', () => {
      if (stack.length === 1) return;
      stack = [data.scanResult.tree];
      selected = data.scanResult.tree;
      render();
    });
    bc.appendChild(brand);

    stack.slice(1).forEach((node, idx) => {
      const i = idx + 1;
      const sep = document.createElement('span');
      sep.className = 'sep';
      sep.textContent = '/';
      bc.appendChild(sep);

      const crumb = document.createElement('span');
      crumb.className = 'crumb' + (i === stack.length - 1 ? ' current' : '');
      crumb.textContent = node.name;
      crumb.addEventListener('click', () => {
        if (i === stack.length - 1) return;
        stack = stack.slice(0, i + 1);
        selected = node;
        render();
      });
      bc.appendChild(crumb);
    });
  }

  // ---------- layout ----------
  function radiusFor(size, isCenter) {
    const r = Math.log2((size || 1) + 1) * 2.1;
    const base = isCenter ? 24 : 10;
    const cap = isCenter ? 44 : 34;
    return Math.max(base, Math.min(cap, base + r));
  }

  // Cap how many nodes render at once so folders with lots of files stay readable.
  // The largest items get their own node; everything else collapses into one
  // "N more items" node the user can inspect in the Details panel.
  function prepareChildren(children) {
    const normal = children.filter((c) => c.type !== 'dir-excluded');
    const excluded = children.filter((c) => c.type === 'dir-excluded');
    const all = [...normal, ...excluded].sort((a, b) => b.size - a.size);
    if (all.length <= MAX_VISIBLE_CHILDREN) return all;
    const visible = all.slice(0, MAX_VISIBLE_CHILDREN - 1);
    const rest = all.slice(MAX_VISIBLE_CHILDREN - 1);
    const restSize = rest.reduce((sum, c) => sum + c.size, 0);
    return [...visible, {
      name: `${rest.length} more item${rest.length === 1 ? '' : 's'}`,
      path: null,
      type: 'aggregate',
      size: restSize,
      items: rest,
    }];
  }

  function computeLayout(centerNode, children, width, height) {
    const cx = width / 2, cy = height / 2;
    const nodes = [{ id: '__center__', x: cx, y: cy, vx: 0, vy: 0, r: radiusFor(centerNode.size, true), data: centerNode, isCenter: true }];
    children.forEach((c, i) => {
      const angle = (i / children.length) * Math.PI * 2 + (i % 2 === 0 ? 0.08 : -0.08);
      const dist = 210 + (i % 4) * 48 + (Math.random() * 30);
      nodes.push({
        id: c.path || `agg-${i}`, x: cx + Math.cos(angle) * dist, y: cy + Math.sin(angle) * dist,
        vx: 0, vy: 0, r: radiusFor(c.size, false), data: c,
        freq: 0.12 + Math.random() * 0.12,
        phaseX: Math.random() * Math.PI * 2,
        phaseY: Math.random() * Math.PI * 2,
        ampX: 2 + Math.random() * 3,
        ampY: 2 + Math.random() * 3,
      });
    });
    const links = children.map((c, i) => [0, i + 1]);

    for (let iter = 0; iter < 180; iter++) {
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let distSq = dx * dx + dy * dy || 0.01;
          let dist = Math.sqrt(distSq);
          const minDist = a.r + b.r + 46;
          let force = Math.min(3600 / distSq, 5);
          if (dist < minDist) force += (minDist - dist) * 0.03;
          const fx = (dx / dist) * force, fy = (dy / dist) * force;
          a.vx -= fx; a.vy -= fy;
          b.vx += fx; b.vy += fy;
        }
      }
      links.forEach(([ai, bi]) => {
        const a = nodes[ai], b = nodes[bi];
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const rest = 150 + b.r;
        const force = (dist - rest) * 0.025;
        const fx = (dx / dist) * force, fy = (dy / dist) * force;
        if (!a.isCenter) { a.vx += fx; a.vy += fy; }
        b.vx -= fx; b.vy -= fy;
      });
      nodes.forEach((n) => {
        if (n.isCenter) { n.x = cx; n.y = cy; n.vx = 0; n.vy = 0; return; }
        n.vx += (cx - n.x) * 0.0006;
        n.vy += (cy - n.y) * 0.0006;
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += n.vx; n.y += n.vy;
      });
    }
    return nodes;
  }

  // ---------- graph render ----------
  function render() {
    if (animHandle) cancelAnimationFrame(animHandle);

    renderBreadcrumb();
    const current = stack[stack.length - 1];
    const children = prepareChildren(current.children || []);

    const rect = graphArea.getBoundingClientRect();
    const width = rect.width, height = rect.height;
    const nodes = computeLayout(current, children, width, height);
    currentNodes = nodes;

    viewport.innerHTML = '';
    zoom = 1; pan = { x: 0, y: 0 };
    applyTransform();

    // edges
    for (let i = 1; i < nodes.length; i++) {
      const n = nodes[i];
      const line = el('line', {
        class: 'edge-line', x1: nodes[0].x, y1: nodes[0].y, x2: n.x, y2: n.y,
      });
      n.edge = line;
      viewport.appendChild(line);
    }

    // nodes
    nodes.forEach((n) => {
      const isAggregate = n.data.type === 'aggregate';
      const isDir = n.isCenter || n.data.type === 'dir' || n.data.type === 'dir-excluded';
      const kind = isAggregate ? 'aggregate' : (isDir ? 'folder' : 'file');
      const flagged = n.data.path ? isPathFlagged(n.data.path) : false;
      const g = el('g', {
        class: 'node-group ' + kind + (n.isCenter ? ' center' : '') + (selected === n.data ? ' selected' : '') + (flagged ? ' flagged' : ''),
        transform: `translate(${n.x},${n.y})`,
      });

      const ring = el('circle', { class: 'node-ring', r: n.r + 6, cx: 0, cy: 0 });
      g.appendChild(ring);

      if (kind === 'file') {
        const icon = iconFor(n.data);
        const dotR = n.r * 0.46;
        const bg = el('circle', { class: 'node-file-bg', r: dotR, cx: 0, cy: 0, fill: 'var(--panel-bg)', stroke: icon.color });
        const iconSize = dotR * 1.35;
        const glyph = el('path', {
          d: icon.d,
          transform: `translate(${-iconSize / 2},${-iconSize / 2}) scale(${iconSize / 24})`,
          stroke: icon.color, fill: 'none', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
        });
        g.appendChild(bg);
        g.appendChild(glyph);
      } else {
        const dot = el('circle', { class: 'node-dot', r: n.r * 0.42, cx: 0, cy: 0 });
        g.appendChild(dot);
      }

      if (flagged) {
        const badgeR = Math.max(7, n.r * 0.28);
        const bx = n.r * 0.62, by = -n.r * 0.62;
        const badgeBg = el('circle', { class: 'security-badge-bg', r: badgeR, cx: bx, cy: by });
        const badgeText = el('text', { class: 'security-badge-text', x: bx, y: by + badgeR * 0.38, 'text-anchor': 'middle' });
        badgeText.textContent = '!';
        g.appendChild(badgeBg);
        g.appendChild(badgeText);
      }

      const label = el('text', { class: 'node-label', x: n.r + 12, y: 4 });
      label.textContent = n.data.name + (isDir && !n.isCenter && !isAggregate ? '/' : '');
      const sub = el('text', { class: 'node-sub', x: n.r + 12, y: 18 });
      sub.textContent = formatBytes(n.data.size);

      if (n.x < width / 2 - 40 && !n.isCenter) {
        label.setAttribute('x', -(n.r + 12));
        label.setAttribute('text-anchor', 'end');
        sub.setAttribute('x', -(n.r + 12));
        sub.setAttribute('text-anchor', 'end');
      }

      g.appendChild(label);
      g.appendChild(sub);

      g.addEventListener('click', (e) => {
        e.stopPropagation();
        handleNodeClick(n);
      });

      n.el = g;
      viewport.appendChild(g);
    });

    renderDetails(selected);
    renderAnalysis();
    animHandle = requestAnimationFrame(animate);
  }

  function animate(ts) {
    animHandle = requestAnimationFrame(animate);
    const t = ts * 0.001;
    currentNodes.forEach((n) => {
      if (n.isCenter || !n.el) return;
      const ox = Math.sin(t * n.freq + n.phaseX) * n.ampX;
      const oy = Math.cos(t * n.freq * 1.3 + n.phaseY) * n.ampY;
      const nx = n.x + ox, ny = n.y + oy;
      n.el.setAttribute('transform', `translate(${nx},${ny})`);
      if (n.edge) {
        n.edge.setAttribute('x2', nx);
        n.edge.setAttribute('y2', ny);
      }
    });
  }

  function pulseElement(elm) {
    if (!elm) return;
    elm.classList.remove('pulse');
    void elm.getBoundingClientRect(); // force reflow so the animation restarts
    elm.classList.add('pulse');
    elm.addEventListener('animationend', () => elm.classList.remove('pulse'), { once: true });
  }

  function switchToDetailsTab() {
    const detailsBtn = document.querySelector('.tab-btn[data-tab="details"]');
    if (detailsBtn && !detailsBtn.classList.contains('active')) detailsBtn.click();
  }

  function switchToAnalysisTab() {
    const analysisBtn = document.querySelector('.tab-btn[data-tab="analysis"]');
    if (analysisBtn && !analysisBtn.classList.contains('active')) analysisBtn.click();
  }

  function handleNodeClick(n) {
    switchToDetailsTab();

    if (n.isCenter) {
      if (stack.length > 1) {
        stack = stack.slice(0, -1);
        selected = stack[stack.length - 1];
        render();
        pulseElement(currentNodes[0] && currentNodes[0].el);
      } else {
        selected = n.data;
        renderDetails(selected);
        pulseElement(n.el);
      }
      handleFlaggedSelection(selected);
      return;
    }
    if (n.data.type === 'aggregate') {
      selected = n.data;
      renderDetails(selected);
      document.querySelectorAll('.node-group').forEach((elm) => elm.classList.remove('selected'));
      n.el.classList.add('selected');
      pulseElement(n.el);
      return;
    }
    selected = n.data;
    const isDir = n.data.type === 'dir' || n.data.type === 'dir-excluded';
    if (isDir && n.data.children && n.data.children.length) {
      stack.push(n.data);
      render();
      pulseElement(currentNodes[0] && currentNodes[0].el);
    } else {
      renderDetails(selected);
      document.querySelectorAll('.node-group').forEach((elm) => elm.classList.remove('selected'));
      n.el.classList.add('selected');
      pulseElement(n.el);
    }
    handleFlaggedSelection(selected);
  }

  // ---------- pan / zoom ----------
  function applyTransform() {
    viewport.setAttribute('transform', `translate(${pan.x},${pan.y}) scale(${zoom})`);
  }
  svg.addEventListener('wheel', (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.92 : 1.08;
    zoom = Math.max(0.4, Math.min(2.5, zoom * delta));
    applyTransform();
  }, { passive: false });

  svg.addEventListener('mousedown', (e) => {
    dragging = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
    svg.classList.add('panning');
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    pan.x = dragging.px + (e.clientX - dragging.x);
    pan.y = dragging.py + (e.clientY - dragging.y);
    applyTransform();
  });
  window.addEventListener('mouseup', () => {
    dragging = null;
    svg.classList.remove('panning');
  });

  window.addEventListener('resize', () => render());

  // ---------- details panel ----------
  function field(label, value, mono) {
    const wrap = document.createElement('div');
    wrap.className = 'field';
    const l = document.createElement('div');
    l.className = 'field-label';
    l.textContent = label;
    const v = document.createElement('div');
    v.className = 'field-value' + (mono ? ' mono' : '');
    v.textContent = value;
    wrap.appendChild(l);
    wrap.appendChild(v);
    return wrap;
  }

  function folderIconSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V7Z"/></svg>';
  }
  function fileIconSvg() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 2h9l5 5v15H6V2Z"/><path d="M15 2v5h5"/></svg>';
  }

  function countRecursive(node) {
    let files = 0, dirs = 0;
    function walk(n) {
      if (n.type === 'file') { files++; return; }
      if (n.type === 'dir-excluded') { dirs++; return; }
      dirs++;
      (n.children || []).forEach(walk);
    }
    (node.children || []).forEach(walk);
    return { files, dirs };
  }

  function topLanguages(node) {
    const stats = {};
    function walk(n) {
      if (n.type === 'file') {
        stats[n.language] = (stats[n.language] || 0) + n.size;
      } else if (n.type === 'dir') {
        (n.children || []).forEach(walk);
      }
    }
    (node.children || [node]).forEach(walk);
    if (node.type === 'file') { stats[node.language] = node.size; }
    return Object.entries(stats).sort((a, b) => b[1] - a[1]).slice(0, 3);
  }

  function renderStackSection(pane, node) {
    const isFile = node && node.type === 'file';

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = isFile ? 'File type' : 'Tech stack';
    pane.appendChild(title);

    const chips = document.createElement('div');
    chips.className = 'stack-chips';

    if (isFile) {
      const c = document.createElement('span');
      c.className = 'stack-chip lang';
      c.textContent = node.language || 'Unknown';
      chips.appendChild(c);
    } else {
      const langEntries = Object.entries(data.scanResult.codeLanguageStats || {})
        .sort((a, b) => b[1].size - a[1].size)
        .slice(0, 6);
      langEntries.forEach(([lang]) => {
        const c = document.createElement('span');
        c.className = 'stack-chip lang';
        c.textContent = lang;
        chips.appendChild(c);
      });
      (data.stack.frameworks || []).forEach((fw) => {
        const c = document.createElement('span');
        c.className = 'stack-chip';
        c.textContent = fw;
        chips.appendChild(c);
      });
      if (!langEntries.length && !(data.stack.frameworks || []).length) {
        const c = document.createElement('span');
        c.className = 'field-value';
        c.textContent = 'No stack detected.';
        chips.appendChild(c);
      }
    }
    pane.appendChild(chips);

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function renderSecurityAnalysisSection(pane, node) {
    if (!node.path || !isPathFlagged(node.path)) return;

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Security analysis';
    pane.appendChild(title);

    const prefix = node.path + '/';
    const findings = (data.secrets && data.secrets.findings || []).filter((f) => (
      f.file === node.path || f.file.startsWith(prefix)
    ));
    const isManifestFlagged = flaggedVulnManifests.has(node.path)
      || [...flaggedVulnManifests].some((p) => p.startsWith(prefix));

    const banner = document.createElement('div');
    banner.className = 'secret-banner';
    const summaryParts = [];
    if (findings.length) summaryParts.push(`${findings.length} possible secret${findings.length === 1 ? '' : 's'} found`);
    if (isManifestFlagged) summaryParts.push('flagged by the dependency vulnerability audit');
    banner.textContent = summaryParts.join(' - ') || 'Security issue detected in this item.';
    pane.appendChild(banner);

    if (findings.length) {
      const list = document.createElement('div');
      findings.slice(0, 5).forEach((f) => {
        const row = document.createElement('div');
        row.className = 'hotfile-row';
        row.innerHTML = `<span class="hotfile-path" title="${esc(f.file)}:${f.line}">${esc(f.rule)} - ${esc(f.file)}:${f.line}</span>`;
        list.appendChild(row);
      });
      pane.appendChild(list);
      if (findings.length > 5) {
        const note = document.createElement('div');
        note.className = 'history-note';
        note.textContent = `+${findings.length - 5} more.`;
        pane.appendChild(note);
      }
    }

    const linkBtn = document.createElement('button');
    linkBtn.className = 'ai-btn';
    linkBtn.style.marginTop = '10px';
    linkBtn.textContent = 'View full security report';
    linkBtn.addEventListener('click', () => {
      switchToAnalysisTab();
      const npmManifest = node.name === 'package.json' || node.name === 'package-lock.json';
      const composerManifest = node.name === 'composer.json' || node.name === 'composer.lock';
      if (npmManifest && data.security.npm && data.security.npm.available) {
        openSecurityModal('npm (Node.js)', data.security.npm);
      } else if (composerManifest && data.security.composer && data.security.composer.available) {
        openSecurityModal('Composer (PHP)', data.security.composer);
      }
    });
    pane.appendChild(linkBtn);

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function renderAggregateDetails(pane, node) {
    document.getElementById('panelName').textContent = node.name;
    document.getElementById('panelIcon').innerHTML = folderIconSvg();
    const badges = document.getElementById('panelBadges');
    badges.innerHTML = '';
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = 'Group';
    badges.appendChild(chip);

    pane.appendChild(field('Combined size', formatBytes(node.size)));
    pane.appendChild(field('Items', `${node.items.length} file${node.items.length === 1 ? '' : 's'}/folders`));

    const listTitle = document.createElement('div');
    listTitle.className = 'field-label';
    listTitle.style.marginBottom = '6px';
    listTitle.textContent = 'Contents';
    pane.appendChild(listTitle);

    const list = document.createElement('div');
    list.className = 'agg-list';
    node.items.slice(0, 60).forEach((item) => {
      const row = document.createElement('div');
      row.className = 'agg-row';
      row.innerHTML = `<span>${item.name}</span><span class="n">${formatBytes(item.size)}</span>`;
      list.appendChild(row);
    });
    pane.appendChild(list);
  }

  function renderAiSummarySection(pane, node) {
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'AI Analysis Engine';
    pane.appendChild(title);

    if (!aiKeyConfigured) {
      const notice = document.createElement('div');
      notice.className = 'ai-key-notice';
      notice.innerHTML = 'No Claude API key configured — summaries use the built-in local engine. <a href="#" id="aiKeyNoticeLink">Add a key in Settings</a> for deeper, code-aware analysis.';
      pane.appendChild(notice);
      const link = notice.querySelector('#aiKeyNoticeLink');
      link.addEventListener('click', (e) => {
        e.preventDefault();
        document.getElementById('settingsBtn').click();
      });
    }

    const wrap = document.createElement('div');
    wrap.className = 'ai-wrap';

    const btn = document.createElement('button');
    btn.className = 'ai-btn';
    btn.id = 'aiSummaryBtn';
    btn.textContent = 'Generate summary';

    const output = document.createElement('div');
    output.className = 'ai-output hidden';
    const outputText = document.createElement('div');
    const outputSource = document.createElement('div');
    outputSource.className = 'ai-source';
    output.appendChild(outputText);
    output.appendChild(outputSource);

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Generating…';
      try {
        const res = await fetch(apiUrl('/api/summary?path=' + encodeURIComponent(node.path || node.name)));
        const json = await res.json();
        outputText.textContent = json.summary || 'No summary available.';
        outputSource.textContent = json.source === 'claude' ? 'Generated by Claude' : 'Generated by the local analysis engine';
        output.classList.remove('hidden');
        btn.textContent = 'Regenerate';
      } catch {
        outputText.textContent = 'Could not generate a summary right now.';
        outputSource.textContent = '';
        output.classList.remove('hidden');
        btn.textContent = 'Generate summary';
      }
      btn.disabled = false;
    });

    wrap.appendChild(btn);
    wrap.appendChild(output);
    pane.appendChild(wrap);

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function renderDetails(node) {
    const pane = document.getElementById('tab-details');
    pane.innerHTML = '';
    if (!node || !data) return;

    renderStackSection(pane, node);

    if (node.type === 'aggregate') {
      renderAggregateDetails(pane, node);
      return;
    }

    renderSecurityAnalysisSection(pane, node);

    const isDir = node.type === 'dir' || node.type === 'dir-excluded' || node === data.scanResult.tree;
    const isRoot = node === data.scanResult.tree;

    document.getElementById('panelName').textContent = node.name;
    document.getElementById('panelIcon').innerHTML = isDir ? folderIconSvg() : fileIconSvg();
    const badges = document.getElementById('panelBadges');
    badges.innerHTML = '';
    const typeChip = document.createElement('span');
    typeChip.className = 'chip';
    typeChip.textContent = isDir ? 'Folder' : 'File';
    badges.appendChild(typeChip);
    if (isRoot) {
      const rootChip = document.createElement('span');
      rootChip.className = 'chip';
      rootChip.textContent = 'root';
      badges.appendChild(rootChip);
    }

    renderAiSummarySection(pane, node);

    pane.appendChild(field('Path', node.path || node.name, true));
    pane.appendChild(field('Size', formatBytes(node.size)));

    if (isDir) {
      const counts = countRecursive(node);
      pane.appendChild(field('Contents', `${counts.files} file${counts.files === 1 ? '' : 's'}, ${counts.dirs} folder${counts.dirs === 1 ? '' : 's'}`));
      const langs = topLanguages(node);
      if (langs.length) {
        pane.appendChild(field('Top languages', langs.map(([l, s]) => `${l} (${formatBytes(s)})`).join(', ')));
      }
      if (node.type === 'dir-excluded') {
        pane.appendChild(field('Note', 'Excluded from drill-down (build/dependency directory) - size still counted.'));
      }
    } else {
      pane.appendChild(field('Type', node.language || 'Unknown'));
      if (data.coverage && data.coverage.available) {
        const cov = data.coverage.files.find((f) => f.file === node.path);
        if (cov) {
          pane.appendChild(field('Test coverage', `${cov.pct}% (${cov.linesHit}/${cov.linesFound} lines)`));
        }
      }
      renderChangeHistorySection(pane, node);
    }
  }

  function renderFsHistoryFallback(pane, node) {
    const list = document.createElement('div');
    list.className = 'history-list';
    const entries = [];
    if (node.birthtime && node.birthtime !== node.mtime) {
      entries.push({ label: 'Created', time: node.birthtime });
    }
    entries.push({ label: 'Last modified', time: node.mtime });
    entries.forEach((e) => {
      const row = document.createElement('div');
      row.className = 'history-row';
      row.innerHTML = `<span class="history-label">${e.label}</span><span class="history-time">${formatDate(e.time)}</span>`;
      list.appendChild(row);
    });
    pane.appendChild(list);
    const note = document.createElement('div');
    note.className = 'history-note';
    note.textContent = 'From filesystem timestamps - not a git repository, so no commit history is available.';
    pane.appendChild(note);
  }

  async function renderChangeHistorySection(pane, node) {
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Change history';
    pane.appendChild(title);

    const body = document.createElement('div');
    body.className = 'history-loading';
    body.textContent = 'Loading…';
    pane.appendChild(body);

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);

    if (!data.git || !data.git.isRepo) {
      body.innerHTML = '';
      renderFsHistoryFallback(body, node);
      return;
    }

    try {
      const res = await fetch(apiUrl('/api/filehistory?path=' + encodeURIComponent(node.path)));
      const json = await res.json();
      body.innerHTML = '';
      if (!json.available || !json.history.length) {
        renderFsHistoryFallback(body, node);
        return;
      }
      const list = document.createElement('div');
      list.className = 'history-list';
      json.history.forEach((commit) => {
        const row = document.createElement('div');
        row.className = 'commit-row';
        row.innerHTML = `
          <div class="commit-msg">${esc(commit.message)}</div>
          <div class="commit-meta"><span class="commit-hash">${esc(commit.hash)}</span> ${esc(commit.author)} &middot; ${formatDate(commit.date)}</div>
        `;
        list.appendChild(row);
      });
      body.appendChild(list);
      if (json.history.length >= 20) {
        const note = document.createElement('div');
        note.className = 'history-note';
        note.textContent = 'Showing the most recent 20 commits touching this file.';
        body.appendChild(note);
      }
    } catch {
      body.innerHTML = '';
      renderFsHistoryFallback(body, node);
    }
  }

  function vibeNote(text) {
    const div = document.createElement('div');
    div.className = 'vibe-note';
    div.textContent = text;
    return div;
  }

  // ---------- analysis panel ----------
  function initials(name) {
    return name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('');
  }

  function renderContributorsSection(pane) {
    const contributors = data.git.contributors;
    if (!contributors || !contributors.length) return;
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Contributors';
    pane.appendChild(title);
    const wrap = document.createElement('div');
    contributors.forEach((c) => {
      const row = document.createElement('div');
      row.className = 'contrib-row';
      row.innerHTML = `<span class="contrib-name"><span class="contrib-avatar">${esc(initials(c.name))}</span>${esc(c.name)}</span><span class="contrib-count">${c.count} commit${c.count === 1 ? '' : 's'}</span>`;
      wrap.appendChild(row);
    });
    pane.appendChild(wrap);
  }

  function renderHotFilesSection(pane) {
    const hotFiles = data.git.hotFiles;
    if (!hotFiles || !hotFiles.length) return;
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Hot files (most frequently changed)';
    pane.appendChild(title);
    const wrap = document.createElement('div');
    hotFiles.forEach((f) => {
      const row = document.createElement('div');
      row.className = 'hotfile-row';
      row.innerHTML = `<span class="hotfile-path" title="${esc(f.file)}">${esc(f.file)}</span><span class="hotfile-count">${f.count} changes</span>`;
      wrap.appendChild(row);
    });
    pane.appendChild(wrap);
    const note = document.createElement('div');
    note.className = 'history-note';
    note.textContent = 'Based on the most recent 1000 commits - files that change often are worth extra scrutiny in review.';
    pane.appendChild(note);
    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function renderSecretsSection(pane) {
    if (!data.secrets) return;
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Secrets';
    pane.appendChild(title);

    const { findings, truncated } = data.secrets;
    if (!findings.length) {
      const ok = document.createElement('div');
      ok.className = 'status-ok';
      ok.textContent = 'No obvious hardcoded secrets found in tracked source files.';
      pane.appendChild(ok);
    } else {
      const banner = document.createElement('div');
      banner.className = 'secret-banner';
      banner.textContent = `${findings.length} possible secret${findings.length === 1 ? '' : 's'} found - review before this code is pushed anywhere public.`;
      pane.appendChild(banner);

      const table = document.createElement('table');
      table.className = 'mini';
      table.innerHTML = '<thead><tr><th>File</th><th>Line</th><th>Rule</th><th>Value</th></tr></thead>';
      const tbody = document.createElement('tbody');
      findings.slice(0, 25).forEach((f) => {
        const tr = document.createElement('tr');
        tr.className = 'row-sev-flagged';
        tr.innerHTML = `<td class="mono-cell">${esc(f.file)}</td><td>${f.line}</td><td>${esc(f.rule)}</td><td class="mono-cell">${esc(f.preview)}</td>`;
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      pane.appendChild(table);

      if (findings.length > 25 || truncated) {
        const note = document.createElement('div');
        note.className = 'history-note';
        note.textContent = truncated
          ? 'Scan stopped early after hitting the finding cap - there may be more.'
          : `Showing 25 of ${findings.length} findings.`;
        pane.appendChild(note);
      }
    }

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function formatDelta(n, unit) {
    if (n === 0) return `no change`;
    const sign = n > 0 ? '+' : '';
    return `${sign}${n}${unit || ''}`;
  }

  function renderTrendSection(pane) {
    if (!data.trend) return;
    const { deltas, previous } = data.trend;

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Since last scan';
    pane.appendChild(title);

    const list = document.createElement('ul');
    list.className = 'insight-list';
    const since = new Date(previous.timestamp).toLocaleString();
    const rows = [
      `Files: ${formatDelta(deltas.totalFiles)} (was ${previous.totalFiles})`,
      `Size: ${formatDelta(Math.round(deltas.totalSize / 1024), ' KB')}`,
      `Vulnerabilities: ${formatDelta(deltas.vulnerabilities)} (was ${previous.vulnerabilities})`,
      `Secrets found: ${formatDelta(deltas.secrets)} (was ${previous.secrets})`,
    ];
    rows.forEach((text) => {
      const li = document.createElement('li');
      li.textContent = text;
      list.appendChild(li);
    });
    pane.appendChild(list);
    const note = document.createElement('div');
    note.className = 'history-note';
    note.textContent = `Compared to the scan from ${since}.`;
    pane.appendChild(note);

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);
  }

  function renderAnalysis() {
    const pane = document.getElementById('tab-analysis');
    pane.innerHTML = '';
    if (!data) return;

    const insightsTitle = document.createElement('h3');
    insightsTitle.className = 'section-title';
    insightsTitle.textContent = 'Insights';
    pane.appendChild(insightsTitle);
    const insightList = document.createElement('ul');
    insightList.className = 'insight-list';
    (data.insights || []).forEach((text) => {
      const li = document.createElement('li');
      li.textContent = text;
      insightList.appendChild(li);
    });
    pane.appendChild(insightList);

    renderTrendSection(pane);

    const langTitle = document.createElement('h3');
    langTitle.className = 'section-title';
    langTitle.textContent = 'Languages';
    pane.appendChild(langTitle);
    const codeStats = data.scanResult.codeLanguageStats || {};
    if (Object.keys(codeStats).length) {
      const codeTotal = Object.values(codeStats).reduce((sum, s) => sum + s.size, 0);
      pane.appendChild(buildLanguageChart(codeStats, codeTotal));
    } else {
      const p = document.createElement('div');
      p.className = 'field-value';
      p.textContent = 'No recognized programming languages found (this project may be mostly data, config, or assets).';
      pane.appendChild(p);
    }

    renderSecretsSection(pane);

    const secTitle = document.createElement('h3');
    secTitle.className = 'section-title';
    secTitle.textContent = 'Dependency security';
    pane.appendChild(secTitle);

    const ecosystems = [
      { key: 'npm', label: 'npm (Node.js)', data: data.security.npm, kind: 'package' },
      { key: 'composer', label: 'Composer (PHP)', data: data.security.composer, kind: 'package' },
      { key: 'wordpress', label: 'WordPress plugins & themes', data: data.security.wordpress, kind: 'wordpress' },
    ];
    const available = ecosystems.filter((e) => e.data && e.data.available);

    if (!available.length) {
      const reasons = ecosystems.map((e) => e.data && e.data.reason).filter(Boolean);
      const p = document.createElement('div');
      p.className = 'field-value';
      p.textContent = reasons.length ? reasons.join(' ') : 'No recognized dependency manifests found.';
      pane.appendChild(p);
    } else {
      available.forEach((eco, i) => {
        if (i > 0) {
          const divider = document.createElement('hr');
          divider.className = 'divider';
          pane.appendChild(divider);
        }
        if (eco.kind === 'wordpress') {
          renderWordPressEcosystem(pane, eco.data);
        } else {
          renderPackageEcosystem(pane, eco.label, eco.data);
        }
      });
    }

    const secDivider = document.createElement('hr');
    secDivider.className = 'divider';
    pane.appendChild(secDivider);

    if (data.git && data.git.isRepo) {
      renderContributorsSection(pane);
      renderHotFilesSection(pane);
    }

    renderLicenseSection(pane);
    renderSbomSection(pane);
    renderComplexitySection(pane);
    renderDeadCodeSection(pane);
    renderDuplicateCodeSection(pane);
    renderCoverageSection(pane);
  }

  function renderCoverageSection(pane) {
    if (!data.coverage || !data.coverage.available) return;

    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Test coverage';
    pane.appendChild(title);

    const summary = document.createElement('div');
    summary.className = 'field-value';
    summary.textContent = `${data.coverage.overallPct}% overall, from ${data.coverage.source}.`;
    pane.appendChild(summary);

    const worst = data.coverage.files.slice(0, 10);
    if (worst.length) {
      const h = document.createElement('div');
      h.className = 'eco-label';
      h.style.marginTop = '12px';
      h.textContent = 'Lowest-covered files';
      pane.appendChild(h);
      worst.forEach((f) => {
        const row = document.createElement('div');
        row.className = 'hotfile-row';
        row.innerHTML = `<span class="hotfile-path" title="${esc(f.file)}">${esc(f.file)}</span><span class="hotfile-count">${f.pct}%</span>`;
        pane.appendChild(row);
      });
    }
  }

  function renderDuplicateCodeSection(pane) {
    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Duplicate code';
    pane.appendChild(title);

    const desc = document.createElement('div');
    desc.className = 'field-value';
    desc.textContent = 'Finds near-identical 6-line blocks repeated across files - copy-paste candidates worth extracting into a shared function.';
    pane.appendChild(desc);

    const btn = document.createElement('button');
    btn.className = 'ai-btn';
    btn.style.marginTop = '10px';
    btn.textContent = 'Scan for duplicates';

    const output = document.createElement('div');
    output.className = 'vibe-output hidden';

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      try {
        const res = await fetch(apiUrl('/api/duplicates'));
        const result = await res.json();
        output.innerHTML = '';
        output.classList.remove('hidden');
        const summary = document.createElement('div');
        summary.className = 'history-note';
        summary.textContent = `Scanned ${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}${result.truncated ? ' (capped)' : ''} - ${result.totalGroups} duplicate group${result.totalGroups === 1 ? '' : 's'} found.`;
        output.appendChild(summary);
        result.groups.forEach((g) => {
          const card = document.createElement('div');
          card.className = 'dup-card';
          const sampleEl = document.createElement('div');
          sampleEl.className = 'dup-sample';
          sampleEl.textContent = g.sample;
          card.appendChild(sampleEl);
          g.occurrences.forEach((o) => {
            const row = document.createElement('div');
            row.className = 'dup-occurrence';
            row.textContent = `${o.file}:${o.startLine}-${o.endLine}`;
            card.appendChild(row);
          });
          output.appendChild(card);
        });
        btn.textContent = 'Re-scan';
      } catch {
        output.innerHTML = '';
        output.appendChild(vibeNote('Could not scan for duplicates right now.'));
        output.classList.remove('hidden');
        btn.textContent = 'Scan for duplicates';
      }
      btn.disabled = false;
    });

    pane.appendChild(btn);
    pane.appendChild(output);
  }

  function renderDeadCodeSection(pane) {
    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Possibly unused exports (JS/TS)';
    pane.appendChild(title);

    const desc = document.createElement('div');
    desc.className = 'field-value';
    desc.textContent = 'Heuristic, name-based scan - exports never referenced by an import anywhere in the project. Verify before deleting; wildcard imports and re-exports can cause false positives.';
    pane.appendChild(desc);

    const btn = document.createElement('button');
    btn.className = 'ai-btn';
    btn.style.marginTop = '10px';
    btn.textContent = 'Scan for unused exports';

    const output = document.createElement('div');
    output.className = 'vibe-output hidden';

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      try {
        const res = await fetch(apiUrl('/api/deadcode'));
        const result = await res.json();
        output.innerHTML = '';
        output.classList.remove('hidden');
        const summary = document.createElement('div');
        summary.className = 'history-note';
        summary.textContent = `Scanned ${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}${result.truncated ? ' (capped)' : ''} - ${result.totalCandidates} candidate${result.totalCandidates === 1 ? '' : 's'}.`;
        output.appendChild(summary);
        if (result.candidates.length) {
          const list = document.createElement('div');
          list.style.marginTop = '8px';
          result.candidates.forEach((c) => {
            const row = document.createElement('div');
            row.className = 'hotfile-row';
            row.innerHTML = `<span class="hotfile-path" title="${esc(c.file)}:${c.line}">${esc(c.name)} - ${esc(c.file)}:${c.line}</span>`;
            list.appendChild(row);
          });
          output.appendChild(list);
        }
        btn.textContent = 'Re-scan';
      } catch {
        output.innerHTML = '';
        output.appendChild(vibeNote('Could not scan for unused exports right now.'));
        output.classList.remove('hidden');
        btn.textContent = 'Scan for unused exports';
      }
      btn.disabled = false;
    });

    pane.appendChild(btn);
    pane.appendChild(output);
  }

  function renderComplexitySection(pane) {
    const divider = document.createElement('hr');
    divider.className = 'divider';
    pane.appendChild(divider);

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Code quality outliers';
    pane.appendChild(title);

    const desc = document.createElement('div');
    desc.className = 'field-value';
    desc.textContent = 'Heuristic scan for the longest and most branching functions in JS/TS/PHP/Java/C-family/Python source.';
    pane.appendChild(desc);

    const btn = document.createElement('button');
    btn.className = 'ai-btn';
    btn.style.marginTop = '10px';
    btn.textContent = 'Scan for outliers';

    const output = document.createElement('div');
    output.className = 'vibe-output hidden';

    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Scanning…';
      try {
        const res = await fetch(apiUrl('/api/complexity'));
        const result = await res.json();
        renderComplexityResult(output, result);
        btn.textContent = 'Re-scan';
      } catch {
        output.innerHTML = '';
        output.appendChild(vibeNote('Could not scan for outliers right now.'));
        output.classList.remove('hidden');
        btn.textContent = 'Scan for outliers';
      }
      btn.disabled = false;
    });

    pane.appendChild(btn);
    pane.appendChild(output);
  }

  function renderComplexityResult(output, result) {
    output.innerHTML = '';
    output.classList.remove('hidden');

    const summary = document.createElement('div');
    summary.className = 'history-note';
    summary.textContent = `Scanned ${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'}${result.truncated ? ' (capped - very large project)' : ''}.`;
    output.appendChild(summary);

    const buildList = (label, items, unitFn) => {
      const h = document.createElement('div');
      h.className = 'eco-label';
      h.style.marginTop = '14px';
      h.textContent = label;
      output.appendChild(h);
      if (!items.length) {
        output.appendChild(vibeNote('None found.'));
        return;
      }
      const list = document.createElement('div');
      items.forEach((f) => {
        const row = document.createElement('div');
        row.className = 'hotfile-row';
        row.innerHTML = `<span class="hotfile-path" title="${esc(f.file)}:${f.startLine}">${esc(f.name)} - ${esc(f.file)}:${f.startLine}</span><span class="hotfile-count">${unitFn(f)}</span>`;
        list.appendChild(row);
      });
      output.appendChild(list);
    };

    buildList('Longest functions', result.longestFunctions, (f) => `${f.lineCount} lines`);
    buildList('Most branching (complexity)', result.mostComplexFunctions, (f) => `complexity ${f.complexity}`);
  }

  const LICENSE_TIER_LABEL = {
    permissive: 'Permissive', 'weak-copyleft': 'Weak copyleft',
    'strong-copyleft': 'Strong copyleft', unknown: 'Unknown', proprietary: 'Proprietary',
  };

  function renderLicenseSection(pane) {
    if (!data.licenses || (!data.licenses.npm && !data.licenses.composer)) return;

    const divider0 = document.createElement('hr');
    divider0.className = 'divider';
    pane.appendChild(divider0);

    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'License compliance';
    pane.appendChild(title);

    [['npm (Node.js)', data.licenses.npm], ['Composer (PHP)', data.licenses.composer]].forEach(([label, eco]) => {
      if (!eco) return;
      const h = document.createElement('div');
      h.className = 'eco-label';
      h.textContent = label;
      pane.appendChild(h);

      const grid = document.createElement('div');
      grid.className = 'sevgrid';
      ['strong-copyleft', 'weak-copyleft', 'unknown', 'permissive'].forEach((tier) => {
        const card = document.createElement('div');
        const sevClass = tier === 'strong-copyleft' ? 'critical' : tier === 'weak-copyleft' ? 'high' : tier === 'unknown' ? 'moderate' : 'low';
        card.className = 'sevcard ' + sevClass;
        card.innerHTML = `<div class="n">${eco.summary[tier] || 0}</div><div class="l">${LICENSE_TIER_LABEL[tier]}</div>`;
        grid.appendChild(card);
      });
      pane.appendChild(grid);

      const flagged = eco.packages.filter((p) => p.tier === 'strong-copyleft' || p.tier === 'weak-copyleft');
      if (flagged.length) {
        const table = document.createElement('table');
        table.className = 'mini';
        table.innerHTML = '<thead><tr><th>Package</th><th>License</th><th>Type</th></tr></thead>';
        const tbody = document.createElement('tbody');
        flagged.forEach((p) => {
          const tr = document.createElement('tr');
          tr.className = p.tier === 'strong-copyleft' ? 'row-sev-critical' : 'row-sev-high';
          tr.innerHTML = `<td>${esc(p.name)}</td><td>${esc(p.license || 'Unknown')}</td><td>${esc(LICENSE_TIER_LABEL[p.tier])}</td>`;
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        pane.appendChild(table);
      } else {
        const ok = document.createElement('div');
        ok.className = 'status-ok';
        ok.textContent = 'No copyleft-licensed dependencies detected.';
        pane.appendChild(ok);
      }
    });
  }

  function renderSbomSection(pane) {
    if (!data.licenses || (!data.licenses.npm && !data.licenses.composer)) return;
    const title = document.createElement('h3');
    title.className = 'section-title';
    title.textContent = 'Software Bill of Materials';
    pane.appendChild(title);

    const desc = document.createElement('div');
    desc.className = 'field-value';
    desc.textContent = 'Export a CycloneDX-format SBOM listing every dependency, version, and license.';
    pane.appendChild(desc);

    const btn = document.createElement('button');
    btn.className = 'ai-btn';
    btn.style.marginTop = '10px';
    btn.textContent = 'Download SBOM (CycloneDX JSON)';
    btn.addEventListener('click', () => {
      window.location.href = apiUrl('/api/sbom');
    });
    pane.appendChild(btn);
  }

  function renderPackageEcosystem(pane, label, eco) {
    const h = document.createElement('div');
    h.className = 'eco-label';
    h.textContent = label;
    pane.appendChild(h);

    if (eco.vulnerabilities) {
      const v = eco.vulnerabilities;
      const grid = document.createElement('div');
      grid.className = 'sevgrid';
      ['critical', 'high', 'moderate', 'low'].forEach((sev) => {
        const card = document.createElement('div');
        card.className = 'sevcard ' + sev;
        card.innerHTML = `<div class="n">${v[sev] || 0}</div><div class="l">${sev}</div>`;
        grid.appendChild(card);
      });
      pane.appendChild(grid);
    } else if (eco.advisories.length) {
      const p = document.createElement('div');
      p.className = 'field-value';
      p.textContent = `${eco.advisories.length} known advisor${eco.advisories.length === 1 ? 'y' : 'ies'} against installed packages.`;
      pane.appendChild(p);
    }

    const totalIssues = eco.advisories.length + eco.outdated.length;
    const btn = document.createElement('button');
    btn.className = 'ai-btn security-report-btn';
    btn.textContent = totalIssues ? `View full report (${totalIssues})` : 'View full report';
    btn.addEventListener('click', () => openSecurityModal(label, eco));
    pane.appendChild(btn);

    if (!totalIssues) {
      const ok = document.createElement('div');
      ok.className = 'status-ok';
      ok.style.marginTop = '10px';
      ok.textContent = 'No known vulnerabilities and everything is up to date.';
      pane.appendChild(ok);
    }
  }

  function renderWordPressEcosystem(pane, wp) {
    const h = document.createElement('div');
    h.className = 'eco-label';
    h.textContent = 'WordPress plugins & themes';
    pane.appendChild(h);

    const outdatedPlugins = wp.plugins.filter((p) => p.outdated).length;
    const outdatedThemes = wp.themes.filter((t) => t.outdated).length;
    const unchecked = [...wp.plugins, ...wp.themes].filter((i) => !i.checked).length;

    const summary = document.createElement('div');
    summary.className = 'field-value';
    summary.textContent = `${wp.plugins.length} plugin${wp.plugins.length === 1 ? '' : 's'}, ${wp.themes.length} theme${wp.themes.length === 1 ? '' : 's'} found in ${wp.wpContentPath}. ${outdatedPlugins + outdatedThemes} behind the latest published version${unchecked ? ` (${unchecked} could not be checked against WordPress.org - likely custom/private).` : '.'}`;
    pane.appendChild(summary);

    const btn = document.createElement('button');
    btn.className = 'ai-btn security-report-btn';
    const totalIssues = outdatedPlugins + outdatedThemes;
    btn.textContent = totalIssues ? `View full report (${totalIssues})` : 'View full report';
    btn.addEventListener('click', () => openWordPressModal(wp));
    pane.appendChild(btn);

    if (!totalIssues) {
      const ok = document.createElement('div');
      ok.className = 'status-ok';
      ok.style.marginTop = '10px';
      ok.textContent = 'All checked plugins and themes are up to date.';
      pane.appendChild(ok);
    }
  }

  const LANG_PALETTE = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#06b6d4', '#a855f7', '#84cc16', '#ec4899', '#14b8a6', '#f97316', '#94a3b8'];

  function buildLanguageChart(languageStats, totalSize) {
    const wrap = document.createElement('div');
    wrap.className = 'lang-chart';
    const total = totalSize || 1;
    const entries = Object.entries(languageStats).sort((a, b) => b[1].size - a[1].size);
    const top = entries.slice(0, 7);
    const restSize = entries.slice(7).reduce((sum, [, s]) => sum + s.size, 0);
    const segments = top.map(([lang, stats], i) => ({ lang, size: stats.size, color: LANG_PALETTE[i % LANG_PALETTE.length] }));
    if (restSize > 0) segments.push({ lang: 'Other', size: restSize, color: '#cbd5e1' });

    const bar = document.createElement('div');
    bar.className = 'lang-stackbar';
    segments.forEach((seg) => {
      const pct = (seg.size / total) * 100;
      if (pct <= 0) return;
      const piece = document.createElement('div');
      piece.className = 'lang-stackbar-seg';
      piece.style.width = pct.toFixed(2) + '%';
      piece.style.background = seg.color;
      piece.title = `${seg.lang} - ${pct.toFixed(1)}%`;
      bar.appendChild(piece);
    });
    wrap.appendChild(bar);

    const legend = document.createElement('div');
    legend.className = 'lang-legend';
    segments.forEach((seg) => {
      const pct = (seg.size / total) * 100;
      if (pct <= 0) return;
      const item = document.createElement('div');
      item.className = 'lang-legend-item';
      item.innerHTML = `<span class="dot" style="background:${seg.color}"></span>${seg.lang} <span class="lang-legend-pct">${pct.toFixed(1)}%</span>`;
      legend.appendChild(item);
    });
    wrap.appendChild(legend);

    return wrap;
  }

  // ---------- security report modal ----------
  const securityModal = document.getElementById('securityModal');
  document.getElementById('securityModalClose').addEventListener('click', () => {
    securityModal.classList.add('hidden');
  });
  securityModal.addEventListener('click', (e) => {
    if (e.target === securityModal) securityModal.classList.add('hidden');
  });

  // ---------- add repo modal ----------
  const addRepoModal = document.getElementById('addRepoModal');
  const addRepoInput = document.getElementById('addRepoInput');
  const addRepoStatus = document.getElementById('addRepoStatus');
  const addRepoSubmit = document.getElementById('addRepoSubmit');

  document.getElementById('addRepoBtn').addEventListener('click', () => {
    addRepoModal.classList.remove('hidden');
    addRepoInput.value = '';
    addRepoStatus.textContent = '';
    addRepoStatus.className = 'settings-status';
    addRepoInput.focus();
  });
  document.getElementById('addRepoClose').addEventListener('click', () => {
    addRepoModal.classList.add('hidden');
  });
  addRepoModal.addEventListener('click', (e) => {
    if (e.target === addRepoModal) addRepoModal.classList.add('hidden');
  });

  addRepoSubmit.addEventListener('click', async () => {
    const repoUrl = addRepoInput.value.trim();
    if (!repoUrl) return;
    addRepoSubmit.disabled = true;
    addRepoSubmit.textContent = 'Cloning…';
    addRepoStatus.textContent = 'Cloning and scanning - this can take a moment for larger repos.';
    addRepoStatus.className = 'settings-status';
    try {
      const res = await fetch('/api/projects/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: repoUrl }),
      });
      const json = await res.json();
      if (!res.ok) {
        addRepoStatus.textContent = json.error || 'Could not add that repository.';
        addRepoStatus.className = 'settings-status error';
      } else {
        addRepoModal.classList.add('hidden');
        loadingEl.classList.remove('hidden');
        await loadProjects({ selectId: json.id });
        await loadProjectData();
      }
    } catch {
      addRepoStatus.textContent = 'Could not reach the server to add that repository.';
      addRepoStatus.className = 'settings-status error';
    }
    addRepoSubmit.disabled = false;
    addRepoSubmit.textContent = 'Clone & analyze';
  });

  function buildSecurityReportText(label, eco) {
    const lines = [
      `CodeScope Security Report - ${label}`,
      `Generated ${new Date().toLocaleString()}`,
      '',
    ];
    if (eco.vulnerabilities) {
      const v = eco.vulnerabilities;
      lines.push(`Vulnerabilities: ${v.critical || 0} critical, ${v.high || 0} high, ${v.moderate || 0} moderate, ${v.low || 0} low`, '');
    }
    if (eco.advisories.length) {
      lines.push('Vulnerable packages:');
      eco.advisories.forEach((a) => {
        lines.push(`- ${a.name} [${a.severity}]${a.fixAvailable !== undefined ? ` fix ${a.fixAvailable ? 'available' : 'requires manual review'}` : ''}${a.via && a.via.length ? ` - via ${a.via.join(', ')}` : ''}${a.cve ? ` (${a.cve})` : ''}`);
      });
      lines.push('');
    }
    if (eco.outdated.length) {
      lines.push('Outdated packages:');
      eco.outdated.forEach((o) => {
        lines.push(`- ${o.name}: ${o.current} -> ${o.latest}`);
      });
    }
    return lines.join('\n');
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function linkOrText(text, url) {
    return url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>` : esc(text);
  }

  function openSecurityModal(label, eco) {
    document.getElementById('securityModalTitle').textContent = `Security Report - ${label}`;
    const body = document.getElementById('securityModalBody');
    body.innerHTML = '';

    const vulnerableNames = new Set(eco.advisories.map((a) => a.name));

    if (eco.advisories.length) {
      const t = document.createElement('h4');
      t.className = 'section-title';
      t.textContent = `Vulnerable packages (${eco.advisories.length})`;
      body.appendChild(t);
      const table = document.createElement('table');
      table.className = 'mini';
      table.innerHTML = '<thead><tr><th>Package</th><th>Severity</th><th>Details</th><th>Fix</th></tr></thead>';
      const tbody = document.createElement('tbody');
      eco.advisories.forEach((a) => {
        const tr = document.createElement('tr');
        tr.className = 'row-sev-' + (a.severity || 'unknown');
        const details = a.via ? (a.via || []).join(', ') : (a.title || a.cve || '');
        const fix = a.fixAvailable !== undefined ? (a.fixAvailable ? 'available' : 'manual') : (a.link ? 'see advisory' : '-');
        tr.innerHTML = `<td>${linkOrText(a.name, a.link)}</td><td>${esc(a.severity)}</td><td class="muted">${esc(details || '-')}</td><td>${esc(fix)}</td>`;
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.appendChild(table);
    } else {
      const ok = document.createElement('div');
      ok.className = 'status-ok';
      ok.textContent = 'No known vulnerabilities found.';
      body.appendChild(ok);
    }

    const t2 = document.createElement('h4');
    t2.className = 'section-title';
    t2.textContent = `Outdated packages (${eco.outdated.length})`;
    body.appendChild(t2);
    if (eco.outdated.length) {
      const table2 = document.createElement('table');
      table2.className = 'mini';
      table2.innerHTML = '<thead><tr><th>Package</th><th>Current</th><th>Latest</th></tr></thead>';
      const tbody2 = document.createElement('tbody');
      eco.outdated.forEach((o) => {
        const tr = document.createElement('tr');
        if (vulnerableNames.has(o.name)) tr.className = 'row-sev-flagged';
        tr.innerHTML = `<td>${linkOrText(o.name, o.link)}</td><td>${esc(o.current)}</td><td>${esc(o.latest)}</td>`;
        tbody2.appendChild(tr);
      });
      table2.appendChild(tbody2);
      body.appendChild(table2);
    } else {
      const ok = document.createElement('div');
      ok.className = 'status-ok';
      ok.textContent = 'All dependencies up to date.';
      body.appendChild(ok);
    }

    const copyBtn = document.getElementById('securityCopyBtn');
    copyBtn.textContent = 'Copy report as text';
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(buildSecurityReportText(label, eco));
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = 'Copy report as text'; }, 1500);
      } catch {
        copyBtn.textContent = 'Could not copy';
      }
    };

    securityModal.classList.remove('hidden');
  }

  function openWordPressModal(wp) {
    document.getElementById('securityModalTitle').textContent = 'Security Report - WordPress';
    const body = document.getElementById('securityModalBody');
    body.innerHTML = '';

    const renderItemTable = (label, items) => {
      const t = document.createElement('h4');
      t.className = 'section-title';
      t.textContent = `${label} (${items.length})`;
      body.appendChild(t);
      if (!items.length) return;
      const table = document.createElement('table');
      table.className = 'mini';
      table.innerHTML = '<thead><tr><th>Name</th><th>Installed</th><th>Latest</th><th>Status</th></tr></thead>';
      const tbody = document.createElement('tbody');
      items.forEach((item) => {
        const status = !item.checked ? 'not on WordPress.org' : (item.outdated ? 'outdated' : 'up to date');
        const tr = document.createElement('tr');
        if (item.outdated) tr.className = 'row-sev-flagged';
        tr.innerHTML = `<td>${linkOrText(item.name, item.link)}</td><td>${esc(item.version)}</td><td>${esc(item.latest || '-')}</td><td>${esc(status)}</td>`;
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      body.appendChild(table);
    };

    renderItemTable('Plugins', wp.plugins);
    renderItemTable('Themes', wp.themes);

    const copyBtn = document.getElementById('securityCopyBtn');
    copyBtn.textContent = 'Copy report as text';
    copyBtn.onclick = async () => {
      const lines = [
        'CodeScope Security Report - WordPress',
        `Generated ${new Date().toLocaleString()}`,
        '',
        'Plugins:',
        ...wp.plugins.map((p) => `- ${p.name}: ${p.version}${p.checked ? ` -> latest ${p.latest}${p.outdated ? ' (outdated)' : ''}` : ' (not on WordPress.org)'}`),
        '',
        'Themes:',
        ...wp.themes.map((t) => `- ${t.name}: ${t.version}${t.checked ? ` -> latest ${t.latest}${t.outdated ? ' (outdated)' : ''}` : ' (not on WordPress.org)'}`),
      ];
      try {
        await navigator.clipboard.writeText(lines.join('\n'));
        copyBtn.textContent = 'Copied';
        setTimeout(() => { copyBtn.textContent = 'Copy report as text'; }, 1500);
      } catch {
        copyBtn.textContent = 'Could not copy';
      }
    };

    securityModal.classList.remove('hidden');
  }

  // After a flagged node is selected, auto-run the AI Analysis Engine for
  // files so the "why does this file have a security issue" story is
  // available immediately instead of requiring an extra click. The findings
  // themselves show inline in the Details panel's Security analysis section
  // (see renderSecurityAnalysisSection).
  function handleFlaggedSelection(nodeData) {
    if (!nodeData || !nodeData.path || !isPathFlagged(nodeData.path)) return;
    if (nodeData.type === 'file') {
      const summaryBtn = document.getElementById('aiSummaryBtn');
      if (summaryBtn) summaryBtn.click();
    }
  }

  load();
})();
