const fs = require('fs');
const path = require('path');

const IGNORE_DIRS = new Set(['.git', 'node_modules', '.cache']);
const FETCH_TIMEOUT_MS = 4000;
const MAX_ITEMS_CHECKED = 40;

// Look for a wp-content directory up to a few levels deep - WordPress sites
// often aren't scanned from the WP root itself (e.g. a Bedrock-style layout,
// or scanning a parent folder that contains the WP install as a subfolder).
function findWpContentDir(rootDir, depth = 3) {
  let entries;
  try {
    entries = fs.readdirSync(rootDir, { withFileTypes: true });
  } catch {
    return null;
  }
  const direct = entries.find((e) => e.isDirectory() && e.name === 'wp-content');
  if (direct) return path.join(rootDir, 'wp-content');
  if (depth <= 0) return null;
  for (const entry of entries) {
    if (!entry.isDirectory() || IGNORE_DIRS.has(entry.name)) continue;
    const found = findWpContentDir(path.join(rootDir, entry.name), depth - 1);
    if (found) return found;
  }
  return null;
}

function readFileHead(filePath, maxBytes = 8192) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(maxBytes);
    const bytesRead = fs.readSync(fd, buf, 0, maxBytes, 0);
    fs.closeSync(fd);
    return buf.toString('utf8', 0, bytesRead);
  } catch {
    return '';
  }
}

function parseHeader(text) {
  const nameMatch = text.match(/(?:Plugin|Theme) Name:\s*(.+)/i);
  const versionMatch = text.match(/Version:\s*([\w.\-+]+)/i);
  return {
    name: nameMatch ? nameMatch[1].trim() : null,
    version: versionMatch ? versionMatch[1].trim() : null,
  };
}

function scanPlugins(wpContentDir) {
  const pluginsDir = path.join(wpContentDir, 'plugins');
  let entries;
  try {
    entries = fs.readdirSync(pluginsDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const plugins = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const slug = entry.name;
    let headerText = '';
    let mainFile = null;

    if (entry.isDirectory()) {
      const dirPath = path.join(pluginsDir, slug);
      let files = [];
      try { files = fs.readdirSync(dirPath); } catch { files = []; }
      const candidate = files.find((f) => f === `${slug}.php`) || files.find((f) => f.endsWith('.php'));
      if (candidate) {
        mainFile = path.join(dirPath, candidate);
        headerText = readFileHead(mainFile);
        if (!/Plugin Name:/i.test(headerText)) {
          for (const f of files) {
            if (!f.endsWith('.php') || path.join(dirPath, f) === mainFile) continue;
            const text = readFileHead(path.join(dirPath, f));
            if (/Plugin Name:/i.test(text)) { headerText = text; break; }
          }
        }
      }
    } else if (entry.name.endsWith('.php')) {
      mainFile = path.join(pluginsDir, entry.name);
      headerText = readFileHead(mainFile);
    } else {
      continue;
    }

    const { name, version } = parseHeader(headerText);
    if (name || version) {
      plugins.push({ slug: slug.replace(/\.php$/, ''), name: name || slug, version: version || 'unknown' });
    }
  }
  return plugins;
}

function scanThemes(wpContentDir) {
  const themesDir = path.join(wpContentDir, 'themes');
  let entries;
  try {
    entries = fs.readdirSync(themesDir, { withFileTypes: true });
  } catch {
    return [];
  }
  const themes = [];
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    const styleCss = path.join(themesDir, entry.name, 'style.css');
    if (!fs.existsSync(styleCss)) continue;
    const { name, version } = parseHeader(readFileHead(styleCss));
    if (name || version) {
      themes.push({ slug: entry.name, name: name || entry.name, version: version || 'unknown' });
    }
  }
  return themes;
}

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function checkPluginLatest(slug) {
  const json = await fetchWithTimeout(`https://api.wordpress.org/plugins/info/1.0/${encodeURIComponent(slug)}.json`);
  if (!json || !json.version) return null;
  return json.version;
}

async function checkThemeLatest(slug) {
  const json = await fetchWithTimeout(`https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=${encodeURIComponent(slug)}`);
  if (!json || !json.version) return null;
  return json.version;
}

async function withLatestVersions(items, checkFn) {
  const capped = items.slice(0, MAX_ITEMS_CHECKED);
  const results = await Promise.all(capped.map(async (item) => {
    const latest = await checkFn(item.slug);
    return {
      ...item,
      latest: latest || null,
      checked: latest !== null,
      outdated: latest ? latest !== item.version : null,
    };
  }));
  // Anything beyond the cap still gets listed, just without a freshness check.
  const rest = items.slice(MAX_ITEMS_CHECKED).map((item) => ({ ...item, latest: null, checked: false, outdated: null }));
  return [...results, ...rest];
}

async function checkWordPress(rootDir) {
  const wpContentDir = findWpContentDir(rootDir);
  if (!wpContentDir) return { available: false, reason: 'no wp-content directory found' };

  const pluginsRaw = scanPlugins(wpContentDir);
  const themesRaw = scanThemes(wpContentDir);

  const [pluginsChecked, themesChecked] = await Promise.all([
    withLatestVersions(pluginsRaw, checkPluginLatest),
    withLatestVersions(themesRaw, checkThemeLatest),
  ]);

  const plugins = pluginsChecked.map((p) => ({
    ...p,
    link: p.checked ? `https://wordpress.org/plugins/${p.slug}/#developers` : null,
  }));
  const themes = themesChecked.map((t) => ({
    ...t,
    link: t.checked ? `https://wordpress.org/themes/${t.slug}/` : null,
  }));

  return {
    available: true,
    wpContentPath: path.relative(rootDir, wpContentDir) || 'wp-content',
    plugins: plugins.sort((a, b) => a.name.localeCompare(b.name)),
    themes: themes.sort((a, b) => a.name.localeCompare(b.name)),
  };
}

module.exports = { checkWordPress };
