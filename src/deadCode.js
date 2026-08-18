const fs = require('fs');
const path = require('path');

const JS_TS_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx']);
const MAX_FILES = 600;
const MAX_FILE_SIZE = 400 * 1024;

// Framework-convention exports that are invoked by the framework itself,
// never manually imported by name - flagging these as "dead" would just be
// noise (Next.js route handlers, data-fetching hooks, middleware, etc).
const IGNORE_NAMES = new Set([
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD',
  'getServerSideProps', 'getStaticProps', 'getStaticPaths', 'getInitialProps',
  'middleware', 'config', 'metadata', 'generateMetadata', 'generateStaticParams',
  'revalidate', 'dynamic', 'runtime',
]);

const EXPORT_PATTERNS = [
  { re: /export\s+(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)/g, group: 1 },
  { re: /export\s+class\s+([A-Za-z_$][\w$]*)/g, group: 1 },
  { re: /export\s+const\s+([A-Za-z_$][\w$]*)/g, group: 1 },
  { re: /export\s+let\s+([A-Za-z_$][\w$]*)/g, group: 1 },
  { re: /export\s+\{([^}]+)\}(?!\s*from)/g, group: 1, list: true },
];

const IMPORT_LIST_RE = /import\s+(?:type\s+)?\{([^}]+)\}\s+from/g;
const REQUIRE_DESTRUCTURE_RE = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(/g;
const PROPERTY_ACCESS_RE = /\.([A-Za-z_$][\w$]*)\s*(?:\(|;|\n|,|\))/g;

function extractListNames(raw) {
  return raw.split(',').map((part) => {
    const p = part.trim();
    if (!p) return null;
    const asMatch = p.match(/^(?:type\s+)?[\w$]+\s+as\s+([\w$]+)$/);
    if (asMatch) return asMatch[1];
    return p.replace(/^type\s+/, '').trim();
  }).filter(Boolean);
}

function collectFiles(node, out, state) {
  if (!node || state.count >= MAX_FILES) return;
  if (node.type === 'file') {
    const ext = (node.ext || '').toLowerCase();
    if (!JS_TS_EXT.has(ext) || ext === '.d.ts' || node.name.endsWith('.d.ts')) return;
    out.push(node);
    state.count++;
  } else if (node.type === 'dir') {
    for (const child of node.children) {
      if (state.count >= MAX_FILES) break;
      collectFiles(child, out, state);
    }
  }
}

function findDeadExports(targetDir, tree) {
  const files = [];
  collectFiles(tree, files, { count: 0 });

  const exportsByFile = {}; // relPath -> [{name, line}]
  const usedNames = new Set();

  for (const file of files) {
    const absPath = path.resolve(targetDir, '..', file.path);
    let text;
    try {
      const stat = fs.statSync(absPath);
      if (stat.size > MAX_FILE_SIZE) continue;
      text = fs.readFileSync(absPath, 'utf8');
    } catch {
      continue;
    }

    const exported = [];
    for (const pattern of EXPORT_PATTERNS) {
      pattern.re.lastIndex = 0;
      let m;
      while ((m = pattern.re.exec(text))) {
        const names = pattern.list ? extractListNames(m[pattern.group]) : [m[pattern.group]];
        for (const name of names) {
          if (!name || IGNORE_NAMES.has(name) || name === 'default') continue;
          const line = text.slice(0, m.index).split('\n').length;
          exported.push({ name, line });
        }
      }
    }
    if (exported.length) exportsByFile[file.path] = exported;

    let m;
    IMPORT_LIST_RE.lastIndex = 0;
    while ((m = IMPORT_LIST_RE.exec(text))) {
      extractListNames(m[1]).forEach((n) => usedNames.add(n));
    }
    REQUIRE_DESTRUCTURE_RE.lastIndex = 0;
    while ((m = REQUIRE_DESTRUCTURE_RE.exec(text))) {
      extractListNames(m[1]).forEach((n) => usedNames.add(n));
    }
    // Namespace access like `Utils.formatDate(...)` - catches re-exported
    // barrels and `import * as` usage that named-import matching would miss.
    PROPERTY_ACCESS_RE.lastIndex = 0;
    while ((m = PROPERTY_ACCESS_RE.exec(text))) {
      usedNames.add(m[1]);
    }
  }

  const candidates = [];
  for (const [file, exported] of Object.entries(exportsByFile)) {
    for (const { name, line } of exported) {
      if (!usedNames.has(name)) {
        candidates.push({ file, name, line });
      }
    }
  }

  return {
    filesScanned: files.length,
    truncated: files.length >= MAX_FILES,
    candidates: candidates.sort((a, b) => a.file.localeCompare(b.file)).slice(0, 100),
    totalCandidates: candidates.length,
  };
}

module.exports = { findDeadExports };
