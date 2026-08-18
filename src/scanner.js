const fs = require('fs');
const path = require('path');
const { loadIgnoreMatcher } = require('./gitignore');

const EXCLUDED_DIRS = new Set(['.git', 'node_modules', '.next', 'dist', 'build', '.venv', '__pycache__', '.cache']);

// `kind` mirrors GitHub Linguist's type field. Only 'programming' and
// 'markup' count toward the GitHub-style Languages bar - 'data' (JSON,
// YAML), 'prose' (Markdown, plain text), and anything unlisted (binaries,
// images, archives) are tracked for file-type stats elsewhere but excluded
// from that specific chart, same as linguist excludes them from a repo's
// language percentages.
const LANGUAGE_META = {
  '.js': { name: 'JavaScript', kind: 'programming' },
  '.jsx': { name: 'JavaScript (JSX)', kind: 'programming', group: 'JavaScript' },
  '.mjs': { name: 'JavaScript', kind: 'programming' },
  '.cjs': { name: 'JavaScript', kind: 'programming' },
  '.ts': { name: 'TypeScript', kind: 'programming' },
  '.tsx': { name: 'TypeScript (TSX)', kind: 'programming', group: 'TypeScript' },
  '.py': { name: 'Python', kind: 'programming' },
  '.rb': { name: 'Ruby', kind: 'programming' },
  '.go': { name: 'Go', kind: 'programming' },
  '.rs': { name: 'Rust', kind: 'programming' },
  '.java': { name: 'Java', kind: 'programming' },
  '.kt': { name: 'Kotlin', kind: 'programming' },
  '.swift': { name: 'Swift', kind: 'programming' },
  '.c': { name: 'C', kind: 'programming' },
  '.h': { name: 'C Header', kind: 'programming' },
  '.cpp': { name: 'C++', kind: 'programming' },
  '.cc': { name: 'C++', kind: 'programming' },
  '.hpp': { name: 'C++ Header', kind: 'programming' },
  '.cs': { name: 'C#', kind: 'programming' },
  '.php': { name: 'PHP', kind: 'programming' },
  '.sql': { name: 'SQL', kind: 'programming' },
  '.sh': { name: 'Shell', kind: 'programming' },
  '.bash': { name: 'Shell', kind: 'programming' },
  '.graphql': { name: 'GraphQL', kind: 'programming' },
  '.prisma': { name: 'Prisma', kind: 'programming' },
  '.html': { name: 'HTML', kind: 'markup' },
  '.htm': { name: 'HTML', kind: 'markup' },
  '.css': { name: 'CSS', kind: 'markup' },
  '.scss': { name: 'SCSS', kind: 'markup' },
  '.less': { name: 'LESS', kind: 'markup' },
  '.vue': { name: 'Vue', kind: 'markup' },
  '.json': { name: 'JSON', kind: 'data' },
  '.jsonc': { name: 'JSON', kind: 'data' },
  '.yaml': { name: 'YAML', kind: 'data' },
  '.yml': { name: 'YAML', kind: 'data' },
  '.toml': { name: 'TOML', kind: 'data' },
  '.xml': { name: 'XML', kind: 'data' },
  '.csv': { name: 'CSV', kind: 'data' },
  '.md': { name: 'Markdown', kind: 'prose' },
  '.mdx': { name: 'Markdown', kind: 'prose' },
  '.txt': { name: 'Text', kind: 'prose' },
  '.rst': { name: 'reStructuredText', kind: 'prose' },
};

// Extensionless config/lock/generated files and noisy suffixes GitHub
// Linguist would classify as "generated" or "vendored" and exclude from
// language stats - build caches, source maps, compiled artifacts, etc.
const GENERATED_PATTERNS = [
  /\.min\.(js|css)$/i,
  /\.map$/i,
  /\.lock$/i,
  /\.tsbuildinfo$/i,
  /\.d\.ts$/i,
  /\.g\.dart$/i,
  /\.pb\.go$/i,
];
const VENDORED_PATH_SEGMENTS = new Set([
  'vendor', 'vendors', 'third_party', 'thirdparty', 'external', 'externals',
  'migrations', 'generated', '__generated__', 'pods', 'carthage', 'packages',
]);

function classify(ext) {
  const meta = LANGUAGE_META[ext.toLowerCase()];
  return meta ? meta.name : (ext ? ext.toUpperCase().slice(1) + ' file' : 'No extension');
}

function languageKind(ext) {
  const meta = LANGUAGE_META[ext.toLowerCase()];
  return meta ? meta.kind : 'other';
}

// The bucket name to roll percentages up into (e.g. .tsx -> "TypeScript"),
// matching Linguist's `group:` behavior - falls back to the display name.
function languageGroup(ext) {
  const meta = LANGUAGE_META[ext.toLowerCase()];
  if (!meta) return null;
  return meta.group || meta.name;
}

function isGeneratedOrVendored(relPath, name) {
  if (GENERATED_PATTERNS.some((re) => re.test(name))) return true;
  const segments = relPath.split(path.sep).slice(0, -1).map((s) => s.toLowerCase());
  return segments.some((seg) => VENDORED_PATH_SEGMENTS.has(seg));
}

// gitignore patterns are relative to the repo root, but our internal relPath
// always carries the scanned root folder's own name as its first segment -
// strip that off before asking the ignore matcher.
function toGitRelPath(relPath) {
  const parts = relPath.split(path.sep);
  return parts.slice(1).join('/');
}

// Fast pre-pass: count how many nodes we'll visit so progress can be reported
// as a percentage. Excluded dirs count as a single node since we don't descend.
function countAll(dirPath, relBase, ig) {
  const name = path.basename(dirPath);
  const relPath = relBase ? path.join(relBase, name) : name;
  let stat;
  try {
    stat = fs.lstatSync(dirPath);
  } catch {
    return 0;
  }
  if (stat.isSymbolicLink()) return 0;
  if (!stat.isDirectory()) return 1;
  if (EXCLUDED_DIRS.has(name)) return 1;
  if (ig && relBase) {
    const gitRel = toGitRelPath(relPath);
    if (gitRel && ig.ignores(gitRel)) return 1;
  }

  let entries = [];
  try {
    entries = fs.readdirSync(dirPath);
  } catch {
    return 1;
  }
  let total = 1;
  for (const entry of entries) {
    total += countAll(path.join(dirPath, entry), relPath, ig);
  }
  return total;
}

function walk(dirPath, relBase, progress, ig) {
  const name = path.basename(dirPath);
  const relPath = relBase ? path.join(relBase, name) : name;
  let stat;
  try {
    stat = fs.lstatSync(dirPath);
  } catch {
    return null;
  }
  if (stat.isSymbolicLink()) return null;

  const gitRel = relBase ? toGitRelPath(relPath) : '';
  const isIgnored = !!(ig && relBase && gitRel && ig.ignores(gitRel + (stat.isDirectory() ? '/' : '')));

  if (stat.isDirectory()) {
    if (EXCLUDED_DIRS.has(name) || isIgnored) {
      let size = 0;
      try {
        size = dirSizeShallow(dirPath);
      } catch {}
      progress.tick();
      return { name, path: relPath, type: 'dir-excluded', size, children: [] };
    }
    let entries = [];
    try {
      entries = fs.readdirSync(dirPath);
    } catch {
      progress.tick();
      return { name, path: relPath, type: 'dir', size: 0, children: [] };
    }
    const children = entries
      .sort()
      .map((entry) => walk(path.join(dirPath, entry), relPath, progress, ig))
      .filter(Boolean);
    const size = children.reduce((sum, c) => sum + c.size, 0);
    progress.tick();
    return { name, path: relPath, type: 'dir', size, children };
  }

  progress.tick();
  if (isIgnored) return null;

  const ext = path.extname(name);
  return {
    name,
    path: relPath,
    type: 'file',
    ext,
    language: classify(ext),
    size: stat.size,
    mtime: stat.mtimeMs,
    birthtime: stat.birthtimeMs,
    ctime: stat.ctimeMs,
  };
}

function dirSizeShallow(dirPath) {
  let total = 0;
  const stack = [dirPath];
  let guard = 0;
  while (stack.length && guard < 20000) {
    guard++;
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        stack.push(full);
      } else {
        try {
          total += fs.statSync(full).size;
        } catch {}
      }
    }
  }
  return total;
}

function flattenFiles(node, out = []) {
  if (!node) return out;
  if (node.type === 'file') {
    out.push(node);
  } else if (node.type === 'dir') {
    for (const child of node.children) flattenFiles(child, out);
  }
  return out;
}

function collectExcludedDirs(node, out = []) {
  if (!node) return out;
  if (node.type === 'dir-excluded') {
    out.push({ name: node.name, path: node.path, size: node.size });
  } else if (node.type === 'dir') {
    for (const child of node.children) collectExcludedDirs(child, out);
  }
  return out;
}

function scan(targetDir, onProgress) {
  const absTarget = path.resolve(targetDir);
  const ig = loadIgnoreMatcher(absTarget);
  const total = countAll(absTarget, '', ig) || 1;
  let done = 0;
  const progress = {
    tick() {
      done += 1;
      if (onProgress) onProgress(done, total);
    },
  };
  const tree = walk(absTarget, '', progress, ig);
  const files = flattenFiles(tree);

  const languageStats = {};
  const codeLanguageStats = {};
  for (const f of files) {
    const lang = f.language;
    if (!languageStats[lang]) languageStats[lang] = { count: 0, size: 0 };
    languageStats[lang].count += 1;
    languageStats[lang].size += f.size;

    const kind = languageKind(f.ext);
    if ((kind === 'programming' || kind === 'markup') && !isGeneratedOrVendored(f.path, f.name)) {
      const group = languageGroup(f.ext) || lang;
      if (!codeLanguageStats[group]) codeLanguageStats[group] = { count: 0, size: 0 };
      codeLanguageStats[group].count += 1;
      codeLanguageStats[group].size += f.size;
    }
  }

  const largestFiles = [...files].sort((a, b) => b.size - a.size).slice(0, 20);

  const excludedDirs = collectExcludedDirs(tree);

  return {
    root: absTarget,
    tree,
    totalFiles: files.length,
    totalSize: tree ? tree.size : 0,
    languageStats,
    codeLanguageStats,
    largestFiles,
    excludedDirs,
    scannedAt: new Date().toISOString(),
  };
}

module.exports = { scan, classify, EXCLUDED_DIRS };
