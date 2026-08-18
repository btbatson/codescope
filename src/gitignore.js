const fs = require('fs');
const path = require('path');
const ignoreLib = require('ignore');

const IGNORE_DIRS_WHILE_COLLECTING = new Set(['.git', 'node_modules']);

// Reads every .gitignore in the tree (not just the root) and merges them
// into one matcher, rewriting each nested file's patterns so they stay
// scoped to the directory they came from - exactly how git itself layers
// nested .gitignore files.
function collectGitignoreFiles(rootDir, relBase, out) {
  const dirPath = relBase ? path.join(rootDir, relBase) : rootDir;
  let entries;
  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  const gitignorePath = path.join(dirPath, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    try {
      const content = fs.readFileSync(gitignorePath, 'utf8');
      out.push({ dir: relBase, content });
    } catch {
      // unreadable - skip
    }
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
    if (IGNORE_DIRS_WHILE_COLLECTING.has(entry.name)) continue;
    collectGitignoreFiles(rootDir, relBase ? path.join(relBase, entry.name) : entry.name, out);
  }
}

function scopePattern(dirRel, rawPattern) {
  let negate = false;
  let pattern = rawPattern;
  if (pattern.startsWith('!')) {
    negate = true;
    pattern = pattern.slice(1);
  }

  const dirPrefix = dirRel ? dirRel.split(path.sep).join('/') + '/' : '';
  let scoped;
  if (!dirPrefix) {
    scoped = pattern;
  } else if (pattern.startsWith('/')) {
    scoped = dirPrefix + pattern.slice(1);
  } else if (pattern.includes('/') && !pattern.endsWith('/')) {
    scoped = dirPrefix + pattern;
  } else {
    // bare filename/glob - matches at any depth under this directory
    scoped = dirPrefix + '**/' + pattern;
  }

  return negate ? '!' + scoped : scoped;
}

function isGitRepo(dir) {
  return fs.existsSync(path.join(dir, '.git'));
}

// Returns null if the target isn't a git repo (no gitignore filtering applied),
// otherwise an object with `.ignores(relPosixPath)`.
function loadIgnoreMatcher(rootDir) {
  if (!isGitRepo(rootDir)) return null;

  const files = [];
  collectGitignoreFiles(rootDir, '', files);
  if (!files.length) return null;

  const ig = ignoreLib();
  for (const { dir, content } of files) {
    const lines = content.split(/\r\n|\r|\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      try {
        ig.add(scopePattern(dir, line));
      } catch {
        // malformed pattern - ignore it rather than fail the whole scan
      }
    }
  }
  return ig;
}

module.exports = { loadIgnoreMatcher, isGitRepo };
