const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function isGitRepo(rootDir) {
  return fs.existsSync(path.join(rootDir, '.git'));
}

function safeGit(args, cwd) {
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 50,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    return null;
  }
}

const LOG_SEP = '\x1f'; // unit separator - safe delimiter unlikely to appear in commit data

// Real commit history for one file, newest first.
function getFileHistory(rootDir, relPath, limit = 20) {
  if (!isGitRepo(rootDir)) return null;
  const format = `%H${LOG_SEP}%an${LOG_SEP}%ad${LOG_SEP}%s`;
  const out = safeGit(
    ['log', `--max-count=${limit}`, '--follow', `--date=iso-strict`, `--format=${format}`, '--', relPath],
    rootDir
  );
  if (out === null) return null;
  const lines = out.split('\n').filter(Boolean);
  return lines.map((line) => {
    const [hash, author, date, ...msgParts] = line.split(LOG_SEP);
    return { hash: hash.slice(0, 7), author, date, message: msgParts.join(LOG_SEP) };
  });
}

// Repo-wide contributor breakdown: commit counts per author.
function getContributors(rootDir, limit = 15) {
  if (!isGitRepo(rootDir)) return null;
  const out = safeGit(['shortlog', '-sne', '--all'], rootDir);
  if (out === null) return null;
  const lines = out.split('\n').filter(Boolean);
  const contributors = lines.map((line) => {
    const m = line.match(/^\s*(\d+)\s+(.+?)\s+<(.+?)>$/);
    if (!m) return null;
    return { count: parseInt(m[1], 10), name: m[2], email: m[3] };
  }).filter(Boolean);
  return contributors.slice(0, limit);
}

// Which files change most often - a practical "risk/complexity" proxy.
// Scoped to a reasonable commit window so it stays fast on large histories.
function getHotFiles(rootDir, limit = 15, commitWindow = 1000) {
  if (!isGitRepo(rootDir)) return null;
  const out = safeGit(
    ['log', `--max-count=${commitWindow}`, '--name-only', '--pretty=format:'],
    rootDir
  );
  if (out === null) return null;
  const counts = {};
  for (const line of out.split('\n')) {
    const f = line.trim();
    if (!f) continue;
    counts[f] = (counts[f] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([file, count]) => ({ file, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

module.exports = { isGitRepo, getFileHistory, getContributors, getHotFiles };
