const fs = require('fs');
const path = require('path');
const https = require('https');

// Downloads a GitHub repo's current contents directly through GitHub's API
// and raw-content CDN, with no `git` binary and no persistent disk required
// beyond the destination directory itself. This is the path used when a
// git executable isn't available - e.g. a Vercel serverless function -  so
// "add a repo" still works for a hosted, no-local-clone demo.

const MAX_FILES = 4000;
const MAX_FILE_BYTES = 1.5 * 1024 * 1024; // skip individually huge files
const MAX_TOTAL_BYTES = 120 * 1024 * 1024; // cap total download for one repo
const CONCURRENCY = 16;
const REQUEST_TIMEOUT_MS = 15000;

const EXCLUDED_PREFIX_RE = /(^|\/)(\.git|node_modules|\.next|dist|build|\.venv|__pycache__|\.cache)(\/|$)/;
const GITHUB_URL_RE = /github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i;

function parseGithubUrl(url) {
  const m = String(url || '').trim().match(GITHUB_URL_RE);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function isGithubUrl(url) {
  return !!parseGithubUrl(url);
}

function ghHeaders(extra = {}) {
  const headers = { 'User-Agent': 'codescope-app', ...extra };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  return headers;
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: ghHeaders({ Accept: 'application/vnd.github+json' }), timeout: REQUEST_TIMEOUT_MS }, (res) => {
      if (res.statusCode >= 400) {
        res.resume();
        reject(Object.assign(new Error(`GitHub API returned ${res.statusCode} for ${url}`), { statusCode: res.statusCode }));
        return;
      }
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (err) { reject(err); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Request to GitHub timed out')));
  });
}

function getBuffer(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: ghHeaders(), timeout: REQUEST_TIMEOUT_MS }, (res) => {
      if (res.statusCode >= 400) {
        res.resume();
        reject(Object.assign(new Error(`GitHub returned ${res.statusCode} for ${url}`), { statusCode: res.statusCode }));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Request to GitHub timed out')));
  });
}

async function resolveDefaultBranch(owner, repo) {
  const info = await getJson(`https://api.github.com/repos/${owner}/${repo}`);
  if (!info || !info.default_branch) throw new Error('Could not read repository info from GitHub - check the URL and that the repo is public.');
  return info.default_branch;
}

async function fetchTreeEntries(owner, repo, branch) {
  const data = await getJson(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (!data || !Array.isArray(data.tree)) throw new Error('Could not read the repository file tree from GitHub.');
  return data.tree.filter((e) => e.type === 'blob' && !EXCLUDED_PREFIX_RE.test(e.path));
}

async function mapWithConcurrency(items, limit, fn) {
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 1 }, worker));
}

async function downloadRepoSnapshot(url, destDir) {
  const parsed = parseGithubUrl(url);
  if (!parsed) {
    const err = new Error('Live (no-clone) analysis currently only supports github.com repository URLs.');
    err.code = 'UNSUPPORTED_HOST';
    throw err;
  }
  const { owner, repo } = parsed;
  const branch = await resolveDefaultBranch(owner, repo);
  const entries = await fetchTreeEntries(owner, repo, branch);

  if (entries.length > MAX_FILES) {
    const err = new Error(`This repository has ${entries.length} files, over the ${MAX_FILES}-file limit for live no-clone analysis.`);
    err.code = 'REPO_TOO_LARGE';
    throw err;
  }

  fs.rmSync(destDir, { recursive: true, force: true });
  fs.mkdirSync(destDir, { recursive: true });

  let totalBytes = 0;
  await mapWithConcurrency(entries, CONCURRENCY, async (entry) => {
    if (typeof entry.size === 'number' && entry.size > MAX_FILE_BYTES) return;
    if (totalBytes > MAX_TOTAL_BYTES) return;
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${entry.path.split('/').map(encodeURIComponent).join('/')}`;
    let buf;
    try {
      buf = await getBuffer(rawUrl);
    } catch {
      return; // best-effort - skip files that fail to download rather than aborting the whole scan
    }
    totalBytes += buf.length;
    const dest = path.join(destDir, entry.path);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, buf);
  });

  return { path: destDir, name: repo, branch };
}

module.exports = { parseGithubUrl, isGithubUrl, downloadRepoSnapshot };
