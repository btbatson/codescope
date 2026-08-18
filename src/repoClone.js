const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { stateRoot } = require('./stateDir');
const { parseGithubUrl, downloadRepoSnapshot } = require('./githubFetch');

const REPOS_DIR = path.join(stateRoot(), 'repos');
const CLONE_TIMEOUT_MS = 180000; // 3 minutes - generous for a shallow clone of a large repo

const URL_RE = /^(https?:\/\/[\w.-]+\/[\w.\-/]+?|git@[\w.-]+:[\w.\-/]+?)(\.git)?\/?$/;

function isValidRepoUrl(url) {
  return typeof url === 'string' && URL_RE.test(url.trim());
}

function run(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { cwd, timeout: CLONE_TIMEOUT_MS, maxBuffer: 1024 * 1024 * 20 }, (err, stdout, stderr) => {
      if (err) {
        const message = (stderr || err.message || '').toString().trim().split('\n').slice(-4).join('\n');
        reject(new Error(message || `${cmd} failed`));
        return;
      }
      resolve(stdout.toString());
    });
  });
}

function deriveName(url) {
  const trimmed = url.trim().replace(/\.git$/, '').replace(/\/$/, '');
  const parts = trimmed.split(/[/:]/);
  return parts[parts.length - 1] || 'repo';
}

function normalizeUrl(url) {
  return url.trim().replace(/\.git$/, '').replace(/\/$/, '');
}

function getRemoteUrl(dir) {
  try {
    const { execFileSync } = require('child_process');
    return execFileSync('git', ['-C', dir, 'remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

// Tracks which URL/mode each cache dir came from in a small registry file
// alongside REPOS_DIR (not inside the repo dirs themselves, so it never
// shows up as a stray file in the scanned tree). Needed because "live"
// (no-git) snapshots have no .git/ to introspect a remote from - without
// this, every repeat add of the same URL in live mode would look like a
// collision with itself and mint a new hash-suffixed dir forever.
const REGISTRY_PATH = path.join(REPOS_DIR, '.origins.json');

function loadRegistry() {
  try {
    return JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function recordOrigin(dir, url, mode) {
  try {
    fs.mkdirSync(REPOS_DIR, { recursive: true });
    const reg = loadRegistry();
    reg[path.basename(dir)] = { url: normalizeUrl(url), mode };
    fs.writeFileSync(REGISTRY_PATH, JSON.stringify(reg));
  } catch {
    // best effort - worst case a future add of the same URL gets a fresh dir
  }
}

function lookupOrigin(dir) {
  return loadRegistry()[path.basename(dir)] || null;
}

// Prefer a clean, human-readable directory name ("Hello-World"). Only fall
// back to a hash suffix if that name is already taken by a *different*
// repository - re-adding the same URL always resolves back to the same dir.
function cacheDirFor(url) {
  const repoName = deriveName(url);
  const plainDir = path.join(REPOS_DIR, repoName);
  if (!fs.existsSync(plainDir)) return plainDir;

  const known = lookupOrigin(plainDir);
  const existingOrigin = known ? known.url : getRemoteUrl(plainDir);
  if (existingOrigin && normalizeUrl(existingOrigin) === normalizeUrl(url)) return plainDir;

  const hash = crypto.createHash('sha1').update(url.trim()).digest('hex').slice(0, 8);
  return path.join(REPOS_DIR, `${repoName}-${hash}`);
}

// Clones a repo on first use; on subsequent calls for the same URL, tries to
// fast-forward the existing shallow clone instead of re-cloning. Never
// throws on the update step - a stale clone is still usable if the network
// is down or the fetch fails for some other reason.
//
// When a `git` binary isn't available at all (e.g. a Vercel serverless
// function, which has no git and no persistent disk) - or when a clone
// attempt fails for a github.com URL for any reason - this falls back to
// downloading the repo's files straight from GitHub's API/CDN instead, so
// "add a repo" still works for a hosted, no-local-clone demo. That fallback
// only supports github.com; other hosts need a real git binary.
async function cloneOrUpdateRepo(url) {
  if (!isValidRepoUrl(url)) {
    const err = new Error("That doesn't look like a valid git repository URL (expected an https:// or git@ URL).");
    err.code = 'INVALID_URL';
    throw err;
  }

  const dir = cacheDirFor(url);
  const name = deriveName(url);
  const known = fs.existsSync(dir) ? lookupOrigin(dir) : null;

  if (fs.existsSync(path.join(dir, '.git'))) {
    try {
      await run('git', ['fetch', '--depth', '1', 'origin'], dir);
      await run('git', ['reset', '--hard', 'origin/HEAD'], dir);
    } catch {
      // fall through - use whatever's already on disk
    }
    return { path: dir, name, mode: 'git' };
  }

  // Already have a live (no-git) snapshot of this exact URL - refresh it the
  // same way rather than attempting a doomed `git clone` into a non-empty
  // directory (git refuses that outright).
  if (known && known.mode === 'live') {
    try {
      const result = await downloadRepoSnapshot(url, dir);
      recordOrigin(dir, url, 'live');
      return { path: result.path, name: result.name || name, mode: 'live' };
    } catch {
      return { path: dir, name, mode: 'live' }; // stale snapshot is still usable
    }
  }

  fs.mkdirSync(REPOS_DIR, { recursive: true });
  try {
    await run('git', ['clone', '--depth', '1', url.trim(), dir]);
    recordOrigin(dir, url, 'git');
    return { path: dir, name, mode: 'git' };
  } catch (err) {
    fs.rmSync(dir, { recursive: true, force: true });

    if (parseGithubUrl(url)) {
      try {
        const result = await downloadRepoSnapshot(url, dir);
        recordOrigin(dir, url, 'live');
        return { path: result.path, name: result.name || name, mode: 'live' };
      } catch (fallbackErr) {
        if (fallbackErr.code === 'REPO_TOO_LARGE') {
          const tooLargeErr = new Error(`${fallbackErr.message} Try "Run on your device" instead - it has no such limit.`);
          tooLargeErr.code = 'REPO_TOO_LARGE';
          throw tooLargeErr;
        }
        const cloneErr = new Error(`Could not clone or fetch that repository: ${fallbackErr.message}`);
        cloneErr.code = 'CLONE_FAILED';
        throw cloneErr;
      }
    }

    const cloneErr = new Error(`Could not clone that repository: ${err.message}`);
    cloneErr.code = 'CLONE_FAILED';
    throw cloneErr;
  }
}

module.exports = { cloneOrUpdateRepo, isValidRepoUrl };
