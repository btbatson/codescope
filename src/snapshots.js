const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const SNAPSHOTS_ROOT = path.join(os.homedir(), '.codescope', 'snapshots');
const MAX_SNAPSHOTS = 30;

function projectDir(targetDir) {
  const hash = crypto.createHash('sha1').update(path.resolve(targetDir)).digest('hex').slice(0, 12);
  return path.join(SNAPSHOTS_ROOT, hash);
}

function listSnapshots(targetDir) {
  const dir = projectDir(targetDir);
  let files;
  try {
    files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  } catch {
    return [];
  }
  return files.map((f) => path.join(dir, f));
}

function extractMetrics(data) {
  const npmVulns = data.security.npm && data.security.npm.available
    ? ['critical', 'high', 'moderate', 'low'].reduce((sum, k) => sum + (data.security.npm.vulnerabilities[k] || 0), 0)
    : 0;
  const composerVulns = data.security.composer && data.security.composer.available
    ? data.security.composer.advisories.length : 0;
  const wpOutdated = data.security.wordpress && data.security.wordpress.available
    ? data.security.wordpress.plugins.filter((p) => p.outdated).length + data.security.wordpress.themes.filter((t) => t.outdated).length
    : 0;

  return {
    timestamp: data.generatedAt,
    totalFiles: data.scanResult.totalFiles,
    totalSize: data.scanResult.totalSize,
    vulnerabilities: npmVulns + composerVulns + wpOutdated,
    secrets: data.secrets ? data.secrets.findings.length : 0,
  };
}

// Returns the most recent existing snapshot's metrics (before this scan is
// saved), then persists the current scan as a new snapshot for next time.
function recordSnapshot(targetDir, data) {
  const existing = listSnapshots(targetDir);
  let previous = null;
  if (existing.length) {
    try {
      previous = JSON.parse(fs.readFileSync(existing[existing.length - 1], 'utf8'));
    } catch {
      previous = null;
    }
  }

  const metrics = extractMetrics(data);
  try {
    const dir = projectDir(targetDir);
    fs.mkdirSync(dir, { recursive: true });
    const filename = `${Date.now()}.json`;
    fs.writeFileSync(path.join(dir, filename), JSON.stringify(metrics, null, 2));

    const all = listSnapshots(targetDir);
    if (all.length > MAX_SNAPSHOTS) {
      all.slice(0, all.length - MAX_SNAPSHOTS).forEach((f) => {
        try { fs.unlinkSync(f); } catch { /* ignore */ }
      });
    }
  } catch {
    // best effort - don't fail the scan if snapshot storage is unavailable
  }

  if (!previous) return null;
  return {
    previous,
    current: metrics,
    deltas: {
      totalFiles: metrics.totalFiles - previous.totalFiles,
      totalSize: metrics.totalSize - previous.totalSize,
      vulnerabilities: metrics.vulnerabilities - previous.vulnerabilities,
      secrets: metrics.secrets - previous.secrets,
    },
  };
}

module.exports = { recordSnapshot };
