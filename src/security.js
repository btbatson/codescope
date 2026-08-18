const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const MANIFESTS = [
  { file: 'package.json', ecosystem: 'npm (Node.js)' },
  { file: 'requirements.txt', ecosystem: 'pip (Python)' },
  { file: 'Pipfile', ecosystem: 'pipenv (Python)' },
  { file: 'pyproject.toml', ecosystem: 'Python (pyproject)' },
  { file: 'Gemfile', ecosystem: 'Bundler (Ruby)' },
  { file: 'go.mod', ecosystem: 'Go modules' },
  { file: 'Cargo.toml', ecosystem: 'Cargo (Rust)' },
  { file: 'composer.json', ecosystem: 'Composer (PHP)' },
];

function detectManifests(rootDir) {
  return MANIFESTS
    .filter((m) => fs.existsSync(path.join(rootDir, m.file)))
    .map((m) => m.file + ' - ' + m.ecosystem);
}

function safeExec(cmd, args, cwd) {
  try {
    const out = execFileSync(cmd, args, {
      cwd,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024 * 50,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { ok: true, out };
  } catch (err) {
    // npm audit / outdated exit non-zero when issues are found; stdout still has JSON
    const out = (err && err.stdout) ? err.stdout.toString() : '';
    if (out) return { ok: true, out };
    return { ok: false, error: err.message };
  }
}

function auditNpm(rootDir) {
  const hasPkg = fs.existsSync(path.join(rootDir, 'package.json'));
  if (!hasPkg) return { available: false, reason: 'no package.json found' };
  const hasLock = fs.existsSync(path.join(rootDir, 'package-lock.json'));
  if (!hasLock) {
    return { available: false, reason: 'no package-lock.json (run npm install first for a full audit)' };
  }

  const auditRes = safeExec('npm', ['audit', '--json'], rootDir);
  const outdatedRes = safeExec('npm', ['outdated', '--json'], rootDir);

  let audit = null;
  let vulnerabilities = { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 };
  let advisories = [];

  if (auditRes.ok) {
    try {
      audit = JSON.parse(auditRes.out);
      if (audit.metadata && audit.metadata.vulnerabilities) {
        vulnerabilities = { ...vulnerabilities, ...audit.metadata.vulnerabilities };
      }
      if (audit.vulnerabilities) {
        advisories = Object.entries(audit.vulnerabilities).map(([name, info]) => {
          const viaObjects = Array.isArray(info.via) ? info.via.filter((v) => typeof v === 'object' && v.title) : [];
          return {
            name,
            severity: info.severity,
            via: Array.isArray(info.via)
              ? info.via.filter((v) => typeof v === 'string' || v.title).map((v) => (typeof v === 'string' ? v : v.title)).slice(0, 3)
              : [],
            fixAvailable: !!info.fixAvailable,
            range: info.range,
            link: viaObjects.length ? viaObjects[0].url : `https://www.npmjs.com/package/${name}`,
          };
        });
      }
    } catch {
      audit = null;
    }
  }

  let outdated = [];
  if (outdatedRes.ok && outdatedRes.out.trim()) {
    try {
      const parsed = JSON.parse(outdatedRes.out);
      outdated = Object.entries(parsed).map(([name, info]) => ({
        name,
        current: info.current || '-',
        wanted: info.wanted || '-',
        latest: info.latest || '-',
        type: info.type || '',
        link: `https://www.npmjs.com/package/${name}?activeTab=versions`,
      }));
    } catch {
      outdated = [];
    }
  }

  return {
    available: true,
    vulnerabilities,
    advisories: advisories.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    outdated: outdated.sort((a, b) => a.name.localeCompare(b.name)),
  };
}

function severityRank(sev) {
  return { critical: 5, high: 4, moderate: 3, low: 2, info: 1 }[sev] || 0;
}

function commandExists(cmd) {
  try {
    if (process.platform === 'win32') {
      execFileSync('where', [cmd], { stdio: 'ignore' });
    } else {
      execFileSync('sh', ['-c', `command -v ${cmd}`], { stdio: 'ignore' });
    }
    return true;
  } catch {
    return false;
  }
}

function auditComposer(rootDir) {
  const hasComposerJson = fs.existsSync(path.join(rootDir, 'composer.json'));
  if (!hasComposerJson) return { available: false, reason: 'no composer.json found' };
  const hasLock = fs.existsSync(path.join(rootDir, 'composer.lock'));
  if (!hasLock) {
    return { available: false, reason: 'no composer.lock (run composer install first for a full audit)' };
  }
  if (!commandExists('composer')) {
    return { available: false, reason: 'composer is not installed / not on PATH' };
  }

  const auditRes = safeExec('composer', ['audit', '--format=json', '--no-interaction'], rootDir);
  const outdatedRes = safeExec('composer', ['outdated', '--direct', '--format=json', '--no-interaction'], rootDir);

  let advisories = [];
  if (auditRes.ok) {
    try {
      const parsed = JSON.parse(auditRes.out);
      const byPackage = parsed.advisories || {};
      advisories = Object.entries(byPackage).flatMap(([pkgName, list]) =>
        (Array.isArray(list) ? list : []).map((a) => ({
          name: pkgName,
          title: a.title || a.cve || 'Known advisory',
          cve: a.cve || null,
          link: a.link || `https://packagist.org/packages/${pkgName}`,
          severity: a.severity || 'unknown',
        })));
    } catch {
      advisories = [];
    }
  }

  let outdated = [];
  if (outdatedRes.ok && outdatedRes.out.trim()) {
    try {
      const parsed = JSON.parse(outdatedRes.out);
      const installed = parsed.installed || [];
      outdated = installed
        .filter((p) => p.version !== p.latest)
        .map((p) => ({
          name: p.name,
          current: p.version || '-',
          latest: p.latest || '-',
          wanted: p.version || '-',
          link: `https://packagist.org/packages/${p.name}#versions`,
        }));
    } catch {
      outdated = [];
    }
  }

  return {
    available: true,
    advisories: advisories.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    outdated: outdated.sort((a, b) => a.name.localeCompare(b.name)),
  };
}

function runSecurityCheck(rootDir) {
  return {
    manifests: detectManifests(rootDir),
    npm: auditNpm(rootDir),
    composer: auditComposer(rootDir),
  };
}

module.exports = { runSecurityCheck };
