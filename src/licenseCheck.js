const fs = require('fs');
const path = require('path');

const PERMISSIVE = new Set([
  'mit', 'isc', 'bsd-2-clause', 'bsd-3-clause', 'bsd-3-clause-clear', 'bsd-4-clause',
  '0bsd', 'apache-2.0', 'apache 2.0', 'unlicense', 'cc0-1.0', 'wtfpl', 'zlib', 'python-2.0',
]);
const WEAK_COPYLEFT = new Set([
  'lgpl-2.0', 'lgpl-2.1', 'lgpl-3.0', 'lgpl-2.0-only', 'lgpl-2.1-only', 'lgpl-3.0-only',
  'lgpl-2.0-or-later', 'lgpl-2.1-or-later', 'lgpl-3.0-or-later',
  'mpl-1.0', 'mpl-1.1', 'mpl-2.0', 'epl-1.0', 'epl-2.0', 'cddl-1.0', 'cddl-1.1',
]);
const STRONG_COPYLEFT = new Set([
  'gpl-1.0', 'gpl-2.0', 'gpl-3.0', 'gpl-2.0-only', 'gpl-3.0-only', 'gpl-2.0-or-later', 'gpl-3.0-or-later',
  'agpl-1.0', 'agpl-3.0', 'agpl-3.0-only', 'agpl-3.0-or-later', 'sspl-1.0',
]);

function classifyLicense(raw) {
  if (!raw) return 'unknown';
  if (raw === 'UNLICENSED') return 'proprietary';
  const norm = String(raw).toLowerCase().trim().replace(/\s*or\s*/g, ' or ').replace(/\(|\)/g, '');
  // dual/OR licenses (e.g. "MIT OR Apache-2.0") - take the least restrictive
  const parts = norm.split(/\s+or\s+|\s*\/\s*/).map((p) => p.trim());
  const tiers = parts.map((p) => {
    if (PERMISSIVE.has(p)) return 0;
    if (WEAK_COPYLEFT.has(p)) return 1;
    if (STRONG_COPYLEFT.has(p)) return 2;
    return 3;
  });
  const best = Math.min(...tiers);
  return ['permissive', 'weak-copyleft', 'strong-copyleft', 'unknown'][best];
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function extractNpmLicense(pkgJson) {
  if (!pkgJson) return null;
  if (typeof pkgJson.license === 'string') return pkgJson.license;
  if (pkgJson.license && pkgJson.license.type) return pkgJson.license.type;
  if (Array.isArray(pkgJson.licenses) && pkgJson.licenses.length) {
    return pkgJson.licenses.map((l) => l.type || l).join(' OR ');
  }
  return null;
}

function checkNpmLicenses(rootDir) {
  const pkgPath = path.join(rootDir, 'package.json');
  if (!fs.existsSync(pkgPath)) return null;
  const pkg = readJson(pkgPath);
  if (!pkg) return null;
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const results = [];
  for (const name of Object.keys(deps)) {
    const depPkgPath = path.join(rootDir, 'node_modules', name, 'package.json');
    if (!fs.existsSync(depPkgPath)) {
      results.push({ name, version: deps[name], license: null, tier: 'unknown', installed: false });
      continue;
    }
    const depPkg = readJson(depPkgPath);
    const license = extractNpmLicense(depPkg);
    results.push({
      name,
      version: (depPkg && depPkg.version) || deps[name],
      license,
      tier: classifyLicense(license),
      installed: true,
    });
  }
  return results;
}

function checkComposerLicenses(rootDir) {
  const composerPath = path.join(rootDir, 'composer.json');
  if (!fs.existsSync(composerPath)) return null;
  const composer = readJson(composerPath);
  if (!composer) return null;
  const deps = { ...(composer.require || {}), ...(composer['require-dev'] || {}) };
  const results = [];
  for (const name of Object.keys(deps)) {
    if (name === 'php' || name.startsWith('ext-')) continue;
    const vendorPkgPath = path.join(rootDir, 'vendor', name, 'composer.json');
    if (!fs.existsSync(vendorPkgPath)) {
      results.push({ name, version: deps[name], license: null, tier: 'unknown', installed: false });
      continue;
    }
    const vendorPkg = readJson(vendorPkgPath);
    let license = null;
    if (vendorPkg) {
      if (typeof vendorPkg.license === 'string') license = vendorPkg.license;
      else if (Array.isArray(vendorPkg.license)) license = vendorPkg.license.join(' OR ');
    }
    results.push({
      name,
      version: (vendorPkg && vendorPkg.version) || deps[name],
      license,
      tier: classifyLicense(license),
      installed: true,
    });
  }
  return results;
}

function summarize(list) {
  const summary = { permissive: 0, 'weak-copyleft': 0, 'strong-copyleft': 0, unknown: 0, proprietary: 0 };
  for (const item of list) {
    summary[item.tier] = (summary[item.tier] || 0) + 1;
  }
  return summary;
}

function checkLicenses(rootDir) {
  const npm = checkNpmLicenses(rootDir);
  const composer = checkComposerLicenses(rootDir);
  return {
    npm: npm ? { packages: npm, summary: summarize(npm) } : null,
    composer: composer ? { packages: composer, summary: summarize(composer) } : null,
  };
}

module.exports = { checkLicenses, classifyLicense };
