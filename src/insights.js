function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function buildInsights(scanResult, security) {
  const notes = [];
  const { totalFiles, totalSize, languageStats, codeLanguageStats, largestFiles, excludedDirs } = scanResult;

  const codeEntries = Object.entries(codeLanguageStats || {}).sort((a, b) => b[1].size - a[1].size);
  if (codeEntries.length) {
    const codeTotal = codeEntries.reduce((sum, [, s]) => sum + s.size, 0);
    const [topLang, topStats] = codeEntries[0];
    const pct = ((topStats.size / codeTotal) * 100).toFixed(0);
    notes.push(`${topLang} dominates the codebase, accounting for ${pct}% of recognized source across ${topStats.count} file${topStats.count === 1 ? '' : 's'}.`);
  } else {
    const langEntries = Object.entries(languageStats).sort((a, b) => b[1].size - a[1].size);
    if (langEntries.length) {
      const [topType, topStats] = langEntries[0];
      const pct = ((topStats.size / totalSize) * 100).toFixed(0);
      notes.push(`No recognized programming languages found - the largest file type is ${topType}, at ${pct}% of total size.`);
    }
  }

  if (largestFiles.length) {
    const biggest = largestFiles[0];
    if (biggest.size > 500 * 1024) {
      notes.push(`${biggest.path} is unusually large (${formatBytes(biggest.size)}) for a source file - worth checking whether it's generated, vendored, or a candidate for splitting.`);
    }
  }

  const lockfileLike = largestFiles.filter((f) => /lock\.(json|yaml)|\.lock$/.test(f.name));
  if (lockfileLike.length) {
    notes.push(`Lockfiles (${lockfileLike.map((f) => f.name).join(', ')}) are among the largest tracked files - normal, but they inflate diff noise if reviewed manually.`);
  }

  const nodeModulesDirs = excludedDirs.filter((d) => d.name === 'node_modules');
  if (nodeModulesDirs.length) {
    const total = nodeModulesDirs.reduce((sum, d) => sum + d.size, 0);
    notes.push(`node_modules ${nodeModulesDirs.length > 1 ? `(${nodeModulesDirs.length} instances) ` : ''}weighs in at ${formatBytes(total)} - excluded from the file map above but counted in the total footprint.`);
  }

  if (security.npm && security.npm.available) {
    notes.push(...ecosystemNotes('npm', security.npm));
  } else if (security.npm && security.npm.reason) {
    notes.push(`npm dependency audit skipped: ${security.npm.reason}.`);
  }

  if (security.composer && security.composer.available) {
    notes.push(...ecosystemNotes('Composer', security.composer));
  } else if (security.composer && security.composer.reason && !/no composer\.json/.test(security.composer.reason)) {
    notes.push(`Composer dependency audit skipped: ${security.composer.reason}.`);
  }

  if (security.wordpress && security.wordpress.available) {
    const { plugins, themes } = security.wordpress;
    const outdatedPlugins = plugins.filter((p) => p.outdated);
    const outdatedThemes = themes.filter((t) => t.outdated);
    if (plugins.length || themes.length) {
      notes.push(`Found ${plugins.length} WordPress plugin${plugins.length === 1 ? '' : 's'} and ${themes.length} theme${themes.length === 1 ? '' : 's'} installed.`);
    }
    if (outdatedPlugins.length) {
      notes.push(`${outdatedPlugins.length} plugin${outdatedPlugins.length === 1 ? '' : 's'} ${outdatedPlugins.length === 1 ? 'is' : 'are'} behind the latest WordPress.org release: ${outdatedPlugins.slice(0, 5).map((p) => p.name).join(', ')}${outdatedPlugins.length > 5 ? ', and others' : ''}.`);
    }
    if (outdatedThemes.length) {
      notes.push(`${outdatedThemes.length} theme${outdatedThemes.length === 1 ? '' : 's'} behind the latest release: ${outdatedThemes.map((t) => t.name).join(', ')}.`);
    }
    if (plugins.length && !outdatedPlugins.length && !outdatedThemes.length) {
      notes.push('All checked WordPress plugins and themes match their latest published version.');
    }
  }

  if (security.manifests.length > 1) {
    notes.push(`Multiple package ecosystems detected (${security.manifests.join('; ')}) - this project spans more than one language/toolchain.`);
  }

  return notes;
}

function ecosystemNotes(label, eco) {
  const notes = [];
  const v = eco.vulnerabilities;
  const totalVulns = v
    ? (v.critical || 0) + (v.high || 0) + (v.moderate || 0) + (v.low || 0)
    : eco.advisories.length;

  if (totalVulns === 0) {
    notes.push(`${label} audit found no known vulnerabilities in the current dependency tree.`);
  } else if (v) {
    const parts = [];
    if (v.critical) parts.push(`${v.critical} critical`);
    if (v.high) parts.push(`${v.high} high`);
    if (v.moderate) parts.push(`${v.moderate} moderate`);
    if (v.low) parts.push(`${v.low} low`);
    notes.push(`${label} audit flagged ${totalVulns} vulnerabilit${totalVulns === 1 ? 'y' : 'ies'} (${parts.join(', ')}). Prioritize critical/high severities first.`);
  } else {
    notes.push(`${label} audit flagged ${totalVulns} known advisor${totalVulns === 1 ? 'y' : 'ies'} against installed packages.`);
  }

  if (eco.outdated.length) {
    const majorBumps = eco.outdated.filter((o) => majorDiff(o.current, o.latest));
    notes.push(`${eco.outdated.length} ${label} package${eco.outdated.length === 1 ? '' : 's'} have newer versions available${majorBumps.length ? `, including ${majorBumps.length} with a major version bump (higher risk of breaking changes)` : ''}.`);
  } else {
    notes.push(`All ${label} dependencies are on their latest resolvable versions.`);
  }

  return notes;
}

function majorDiff(current, latest) {
  if (!current || !latest) return false;
  const c = String(current).split('.')[0].replace(/\D/g, '');
  const l = String(latest).split('.')[0].replace(/\D/g, '');
  return c && l && c !== l;
}

module.exports = { buildInsights, formatBytes };
