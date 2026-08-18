const fs = require('fs');
const path = require('path');

const CANDIDATE_PATHS = [
  'coverage/lcov.info',
  '.nyc_output/lcov.info',
  'coverage/lcov-report/lcov.info',
];

function findLcovFile(rootDir) {
  for (const rel of CANDIDATE_PATHS) {
    const full = path.join(rootDir, rel);
    if (fs.existsSync(full)) return full;
  }
  return null;
}

function toProjectRelative(rootDir, sfPath) {
  const rootName = path.basename(rootDir);
  if (sfPath.startsWith(rootDir)) {
    const rel = path.relative(rootDir, sfPath);
    return path.join(rootName, rel).split(path.sep).join('/');
  }
  return sfPath.split(path.sep).join('/');
}

function parseLcov(content, rootDir) {
  const files = [];
  let current = null;

  for (const line of content.split('\n')) {
    if (line.startsWith('SF:')) {
      current = { file: toProjectRelative(rootDir, line.slice(3).trim()), linesFound: 0, linesHit: 0, functionsFound: 0, functionsHit: 0 };
    } else if (line.startsWith('LF:') && current) {
      current.linesFound = parseInt(line.slice(3), 10) || 0;
    } else if (line.startsWith('LH:') && current) {
      current.linesHit = parseInt(line.slice(3), 10) || 0;
    } else if (line.startsWith('FNF:') && current) {
      current.functionsFound = parseInt(line.slice(4), 10) || 0;
    } else if (line.startsWith('FNH:') && current) {
      current.functionsHit = parseInt(line.slice(4), 10) || 0;
    } else if (line.startsWith('end_of_record') && current) {
      current.pct = current.linesFound ? Math.round((current.linesHit / current.linesFound) * 1000) / 10 : 0;
      files.push(current);
      current = null;
    }
  }
  return files;
}

function getCoverage(rootDir) {
  const lcovPath = findLcovFile(rootDir);
  if (!lcovPath) return { available: false };

  let content;
  try {
    content = fs.readFileSync(lcovPath, 'utf8');
  } catch {
    return { available: false };
  }

  const files = parseLcov(content, rootDir);
  const totalFound = files.reduce((sum, f) => sum + f.linesFound, 0);
  const totalHit = files.reduce((sum, f) => sum + f.linesHit, 0);

  return {
    available: true,
    source: path.relative(rootDir, lcovPath),
    overallPct: totalFound ? Math.round((totalHit / totalFound) * 1000) / 10 : 0,
    files: files.sort((a, b) => a.pct - b.pct),
  };
}

module.exports = { getCoverage };
