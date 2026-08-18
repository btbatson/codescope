function makeProgressLogger(label = 'Scanning') {
  let lastPct = -1;
  return function onProgress(done, total) {
    const pct = total ? Math.min(100, Math.floor((done / total) * 100)) : 100;
    if (pct === lastPct) return;
    lastPct = pct;
    process.stdout.write(`\r${label}... ${pct}% (${done}/${total})`);
    if (pct >= 100) process.stdout.write('\n');
  };
}

module.exports = { makeProgressLogger };
