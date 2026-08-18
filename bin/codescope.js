#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { scan } = require('../src/scanner');
const { runSecurityCheck } = require('../src/security');
const { buildInsights } = require('../src/insights');
const { buildHtmlReport } = require('../src/report');
const { startServer } = require('../src/appServer');
const { makeProgressLogger } = require('../src/progress');
const { checkWordPress } = require('../src/wordpress');
const { scanForSecrets } = require('../src/secretScan');

function parseArgs(argv) {
  const args = {
    targets: [], out: null, port: 4488, open: true, json: false,
    ci: false, failOn: 'high', ignoreSecrets: false,
  };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out' || a === '-o') args.out = argv[++i];
    else if (a === '--port' || a === '-p') args.port = parseInt(argv[++i], 10);
    else if (a === '--no-open') args.open = false;
    else if (a === '--json') args.json = true;
    else if (a === 'ci' || a === '--ci') args.ci = true;
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--ignore-secrets') args.ignoreSecrets = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else rest.push(a);
  }
  args.targets = rest.length ? rest : ['.'];
  return args;
}

const SEVERITY_RANK = { critical: 4, high: 3, moderate: 2, low: 1, none: 0 };

async function runCiMode(target, args) {
  const scanResult = scan(target);
  const security = runSecurityCheck(target);
  security.wordpress = await checkWordPress(target);
  const secrets = scanForSecrets(target, scanResult.tree);

  console.log(`CodeScope CI Summary`);
  console.log(`Project: ${target}`);
  console.log(`Files: ${scanResult.totalFiles}`);

  let worstSeverity = 'none';
  let totalVulns = 0;
  const bump = (sev) => { if (SEVERITY_RANK[sev] > SEVERITY_RANK[worstSeverity]) worstSeverity = sev; };

  if (security.npm && security.npm.available) {
    const v = security.npm.vulnerabilities;
    totalVulns += (v.critical || 0) + (v.high || 0) + (v.moderate || 0) + (v.low || 0);
    console.log(`npm: ${v.critical || 0} critical, ${v.high || 0} high, ${v.moderate || 0} moderate, ${v.low || 0} low`);
    ['critical', 'high', 'moderate', 'low'].forEach((sev) => { if (v[sev]) bump(sev); });
  }
  if (security.composer && security.composer.available) {
    totalVulns += security.composer.advisories.length;
    console.log(`composer: ${security.composer.advisories.length} advisories`);
    security.composer.advisories.forEach((a) => bump((a.severity || '').toLowerCase()));
  }
  if (security.wordpress && security.wordpress.available) {
    const outdated = security.wordpress.plugins.filter((p) => p.outdated).length + security.wordpress.themes.filter((t) => t.outdated).length;
    console.log(`WordPress: ${outdated} outdated plugin(s)/theme(s)`);
  }

  console.log(`Secrets found: ${secrets.findings.length}`);

  const threshold = SEVERITY_RANK[args.failOn] ?? SEVERITY_RANK.high;
  const severityFail = SEVERITY_RANK[worstSeverity] >= threshold && SEVERITY_RANK[worstSeverity] > 0;
  const secretsFail = !args.ignoreSecrets && secrets.findings.length > 0;

  if (severityFail || secretsFail) {
    const reasons = [];
    if (severityFail) reasons.push(`${worstSeverity}-severity vulnerabilities present (threshold: ${args.failOn})`);
    if (secretsFail) reasons.push(`${secrets.findings.length} possible secret(s) found`);
    console.log(`Result: FAIL - ${reasons.join('; ')}`);
    process.exit(1);
  }
  console.log('Result: PASS');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    console.log(`CodeScope -- scan a codebase, map its contents, and audit dependencies.

Usage:
  codescope [path]                 Launch the interactive dashboard in your browser
  codescope [path1] [path2] ...    Launch the dashboard with a project switcher for multiple projects
  codescope [path] --out file.html Write a static, shareable HTML report instead
  codescope ci [path]              Headless CI check - prints a summary, exits non-zero on findings

Options:
  -p, --port <n>      Dashboard server port (default: 4488)
  --no-open           Don't auto-open the browser
  -o, --out <file>    Write a static HTML report to this path (skips the server)
  --json              With --out, also write the raw scan+security data as JSON
  --fail-on <level>   CI mode only: critical|high|moderate|low (default: high)
  --ignore-secrets    CI mode only: don't fail the build on found secrets
  -h, --help          Show this help
`);
    return;
  }

  const targets = args.targets.map((t) => path.resolve(t));
  for (const target of targets) {
    if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
      console.error(`Error: "${target}" is not a directory.`);
      process.exit(1);
    }
  }

  if (args.ci) {
    await runCiMode(targets[0], args);
    return;
  }

  if (args.out) {
    const target = targets[0];
    const scanResult = scan(target, makeProgressLogger('Scanning'));
    console.log('Checking dependencies for security & freshness ...');
    const security = runSecurityCheck(target);
    security.wordpress = await checkWordPress(target);
    const insights = buildInsights(scanResult, security);
    const html = buildHtmlReport({ scanResult, security, insights });

    const outPath = path.resolve(args.out);
    fs.writeFileSync(outPath, html, 'utf8');
    console.log(`Report written to ${outPath}`);

    if (args.json) {
      const jsonPath = outPath.replace(/\.html?$/, '') + '.json';
      fs.writeFileSync(jsonPath, JSON.stringify({ scanResult, security, insights }, null, 2), 'utf8');
      console.log(`Raw data written to ${jsonPath}`);
    }
    return;
  }

  startServer(targets, { port: args.port, open: args.open }).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
