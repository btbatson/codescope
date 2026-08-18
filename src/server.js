const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { scan } = require('./scanner');
const { runSecurityCheck } = require('./security');
const { buildInsights } = require('./insights');
const { detectStack } = require('./stack');
const { generateSummary, findNode } = require('./aiSummary');
const { makeProgressLogger } = require('./progress');
const {
  applyStoredApiKey, getStatus, setApiKey, clearApiKey,
  setWebhookUrl, clearWebhookUrl,
} = require('./config');
const { notifyIfWorsened } = require('./webhook');
const { checkWordPress } = require('./wordpress');
const gitInfo = require('./git');
const { scanForSecrets } = require('./secretScan');
const { checkLicenses } = require('./licenseCheck');
const { buildSbom } = require('./sbom');
const { analyzeComplexity } = require('./complexity');
const { findDeadExports } = require('./deadCode');
const { findDuplicateBlocks } = require('./duplicateCode');
const { getCoverage } = require('./coverage');
const { recordSnapshot } = require('./snapshots');

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) req.destroy(); // guard against absurdly large bodies
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function toGitRelPath(nodePath) {
  const parts = nodePath.split(path.sep);
  return parts.slice(1).join('/');
}

async function buildData(targetDir, { silent = false } = {}) {
  const scanResult = scan(targetDir, silent ? undefined : makeProgressLogger('Scanning'));
  const security = runSecurityCheck(targetDir);
  security.wordpress = await checkWordPress(targetDir);
  const insights = buildInsights(scanResult, security);
  const stack = detectStack(targetDir);

  const isRepo = gitInfo.isGitRepo(targetDir);
  const git = {
    isRepo,
    contributors: isRepo ? gitInfo.getContributors(targetDir) : null,
    hotFiles: isRepo ? gitInfo.getHotFiles(targetDir) : null,
  };

  const secrets = scanForSecrets(targetDir, scanResult.tree);
  const licenses = checkLicenses(targetDir);
  const coverage = getCoverage(targetDir);

  const result = { scanResult, security, insights, stack, git, secrets, licenses, coverage, generatedAt: new Date().toISOString() };
  result.trend = recordSnapshot(targetDir, result);
  return result;
}

function openBrowser(url) {
  const platform = process.platform;
  try {
    if (platform === 'darwin') {
      spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    } else if (platform === 'win32') {
      spawn('cmd', ['/c', 'start', '""', url], { stdio: 'ignore', detached: true, shell: true }).unref();
    } else {
      spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
    }
  } catch {
    // best effort - non-fatal if no GUI browser can be launched
  }
}

async function startServer(targetDirs, { port = 4488, open = true } = {}) {
  const dirs = Array.isArray(targetDirs) ? targetDirs : [targetDirs];
  const publicDir = path.join(__dirname, '..', 'public');

  applyStoredApiKey();

  const projects = dirs.map((targetDir, i) => ({
    id: String(i),
    name: path.basename(targetDir),
    targetDir,
    cache: null,
  }));

  for (const project of projects) {
    console.log(`Scanning ${project.targetDir}`);
    project.cache = await buildData(project.targetDir);
  }

  function getProject(url) {
    const id = url.searchParams.get('project') || projects[0].id;
    return projects.find((p) => p.id === id) || projects[0];
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');

    if (url.pathname === '/api/projects') {
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(projects.map((p) => ({ id: p.id, name: p.name, path: p.targetDir }))));
      return;
    }

    if (url.pathname === '/api/data') {
      const project = getProject(url);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(project.cache));
      return;
    }

    if (url.pathname === '/api/rescan' && req.method === 'POST') {
      const project = getProject(url);
      buildData(project.targetDir)
        .then((fresh) => {
          project.cache = fresh;
          const projectName = (fresh.stack && fresh.stack.name) || fresh.scanResult.tree.name;
          notifyIfWorsened(projectName, fresh.trend);
          res.writeHead(200, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify(project.cache));
        })
        .catch((err) => {
          res.writeHead(500, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
        });
      return;
    }

    if (url.pathname === '/api/summary') {
      const project = getProject(url);
      const nodePath = url.searchParams.get('path') || project.cache.scanResult.tree.path;
      const node = findNode(project.cache.scanResult.tree, nodePath);
      if (!node) {
        res.writeHead(404, { 'Content-Type': MIME['.json'] });
        res.end(JSON.stringify({ error: 'Node not found' }));
        return;
      }
      const summaryAbsPath = node.type === 'file' ? path.resolve(project.targetDir, '..', node.path) : null;
      generateSummary(node, project.cache.scanResult, project.cache.security, project.cache.secrets, summaryAbsPath)
        .then(({ summary, source }) => {
          res.writeHead(200, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ summary, source }));
        })
        .catch((err) => {
          res.writeHead(500, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ error: err.message }));
        });
      return;
    }

    if (url.pathname === '/api/filehistory') {
      const project = getProject(url);
      const nodePath = url.searchParams.get('path');
      const node = findNode(project.cache.scanResult.tree, nodePath);
      if (!node || node.type !== 'file') {
        res.writeHead(404, { 'Content-Type': MIME['.json'] });
        res.end(JSON.stringify({ error: 'File not found' }));
        return;
      }
      const history = gitInfo.isGitRepo(project.targetDir)
        ? gitInfo.getFileHistory(project.targetDir, toGitRelPath(node.path))
        : null;
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify({ available: !!history, history: history || [] }));
      return;
    }

    if (url.pathname === '/api/sbom') {
      const project = getProject(url);
      const projectName = (project.cache.stack && project.cache.stack.name) || project.cache.scanResult.tree.name;
      const sbom = buildSbom(projectName, project.cache.licenses || {});
      res.writeHead(200, {
        'Content-Type': MIME['.json'],
        'Content-Disposition': `attachment; filename="${projectName}-sbom.cdx.json"`,
      });
      res.end(JSON.stringify(sbom, null, 2));
      return;
    }

    if (url.pathname === '/api/complexity') {
      const project = getProject(url);
      const result = analyzeComplexity(project.targetDir, project.cache.scanResult.tree);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(result));
      return;
    }

    if (url.pathname === '/api/deadcode') {
      const project = getProject(url);
      const result = findDeadExports(project.targetDir, project.cache.scanResult.tree);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(result));
      return;
    }

    if (url.pathname === '/api/duplicates') {
      const project = getProject(url);
      const result = findDuplicateBlocks(project.targetDir, project.cache.scanResult.tree);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(result));
      return;
    }

    if (url.pathname === '/api/settings' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(getStatus()));
      return;
    }

    if (url.pathname === '/api/settings' && req.method === 'POST') {
      readJsonBody(req)
        .then((body) => {
          const apiKey = (body.apiKey || '').trim();
          if (!apiKey) {
            res.writeHead(400, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: 'apiKey is required' }));
            return;
          }
          try {
            const status = setApiKey(apiKey);
            res.writeHead(200, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify(status));
          } catch (err) {
            res.writeHead(422, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: err.message }));
          }
        })
        .catch(() => {
          res.writeHead(400, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        });
      return;
    }

    if (url.pathname === '/api/settings' && req.method === 'DELETE') {
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(clearApiKey()));
      return;
    }

    if (url.pathname === '/api/settings/webhook' && req.method === 'POST') {
      readJsonBody(req)
        .then((body) => {
          const webhookUrl = (body.webhookUrl || '').trim();
          if (!webhookUrl) {
            res.writeHead(400, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: 'webhookUrl is required' }));
            return;
          }
          try {
            const status = setWebhookUrl(webhookUrl);
            res.writeHead(200, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify(status));
          } catch (err) {
            res.writeHead(422, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: err.message }));
          }
        })
        .catch(() => {
          res.writeHead(400, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        });
      return;
    }

    if (url.pathname === '/api/settings/webhook' && req.method === 'DELETE') {
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(clearWebhookUrl()));
      return;
    }

    let filePath = url.pathname === '/' ? '/index.html' : url.pathname;
    filePath = path.normalize(path.join(publicDir, filePath));
    if (!filePath.startsWith(publicDir)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(content);
    });
  });

  server.listen(port, () => {
    const url = `http://localhost:${port}`;
    console.log(`CodeScope dashboard running at ${url}`);
    if (open) openBrowser(url);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${port} is already in use. Try: codescope --port ${port + 1}`);
      process.exit(1);
    }
    throw err;
  });

  return server;
}

module.exports = { startServer };
