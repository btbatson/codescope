const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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
const { cloneOrUpdateRepo } = require('./repoClone');

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

const SESSION_COOKIE = 'cs_sid';
const MAX_SESSIONS = 200; // just an in-memory demo cache, not real persistence - keep it bounded
const sessionProjects = new Map();

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  });
  return out;
}

// Each visitor to the hosted deployment gets their own private, in-memory
// project list, keyed by an anonymous session cookie - otherwise, since a
// warm serverless container can serve multiple visitors, one person adding
// a repo could leak into a stranger's view of the app. Every session starts
// empty, so the hosted app always opens on the "add a repo" welcome screen.
function getSessionProjects(req, res) {
  const cookies = parseCookies(req);
  let sid = cookies[SESSION_COOKIE];
  if (!sid || !sessionProjects.has(sid)) {
    sid = crypto.randomUUID();
    sessionProjects.set(sid, []);
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`);
    if (sessionProjects.size > MAX_SESSIONS) {
      sessionProjects.delete(sessionProjects.keys().next().value);
    }
  }
  return sessionProjects.get(sid);
}

function getProject(projects, url) {
  if (!projects.length) return null;
  const id = url.searchParams.get('project') || projects[0].id;
  return projects.find((p) => p.id === id) || projects[0];
}

function createHandler(projectsOrOptions, publicDir, { perSession = false } = {}) {
  return function handler(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const projects = perSession ? getSessionProjects(req, res) : projectsOrOptions;

    if (url.pathname === '/api/projects') {
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(projects.map((p) => ({ id: p.id, name: p.name, path: p.targetDir, mode: p.mode || 'local' }))));
      return;
    }

    if (url.pathname === '/api/projects/add' && req.method === 'POST') {
      readJsonBody(req)
        .then(async (body) => {
          const repoUrl = (body.url || '').trim();
          if (!repoUrl) {
            res.writeHead(400, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: 'url is required' }));
            return;
          }
          try {
            const { path: clonedPath, name, mode } = await cloneOrUpdateRepo(repoUrl);
            const existing = projects.find((p) => p.targetDir === clonedPath);
            if (existing) {
              existing.mode = mode;
              existing.cache = await buildData(clonedPath, { silent: true });
              res.writeHead(200, { 'Content-Type': MIME['.json'] });
              res.end(JSON.stringify({ id: existing.id, name: existing.name, path: existing.targetDir, mode: existing.mode }));
              return;
            }
            const project = { id: String(projects.length), name, targetDir: clonedPath, mode, cache: null };
            project.cache = await buildData(clonedPath, { silent: true });
            projects.push(project);
            res.writeHead(200, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ id: project.id, name: project.name, path: project.targetDir, mode: project.mode }));
          } catch (err) {
            const status = err.code === 'INVALID_URL' || err.code === 'REPO_TOO_LARGE' ? 400 : 422;
            res.writeHead(status, { 'Content-Type': MIME['.json'] });
            res.end(JSON.stringify({ error: err.message }));
          }
        })
        .catch(() => {
          res.writeHead(400, { 'Content-Type': MIME['.json'] });
          res.end(JSON.stringify({ error: 'Invalid request body' }));
        });
      return;
    }

    if (url.pathname === '/api/data') {
      const project = getProject(projects, url);
      if (!project) {
        res.writeHead(200, { 'Content-Type': MIME['.json'] });
        res.end(JSON.stringify({ empty: true }));
        return;
      }
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(project.cache));
      return;
    }

    function requireProject() {
      const project = getProject(projects, url);
      if (!project) {
        res.writeHead(404, { 'Content-Type': MIME['.json'] });
        res.end(JSON.stringify({ error: 'No project selected yet - add a repository first.' }));
      }
      return project;
    }

    if (url.pathname === '/api/rescan' && req.method === 'POST') {
      const project = requireProject();
      if (!project) return;
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
      const project = requireProject();
      if (!project) return;
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
      const project = requireProject();
      if (!project) return;
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
      const project = requireProject();
      if (!project) return;
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
      const project = requireProject();
      if (!project) return;
      const result = analyzeComplexity(project.targetDir, project.cache.scanResult.tree);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(result));
      return;
    }

    if (url.pathname === '/api/deadcode') {
      const project = requireProject();
      if (!project) return;
      const result = findDeadExports(project.targetDir, project.cache.scanResult.tree);
      res.writeHead(200, { 'Content-Type': MIME['.json'] });
      res.end(JSON.stringify(result));
      return;
    }

    if (url.pathname === '/api/duplicates') {
      const project = requireProject();
      if (!project) return;
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
  };
}

async function startServer(targetDirs, { port = 4488, open = true } = {}) {
  const dirs = Array.isArray(targetDirs) ? targetDirs : [targetDirs];
  const publicDir = path.join(__dirname, '..', 'public');

  applyStoredApiKey();

  const projects = dirs.map((targetDir, i) => ({
    id: String(i),
    name: path.basename(targetDir),
    targetDir,
    mode: 'local',
    cache: null,
  }));

  for (const project of projects) {
    console.log(`Scanning ${project.targetDir}`);
    project.cache = await buildData(project.targetDir);
  }

  const handler = createHandler(projects, publicDir);
  const server = http.createServer(handler);

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

// Vercel's build was observed auto-detecting a file literally named
// server.js anywhere in the repo as an implicit function entry point, by
// naming convention, independent of api/index.js - this file was renamed to
// appServer.js to avoid that collision. Exporting a callable here too (with
// the real API attached as properties - functions are objects too) is a
// second, cheap line of defense: it keeps `require('./appServer')` working
// exactly as before for bin/codescope.js and api/index.js, while also
// surviving being invoked directly instead of hard-crashing the deployment.
function serverModule(req, res) {
  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain');
  res.end('src/appServer.js is a shared module, not a deployable entry point - see api/index.js.');
}
serverModule.startServer = startServer;
serverModule.createHandler = createHandler;
serverModule.buildData = buildData;

module.exports = serverModule;
