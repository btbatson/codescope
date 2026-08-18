const path = require('path');

// A crash anywhere in the require chain (or in applyStoredApiKey/createHandler
// below) would otherwise take down every single request with an opaque
// FUNCTION_INVOCATION_FAILED and no clue why. Catching it here means the
// actual error message and stack make it into Vercel's function logs and
// back to the client as JSON instead.
let handler;
let bootError;
try {
  const { createHandler } = require('../src/server');
  const { applyStoredApiKey } = require('../src/config');

  applyStoredApiKey();

  // No target directory to scan on boot - a Vercel deployment has no local
  // codebase to point at. It's meant to be used through the "Add repo" flow,
  // which fetches github.com repos live via GitHub's API/CDN (no `git`
  // binary or persistent disk required) since repoClone.js falls back to
  // that automatically whenever a git executable isn't available.
  const projects = [];
  const publicDir = path.join(__dirname, '..', 'public');
  handler = createHandler(projects, publicDir);
} catch (err) {
  bootError = err;
  console.error('CodeScope function failed to initialize:', err);
}

module.exports = (req, res) => {
  if (bootError) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'CodeScope failed to start', message: bootError.message, stack: bootError.stack }));
    return;
  }
  try {
    handler(req, res);
  } catch (err) {
    console.error('CodeScope request crashed:', err);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Internal error', message: err.message, stack: err.stack }));
    }
  }
};
