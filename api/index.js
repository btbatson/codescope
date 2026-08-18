const path = require('path');
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
const handler = createHandler(projects, publicDir);

module.exports = (req, res) => handler(req, res);
