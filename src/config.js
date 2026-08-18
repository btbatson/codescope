const fs = require('fs');
const os = require('os');
const path = require('path');

const CONFIG_DIR = path.join(os.homedir(), '.codescope');
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

// Tracks whether the currently-active ANTHROPIC_API_KEY came from our config
// file (so we know it's safe to unset) vs. the user's own shell environment
// (which we should never touch).
let keySetByConfig = false;

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveConfig(config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

// Called once at server startup: if the shell didn't already provide a key,
// fall back to whatever was saved locally via the dashboard's Settings panel.
function applyStoredApiKey() {
  if (process.env.ANTHROPIC_API_KEY) return;
  const config = loadConfig();
  if (config.anthropicApiKey) {
    process.env.ANTHROPIC_API_KEY = config.anthropicApiKey;
    keySetByConfig = true;
  }
}

function maskKey(key) {
  if (!key || key.length < 8) return null;
  return `${key.slice(0, 7)}...${key.slice(-4)}`;
}

function maskUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/...`;
  } catch {
    return null;
  }
}

function getStatus() {
  const key = process.env.ANTHROPIC_API_KEY;
  const config = loadConfig();
  return {
    hasApiKey: !!key,
    keyPreview: maskKey(key),
    hasWebhook: !!config.webhookUrl,
    webhookPreview: maskUrl(config.webhookUrl),
  };
}

function getWebhookUrl() {
  return loadConfig().webhookUrl || null;
}

function setWebhookUrl(url) {
  if (!/^https?:\/\/.+/.test(url)) {
    const err = new Error('That doesn\'t look like a valid URL - it should start with http:// or https://.');
    err.code = 'INVALID_URL';
    throw err;
  }
  const config = loadConfig();
  config.webhookUrl = url;
  saveConfig(config);
  return getStatus();
}

function clearWebhookUrl() {
  const config = loadConfig();
  delete config.webhookUrl;
  saveConfig(config);
  return getStatus();
}

// Anthropic API keys look like "sk-ant-api03-...". This won't catch a
// revoked or fake-but-well-formed key (only a real API call can), but it
// catches pasting the wrong thing entirely - a shell command, a stray quote,
// whitespace - which is the far more common mistake.
function isPlausibleKey(apiKey) {
  return /^sk-ant-[A-Za-z0-9_-]{20,}$/.test(apiKey);
}

function setApiKey(apiKey) {
  if (!isPlausibleKey(apiKey)) {
    const err = new Error("That doesn't look like an Anthropic API key. It should start with \"sk-ant-\" and contain only the key itself - nothing else pasted around it.");
    err.code = 'INVALID_KEY';
    throw err;
  }
  const config = loadConfig();
  config.anthropicApiKey = apiKey;
  saveConfig(config);
  process.env.ANTHROPIC_API_KEY = apiKey;
  keySetByConfig = true;
  return getStatus();
}

function clearApiKey() {
  const config = loadConfig();
  delete config.anthropicApiKey;
  saveConfig(config);
  if (keySetByConfig) {
    delete process.env.ANTHROPIC_API_KEY;
    keySetByConfig = false;
  }
  return getStatus();
}

module.exports = {
  applyStoredApiKey, getStatus, setApiKey, clearApiKey,
  getWebhookUrl, setWebhookUrl, clearWebhookUrl,
};
