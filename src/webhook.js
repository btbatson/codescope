const { getWebhookUrl } = require('./config');

async function sendWebhook(url, payload) {
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error('Webhook notification failed:', err.message);
  }
}

// Fires only when a rescan finds MORE vulnerabilities or secrets than the
// previous scan - not on every rescan, and never on the very first scan
// (no baseline to compare against yet).
function notifyIfWorsened(projectName, trend) {
  const url = getWebhookUrl();
  if (!url || !trend) return;

  const { deltas, current } = trend;
  if (deltas.vulnerabilities <= 0 && deltas.secrets <= 0) return;

  const lines = [`CodeScope: new findings in ${projectName}`];
  if (deltas.vulnerabilities > 0) {
    lines.push(`+${deltas.vulnerabilities} vulnerabilit${deltas.vulnerabilities === 1 ? 'y' : 'ies'} (now ${current.vulnerabilities} total)`);
  }
  if (deltas.secrets > 0) {
    lines.push(`+${deltas.secrets} possible secret${deltas.secrets === 1 ? '' : 's'} (now ${current.secrets} total)`);
  }

  // Slack-compatible `text` field plus raw structured data for generic consumers.
  sendWebhook(url, { text: lines.join(' - '), project: projectName, deltas, current });
}

module.exports = { notifyIfWorsened };
