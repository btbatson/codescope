const os = require('os');
const path = require('path');

// On serverless platforms (Vercel, AWS Lambda, ...) $HOME usually isn't
// writable and each invocation may land on a fresh container, so state that
// would normally live in ~/.codescope goes to the ephemeral /tmp instead.
// It won't reliably survive between requests there, but that's fine - on
// those platforms the point is to serve a live demo, not persist history.
const IS_SERVERLESS = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);

function stateRoot() {
  if (process.env.CODESCOPE_STATE_DIR) return process.env.CODESCOPE_STATE_DIR;
  if (IS_SERVERLESS) return path.join(os.tmpdir(), '.codescope');
  return path.join(os.homedir(), '.codescope');
}

module.exports = { stateRoot, IS_SERVERLESS };
