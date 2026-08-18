const fs = require('fs');
const { formatBytes } = require('./insights');
const { scanFileForVulnPatterns } = require('./securityPatterns');

const OPENERS = [
  'Here is what stands out:',
  'Taking a closer look:',
  'At a glance:',
  'Breaking this down:',
  'A quick read on this:',
];

const PURPOSE_GUESSES = {
  src: 'This is typically the main application source directory.',
  lib: 'This usually holds shared library code.',
  'wp-content': 'This is a WordPress content directory - usually themes, plugins, and uploads live here.',
  'wp-admin': "This is WordPress's core admin dashboard code, typically not meant to be edited directly.",
  'wp-includes': "This holds WordPress's core includes and library code.",
  node_modules: 'This holds installed npm dependencies - normally excluded from version control.',
  vendor: 'This holds third-party dependencies pulled in by a package manager.',
  public: 'This usually holds statically served, publicly accessible assets.',
  dist: 'This is likely a build output directory, generated rather than hand-written.',
  build: 'This is likely a build output directory, generated rather than hand-written.',
  assets: 'This typically holds images, fonts, or other static assets.',
  components: 'This likely holds reusable UI components.',
  tests: "This likely holds the project's test suite.",
  test: "This likely holds the project's test suite.",
  __tests__: "This likely holds the project's test suite.",
  spec: "This likely holds the project's test suite.",
  '.git': "This is Git's internal repository data.",
  '.github': 'This holds GitHub-specific configuration such as workflows and issue templates.',
  docs: 'This likely holds project documentation.',
  scripts: 'This likely holds automation or build scripts.',
  config: 'This likely holds configuration files.',
  migrations: 'This likely holds database migration files.',
  api: 'This likely holds API route or endpoint definitions.',
  hooks: 'This likely holds reusable logic hooks.',
  utils: 'This likely holds shared utility/helper functions.',
  styles: 'This likely holds stylesheets or design tokens.',
};

const CLAUDE_MODEL = 'claude-sonnet-5';
const CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages';
const MAX_SCAN_SIZE = 400 * 1024;
const MAX_CODE_EXCERPT = 8000; // chars sent to Claude - keeps prompts cheap and fast

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function countRecursive(node) {
  let files = 0, dirs = 0;
  function walk(n) {
    if (n.type === 'file') { files++; return; }
    if (n.type === 'dir-excluded') { dirs++; return; }
    dirs++;
    (n.children || []).forEach(walk);
  }
  (node.children || []).forEach(walk);
  return { files, dirs };
}

function topLanguages(node, limit = 3) {
  const stats = {};
  function walk(n) {
    if (n.type === 'file') {
      stats[n.language] = (stats[n.language] || 0) + n.size;
    } else if (n.type === 'dir') {
      (n.children || []).forEach(walk);
    }
  }
  (node.children || []).forEach(walk);
  return Object.entries(stats).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function findLargestDescendant(node) {
  let largest = null;
  function walk(n) {
    if (n === node) {
      (n.children || []).forEach(walk);
      return;
    }
    if (!largest || n.size > largest.size) largest = n;
    if (n.type === 'dir') (n.children || []).forEach(walk);
  }
  (node.children || []).forEach((c) => {
    if (!largest || c.size > largest.size) largest = c;
  });
  return largest;
}

function findNode(tree, targetPath) {
  if (!tree) return null;
  if (tree.path === targetPath) return tree;
  if (tree.type !== 'dir') return null;
  for (const child of tree.children || []) {
    const found = findNode(child, targetPath);
    if (found) return found;
  }
  return null;
}

function purposeGuess(name) {
  return PURPOSE_GUESSES[name.toLowerCase()] || null;
}

// Best-effort read for the vulnerability pattern scan + the Claude prompt.
// Returns null for anything binary, missing, or too large to bother with.
function readFileForScan(absPath) {
  if (!absPath) return null;
  try {
    const stat = fs.statSync(absPath);
    if (!stat.isFile() || stat.size > MAX_SCAN_SIZE) return null;
    const content = fs.readFileSync(absPath, 'utf8');
    if (content.slice(0, 2000).indexOf(String.fromCharCode(0)) !== -1) return null; // binary
    return content;
  } catch {
    return null;
  }
}

// Gather the grounded facts once, then either template them (heuristic engine)
// or hand them to Claude to write up (so Claude narrates real numbers instead
// of inventing any).
function buildFacts(node, scanResult, security, secrets, absPath) {
  const isRoot = node.path === scanResult.tree.path;
  if (node.type === 'file') {
    const fileFindings = secrets ? secrets.findings.filter((f) => f.file === node.path) : [];
    const content = readFileForScan(absPath);
    const vulnFindings = content ? scanFileForVulnPatterns(content, node.ext) : [];
    return {
      isRoot, kind: 'file', name: node.name, language: node.language,
      size: node.size, mtime: node.mtime,
      secretFindings: fileFindings.length ? fileFindings.map((f) => f.rule) : null,
      vulnFindings,
      codeExcerpt: content ? content.slice(0, MAX_CODE_EXCERPT) : null,
      codeTruncated: content ? content.length > MAX_CODE_EXCERPT : false,
    };
  }
  const counts = countRecursive(node);
  const langs = topLanguages(node);
  const largest = findLargestDescendant(node);
  const facts = {
    isRoot, kind: 'dir', name: node.name, size: node.size,
    files: counts.files, dirs: counts.dirs,
    languages: langs.map(([lang, size]) => ({ lang, size })),
    purpose: purposeGuess(node.name),
    largest: largest && largest.size > 0 ? { name: largest.name, size: largest.size } : null,
  };
  if (isRoot && security) {
    let total = 0;
    if (security.npm && security.npm.available) {
      const v = security.npm.vulnerabilities;
      total += (v.critical || 0) + (v.high || 0) + (v.moderate || 0) + (v.low || 0);
    }
    if (security.composer && security.composer.available) {
      total += security.composer.advisories.length;
    }
    if (security.wordpress && security.wordpress.available) {
      total += security.wordpress.plugins.filter((p) => p.outdated).length
        + security.wordpress.themes.filter((t) => t.outdated).length;
    }
    if (security.npm || security.composer || security.wordpress) facts.vulnerabilities = total;
  }
  return facts;
}

function describeVulnFindings(vulnFindings) {
  const byCategory = new Map();
  for (const f of vulnFindings) {
    if (!byCategory.has(f.category)) byCategory.set(f.category, []);
    byCategory.get(f.category).push(f);
  }
  const parts = [];
  let shown = 0;
  for (const [category, items] of byCategory) {
    if (shown >= 3) break;
    parts.push(`${category} (line ${items[0].line}: ${items[0].note})`);
    shown++;
  }
  const remaining = byCategory.size - shown;
  return `${parts.join('; ')}${remaining > 0 ? `, and ${remaining} other categor${remaining === 1 ? 'y' : 'ies'} of concern` : ''}`;
}

function composeHeuristicSummary(facts) {
  const opener = pick(OPENERS);
  const parts = [];

  if (facts.kind === 'file') {
    if (facts.vulnFindings && facts.vulnFindings.length) {
      parts.push(`Security pattern scan flagged ${facts.vulnFindings.length} potential issue${facts.vulnFindings.length === 1 ? '' : 's'} in ${facts.name}: ${describeVulnFindings(facts.vulnFindings)}. This is a heuristic pattern scan, not a full audit - verify manually before treating it as authoritative.`);
    }
    parts.push(`${opener} ${facts.name} is a ${facts.language} file, ${formatBytes(facts.size)}${facts.mtime ? `, last modified ${new Date(facts.mtime).toLocaleDateString()}` : ''}.`);
    if (/\.(test|spec)\./i.test(facts.name)) parts.push('Its name suggests this is an automated test file.');
    else if (/config/i.test(facts.name)) parts.push('Its name suggests this is a configuration file.');
    else if (/^readme/i.test(facts.name)) parts.push('This is the project (or folder) readme - usually the best starting point for context.');
    if (facts.secretFindings) {
      parts.push(`The secret scanner flagged this file for ${facts.secretFindings.join(', ')} - worth checking whether this was hardcoded intentionally, left in by mistake, or introduced by generated/copied code.`);
    }
    if (facts.vulnFindings && !facts.vulnFindings.length) {
      parts.push('The heuristic security pattern scan found no obvious issues (SQL/command injection, XSS, weak crypto, etc.) in this file, though this only covers pattern-matchable cases.');
    }
    return parts.join(' ');
  }

  const label = facts.isRoot ? 'this project' : `the "${facts.name}" folder`;
  parts.push(`${opener} ${label} contains ${facts.files} file${facts.files === 1 ? '' : 's'} across ${facts.dirs} folder${facts.dirs === 1 ? '' : 's'}, totalling ${formatBytes(facts.size)}.`);

  if (facts.languages.length) {
    const [top, ...rest] = facts.languages;
    parts.push(`The dominant file type is ${top.lang} (${formatBytes(top.size)})${rest.length ? `, followed by ${rest.slice(0, 2).map((l) => l.lang).join(' and ')}` : ''}.`);
  }

  if (facts.purpose) parts.push(facts.purpose);

  if (facts.largest) {
    parts.push(`The largest item inside is ${facts.largest.name} at ${formatBytes(facts.largest.size)}.`);
  }

  if (facts.isRoot && facts.vulnerabilities !== undefined) {
    parts.push(facts.vulnerabilities
      ? `A dependency audit found ${facts.vulnerabilities} known vulnerabilit${facts.vulnerabilities === 1 ? 'y' : 'ies'} - see the Analysis tab for details.`
      : 'A dependency audit found no known vulnerabilities.');
  }

  return parts.join(' ');
}

function factsToPrompt(facts) {
  if (facts.kind === 'file') {
    return [
      `File: ${facts.name}`,
      `Language/type: ${facts.language}`,
      `Size: ${formatBytes(facts.size)}`,
      facts.mtime ? `Last modified: ${new Date(facts.mtime).toLocaleDateString()}` : null,
      facts.secretFindings ? `Secret scanner flagged this file for: ${facts.secretFindings.join(', ')}` : null,
      facts.vulnFindings && facts.vulnFindings.length
        ? `Heuristic pattern scan flagged:\n${facts.vulnFindings.map((f) => `  - [${f.severity}] ${f.category} at line ${f.line}: ${f.note} (code: ${f.snippet})`).join('\n')}`
        : null,
    ].filter(Boolean).join('\n');
  }
  const lines = [
    `Folder: ${facts.isRoot ? '(project root) ' : ''}${facts.name}`,
    `Contents: ${facts.files} files across ${facts.dirs} subfolders`,
    `Total size: ${formatBytes(facts.size)}`,
  ];
  if (facts.languages.length) {
    lines.push(`File types by size: ${facts.languages.map((l) => `${l.lang} (${formatBytes(l.size)})`).join(', ')}`);
  }
  if (facts.purpose) lines.push(`Naming convention hint: ${facts.purpose}`);
  if (facts.largest) lines.push(`Largest item inside: ${facts.largest.name} (${formatBytes(facts.largest.size)})`);
  if (facts.vulnerabilities !== undefined) {
    lines.push(`Dependency audit: ${facts.vulnerabilities} known vulnerabilities`);
  }
  return lines.join('\n');
}

const SECURITY_REVIEW_CHECKLIST = `
- Injection: SQL injection (string-concatenated queries, missing parameterization), command injection (unsanitized input in shell calls), XSS (unescaped output in HTML/JS contexts), LDAP/XML/template injection
- Authentication and access control: weak or missing auth checks, broken access control (missing authorization on endpoints), insecure session handling (predictable tokens, missing expiration), hardcoded credentials/API keys/secrets
- Data handling: sensitive data exposure (logging secrets, plaintext passwords), insecure deserialization, missing input validation/sanitization, path traversal
- Cryptography: weak/outdated algorithms (MD5, SHA1 for passwords, DES), improper key management, insecure randomness for security-sensitive contexts
- Web-specific: CSRF, insecure CORS configuration, missing security headers, SSRF
- Configuration: insecure defaults, debug mode left enabled
- Memory/logic issues (for C/C++/similar): buffer overflows, use-after-free, integer overflow, race conditions, off-by-one errors that create exploitable conditions`;

async function callClaude(facts) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  let prompt;
  if (facts.kind === 'file') {
    prompt = `You are a security-focused code reviewer. Review the file below for real, verifiable issues against this checklist - only report what you can actually see in the code shown, never speculate about code you can't see, and do not invent line numbers or issues that aren't present:
${SECURITY_REVIEW_CHECKLIST}

If a heuristic pattern scanner already flagged something, verify it against the actual code and mention whether it looks like a real concern or a false positive. If the file has no significant issues, say so plainly - don't manufacture concerns to fill space.

Write a plain-text summary, no markdown, no headers, no bullet points. Lead with security findings (if any) naming the specific issue and line, then briefly describe what the file does. Keep it to 2-6 sentences depending on how much there is to report.

Facts:
${factsToPrompt(facts)}

${facts.codeExcerpt ? `Source code${facts.codeTruncated ? ' (truncated to the first part of the file)' : ''}:\n\`\`\`\n${facts.codeExcerpt}\n\`\`\`` : 'Source code was not available to review (binary, too large, or unreadable) - base the summary only on the facts above.'}`;
  } else {
    prompt = `You are a code-review assistant summarizing one node of a project's file tree for a developer dashboard. Using ONLY the facts below (do not invent anything not listed), write a 2-4 sentence plain-text summary. Be concrete and specific, no markdown, no headers, no bullet points, just prose. Vary your opening phrase naturally.

Facts:
${factsToPrompt(facts)}`;
  }

  const res = await fetch(CLAUDE_API_URL, {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 500,
      messages: [{ role: 'user', content: prompt }],
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Claude API error ${res.status}: ${body.slice(0, 200)}`);
  }

  const json = await res.json();
  const text = json.content && json.content[0] && json.content[0].text;
  return text ? text.trim() : null;
}

async function generateSummary(node, scanResult, security, secrets, absPath) {
  const facts = buildFacts(node, scanResult, security, secrets, absPath);

  if (process.env.ANTHROPIC_API_KEY) {
    try {
      const claudeText = await callClaude(facts);
      if (claudeText) return { summary: claudeText, source: 'claude' };
    } catch (err) {
      console.error('Claude summary failed, falling back to local engine:', err.message);
    }
  }

  return { summary: composeHeuristicSummary(facts), source: 'heuristic' };
}

module.exports = { generateSummary, findNode };
