// Heuristic, regex-based scan for common vulnerability patterns. This is not
// a substitute for a real SAST tool or manual review - it catches the
// reliably-pattern-matchable cases (string-built queries, dangerous C
// functions, obviously weak crypto) and flags them for a human to verify.
// Anything requiring real data-flow analysis (broken access control, CSRF,
// SSRF, race conditions) is left to the Claude-powered path, which reads the
// actual code instead of just matching patterns.

const RULES = [
  // --- Injection ---
  {
    category: 'SQL Injection', severity: 'high',
    re: /\.(query|execute|exec)\s*\(\s*[`'"][^`'"]*[`'"]\s*\+/,
    note: 'Query built with string concatenation instead of parameterized placeholders.',
  },
  {
    category: 'SQL Injection', severity: 'high',
    re: /(SELECT|INSERT|UPDATE|DELETE)\s+.{0,80}[`'"]\s*\+\s*\w+/i,
    note: 'SQL keyword found next to string concatenation - likely an unparameterized query.',
  },
  {
    category: 'SQL Injection', severity: 'high',
    re: /`[^`]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}[^`]*`/i,
    note: 'Template literal interpolates a variable directly into a SQL statement.',
  },
  {
    category: 'Command Injection', severity: 'critical',
    re: /\b(exec|execSync|spawn|spawnSync|system|popen|shell_exec|passthru)\s*\([^)]*\+/,
    note: 'Shell/process call built with string concatenation - untrusted input could break out of the intended command.',
  },
  {
    category: 'Command Injection', severity: 'critical',
    re: /\b(exec|system|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
    note: 'PHP superglobal passed directly into a shell execution function.',
  },
  {
    category: 'Command Injection', severity: 'high',
    re: /subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True/,
    note: 'subprocess call with shell=True - verify the command isn\'t built from untrusted input.',
  },
  {
    category: 'Cross-Site Scripting (XSS)', severity: 'high',
    re: /\.innerHTML\s*=\s*(?!['"`]\s*['"`])[^;=]+;/,
    note: 'innerHTML assigned a non-literal value - escape or sanitize before inserting into the DOM.',
  },
  {
    category: 'Cross-Site Scripting (XSS)', severity: 'moderate',
    re: /dangerouslySetInnerHTML/,
    note: 'React dangerouslySetInnerHTML bypasses XSS protection - confirm the content is sanitized.',
  },
  {
    category: 'Cross-Site Scripting (XSS)', severity: 'moderate',
    re: /document\.write\s*\(/,
    note: 'document.write with dynamic content is a classic XSS vector.',
  },
  {
    category: 'Cross-Site Scripting (XSS)', severity: 'high',
    re: /echo\s+\$_(GET|POST|REQUEST)\b(?!.*htmlspecialchars)/i,
    note: 'PHP superglobal echoed without htmlspecialchars/escaping.',
  },
  {
    category: 'Template Injection', severity: 'high',
    re: /render_template_string\s*\(/,
    note: 'Flask render_template_string with untrusted input can lead to server-side template injection.',
  },
  {
    category: 'XML Injection (XXE)', severity: 'high',
    re: /LIBXML_NOENT|resolveExternals\s*=\s*true|setFeature\(\s*["']http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl["']\s*,\s*false/,
    note: 'XML parser configured to resolve external entities - vulnerable to XXE unless the source is fully trusted.',
  },

  // --- Data handling ---
  {
    category: 'Insecure Deserialization', severity: 'high',
    re: /pickle\.loads?\s*\(/,
    note: "Python pickle deserializes arbitrary objects - never unpickle untrusted data.",
  },
  {
    category: 'Insecure Deserialization', severity: 'moderate',
    re: /yaml\.load\s*\((?!.*SafeLoader)/,
    note: 'yaml.load without SafeLoader can execute arbitrary code from the input.',
  },
  {
    category: 'Insecure Deserialization', severity: 'high',
    re: /\bunserialize\s*\(/,
    note: "PHP unserialize() on untrusted input can lead to object injection.",
  },
  {
    category: 'Sensitive Data Exposure', severity: 'moderate',
    re: /(console\.log|print|logger\.\w+)\s*\([^)]*(password|secret|token|api[_-]?key)\b/i,
    note: 'Logging a variable whose name suggests it holds a credential or secret.',
  },
  {
    category: 'Path Traversal', severity: 'high',
    re: /(readFile|readFileSync|createReadStream|open|fopen)\s*\([^)]*(req\.(query|params|body)|\$_(GET|POST))/i,
    note: 'File path built directly from request input - validate/sanitize to prevent path traversal.',
  },

  // --- Cryptography ---
  {
    category: 'Weak Cryptography', severity: 'moderate',
    re: /\b(createHash\(['"]md5['"]\)|hashlib\.md5|MD5\.|md5\()/,
    note: 'MD5 is not safe for passwords or security-sensitive hashing - use bcrypt/argon2/scrypt.',
  },
  {
    category: 'Weak Cryptography', severity: 'moderate',
    re: /\b(createHash\(['"]sha1['"]\)|hashlib\.sha1|SHA1\.|sha1\()/,
    note: 'SHA-1 is deprecated for security use - use bcrypt/argon2/scrypt for passwords, SHA-256+ otherwise.',
  },
  {
    category: 'Weak Cryptography', severity: 'high',
    re: /\bDES\b|createCipher\(|Cipher\.getInstance\(["']DES|["']ECB["']/,
    note: 'DES and ECB mode are considered broken - use AES-GCM or similar authenticated encryption.',
  },
  {
    category: 'Insecure Randomness', severity: 'moderate',
    re: /Math\.random\(\)[^;]{0,60}(token|secret|password|session|otp|nonce)/i,
    note: 'Math.random() is not cryptographically secure - use crypto.randomBytes for security-sensitive values.',
  },
  {
    category: 'Insecure Randomness', severity: 'moderate',
    re: /\brand\(\)[^;]{0,60}(token|secret|password|session)/i,
    note: 'rand()/mt_rand() is not cryptographically secure for security-sensitive values.',
  },

  // --- Web-specific ---
  {
    category: 'Insecure CORS', severity: 'moderate',
    re: /Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]/,
    note: "Wildcard CORS origin ('*') allows any site to read responses - scope it to known origins.",
  },
  {
    category: 'Insecure CORS', severity: 'moderate',
    re: /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/,
    note: "CORS configured with origin: '*' - scope it to known origins if credentials or sensitive data are involved.",
  },
  {
    category: 'Possible SSRF', severity: 'moderate',
    re: /\b(fetch|axios\.\w+|requests\.\w+|urlopen)\s*\(\s*(?!['"`])\w[\w.]*\)/,
    note: 'URL passed as a variable rather than a literal - if it originates from user input, validate/allow-list it to prevent SSRF.',
  },

  // --- Configuration ---
  {
    category: 'Debug Mode Enabled', severity: 'low',
    re: /\b(DEBUG|app\.debug)\s*=\s*True\b/,
    note: 'Debug mode left on can leak stack traces and internals in production.',
  },

  // --- Memory safety (C/C++) ---
  {
    category: 'Buffer Overflow Risk', severity: 'high',
    re: /\bgets\s*\(/,
    note: 'gets() has no bounds checking and is inherently unsafe - use fgets() instead.',
  },
  {
    category: 'Buffer Overflow Risk', severity: 'moderate',
    re: /\b(strcpy|strcat|sprintf|vsprintf)\s*\(/,
    note: 'Unbounded C string function - prefer the bounded variant (strncpy, strncat, snprintf).',
  },
];

const EXT_LANG_HINT = {
  '.c': 'c', '.h': 'c', '.cpp': 'c', '.hpp': 'c', '.cc': 'c',
};

function scanFileForVulnPatterns(content, ext, maxFindings = 15) {
  const lines = content.split(/\r\n|\r|\n/);
  const findings = [];

  for (let i = 0; i < lines.length && findings.length < maxFindings; i++) {
    const line = lines[i];
    for (const rule of RULES) {
      if (rule.re.test(line)) {
        findings.push({
          category: rule.category,
          severity: rule.severity,
          line: i + 1,
          note: rule.note,
          snippet: line.trim().slice(0, 140),
        });
        if (findings.length >= maxFindings) break;
      }
    }
  }

  return findings;
}

module.exports = { scanFileForVulnPatterns, EXT_LANG_HINT };
