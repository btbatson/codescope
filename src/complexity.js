const fs = require('fs');
const path = require('path');

const MAX_FILES = 400;
const MAX_FILE_SIZE = 400 * 1024;

const BRACE_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.php', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.swift', '.kt', '.rs']);
const INDENT_EXT = new Set(['.py']);

const DECISION_RE = /\b(if|else if|elif|for|foreach|while|case|catch|except)\b|&&|\|\||\?\s*[^:]+:/g;

// Matches common function/method declaration openers across C-like languages.
const BRACE_FN_RE = /^[ \t]*(?:export\s+)?(?:default\s+)?(?:public\s+|private\s+|protected\s+|static\s+|async\s+|function\s+)*(?:function\s*\*?\s*([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?\([^)]*\)\s*=>|([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{)/;
const PY_FN_RE = /^([ \t]*)def\s+([A-Za-z_]\w*)\s*\(/;

function countDecisionPoints(text) {
  const matches = text.match(DECISION_RE);
  return matches ? matches.length : 0;
}

function analyzeBraceFile(text, relPath, functions) {
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = BRACE_FN_RE.exec(lines[i]);
    if (!m) continue;
    const name = m[1] || m[2] || m[3] || 'anonymous';

    // Find the opening brace (may be on this line or a following one), then
    // walk forward counting brace depth to find where the function ends.
    let braceLine = i;
    let searchText = lines[i];
    while (!searchText.includes('{') && braceLine < lines.length - 1 && braceLine < i + 3) {
      braceLine++;
      searchText = lines[braceLine];
    }
    if (!searchText.includes('{')) continue;

    let depth = 0;
    let started = false;
    let endLine = braceLine;
    for (let j = braceLine; j < lines.length && j < braceLine + 2000; j++) {
      for (const ch of lines[j]) {
        if (ch === '{') { depth++; started = true; }
        else if (ch === '}') depth--;
      }
      if (started && depth <= 0) { endLine = j; break; }
      endLine = j;
    }

    const bodyLines = lines.slice(i, endLine + 1);
    const bodyText = bodyLines.join('\n');
    const lineCount = endLine - i + 1;
    if (lineCount < 3) continue;

    functions.push({
      name, file: relPath, startLine: i + 1, endLine: endLine + 1,
      lineCount, complexity: 1 + countDecisionPoints(bodyText),
    });
    i = endLine; // skip past this function's body
  }
}

function analyzePythonFile(text, relPath, functions) {
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = PY_FN_RE.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const name = m[2];
    let endLine = i;
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j];
      if (!line.trim()) { endLine = j; continue; }
      const lineIndent = line.match(/^[ \t]*/)[0].length;
      if (lineIndent <= indent) break;
      endLine = j;
    }
    const lineCount = endLine - i + 1;
    if (lineCount < 3) continue;
    const bodyText = lines.slice(i, endLine + 1).join('\n');
    functions.push({
      name, file: relPath, startLine: i + 1, endLine: endLine + 1,
      lineCount, complexity: 1 + countDecisionPoints(bodyText),
    });
  }
}

function walkForComplexity(targetDir, node, functions, state) {
  if (!node || state.filesScanned >= MAX_FILES) return;
  if (node.type === 'file') {
    const ext = (node.ext || '').toLowerCase();
    if (!BRACE_EXT.has(ext) && !INDENT_EXT.has(ext)) return;
    state.filesScanned++;
    const absPath = path.resolve(targetDir, '..', node.path);
    let text;
    try {
      const stat = fs.statSync(absPath);
      if (stat.size > MAX_FILE_SIZE) return;
      text = fs.readFileSync(absPath, 'utf8');
    } catch {
      return;
    }
    if (BRACE_EXT.has(ext)) analyzeBraceFile(text, node.path, functions);
    else analyzePythonFile(text, node.path, functions);
  } else if (node.type === 'dir') {
    for (const child of node.children) {
      if (state.filesScanned >= MAX_FILES) break;
      walkForComplexity(targetDir, child, functions, state);
    }
  }
}

function analyzeComplexity(targetDir, tree) {
  const functions = [];
  const state = { filesScanned: 0 };
  walkForComplexity(targetDir, tree, functions, state);

  return {
    filesScanned: state.filesScanned,
    truncated: state.filesScanned >= MAX_FILES,
    longestFunctions: [...functions].sort((a, b) => b.lineCount - a.lineCount).slice(0, 15),
    mostComplexFunctions: [...functions].sort((a, b) => b.complexity - a.complexity).slice(0, 15),
  };
}

module.exports = { analyzeComplexity };
