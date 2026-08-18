const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CODE_EXT = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.go', '.rs',
  '.java', '.kt', '.swift', '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.vue',
]);
const MAX_FILES = 400;
const MAX_FILE_SIZE = 400 * 1024;
const WINDOW = 6; // lines per block
const MIN_BLOCK_LENGTH = 60; // normalized chars - filters out trivial short blocks
const MAX_GROUPS = 20;

function normalize(line) {
  return line.trim().replace(/\s+/g, ' ');
}

function collectFiles(node, out, state) {
  if (!node || state.count >= MAX_FILES) return;
  if (node.type === 'file') {
    if (!CODE_EXT.has((node.ext || '').toLowerCase())) return;
    out.push(node);
    state.count++;
  } else if (node.type === 'dir') {
    for (const child of node.children) {
      if (state.count >= MAX_FILES) break;
      collectFiles(child, out, state);
    }
  }
}

function findDuplicateBlocks(targetDir, tree) {
  const files = [];
  collectFiles(tree, files, { count: 0 });

  const buckets = new Map(); // hash -> [{file, startLine}]

  for (const file of files) {
    const absPath = path.resolve(targetDir, '..', file.path);
    let text;
    try {
      const stat = fs.statSync(absPath);
      if (stat.size > MAX_FILE_SIZE) continue;
      text = fs.readFileSync(absPath, 'utf8');
    } catch {
      continue;
    }

    const rawLines = text.split(/\r\n|\r|\n/);
    // Keep normalized non-blank lines with their original line numbers.
    const lines = [];
    rawLines.forEach((l, i) => {
      const n = normalize(l);
      if (n) lines.push({ text: n, lineNo: i + 1 });
    });

    for (let i = 0; i + WINDOW <= lines.length; i += WINDOW) {
      const block = lines.slice(i, i + WINDOW);
      const joined = block.map((b) => b.text).join('\n');
      if (joined.length < MIN_BLOCK_LENGTH) continue;
      const hash = crypto.createHash('md5').update(joined).digest('hex');
      if (!buckets.has(hash)) buckets.set(hash, []);
      buckets.get(hash).push({ file: file.path, startLine: block[0].lineNo, endLine: block[block.length - 1].lineNo, sample: block[0].text });
    }
  }

  const groups = [];
  for (const occurrences of buckets.values()) {
    if (occurrences.length < 2) continue;
    const distinctFiles = new Set(occurrences.map((o) => o.file));
    // A same-file "duplicate" only counts if it's a genuinely separate block, not just adjacent windows.
    if (distinctFiles.size === 1 && occurrences.length < 2) continue;
    groups.push({
      occurrences,
      fileCount: distinctFiles.size,
      sample: occurrences[0].sample,
      lineCount: WINDOW,
    });
  }

  groups.sort((a, b) => (b.fileCount - a.fileCount) || (b.occurrences.length - a.occurrences.length));

  return {
    filesScanned: files.length,
    truncated: files.length >= MAX_FILES,
    groups: groups.slice(0, MAX_GROUPS),
    totalGroups: groups.length,
  };
}

module.exports = { findDuplicateBlocks };
