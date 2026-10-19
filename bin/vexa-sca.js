#!/usr/bin/env node

/**
 * Vexa SCA CLI (Cross-Platform Native Rust Launcher)
 * Brand: Vexa | Product: Vexa SCA (vexa-sca)
 */
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const binExt = process.platform === 'win32' ? '.exe' : '';
const rootDir = path.join(__dirname, '..');

// Prioritize vexa-sca, with backwards-compatible aliases vexa and sca
const candidateBins = ['vexa-sca', 'vexa', 'sca'];

let cmd;
let cmdArgs;

// 1. Check release directory
for (const binName of candidateBins) {
  const candidate = path.join(rootDir, 'target', 'release', `${binName}${binExt}`);
  if (fs.existsSync(candidate)) {
    cmd = candidate;
    cmdArgs = process.argv.slice(2);
    break;
  }
}

// 2. Check debug directory
if (!cmd) {
  for (const binName of candidateBins) {
    const candidate = path.join(rootDir, 'target', 'debug', `${binName}${binExt}`);
    if (fs.existsSync(candidate)) {
      cmd = candidate;
      cmdArgs = process.argv.slice(2);
      break;
    }
  }
}

// 3. Fallback to cargo run with primary binary vexa-sca
if (!cmd) {
  cmd = 'cargo';
  cmdArgs = ['run', '--bin', 'vexa-sca', '--', ...process.argv.slice(2)];
}

const result = spawnSync(cmd, cmdArgs, {
  stdio: 'inherit',
  shell: process.platform === 'win32' && cmd === 'cargo',
});

process.exit(result.status ?? (result.error ? 1 : 0));
