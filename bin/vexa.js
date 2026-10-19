#!/usr/bin/env node

/**
 * Vexa CLI (Native Rust Wrapper)
 */
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const binExt = process.platform === 'win32' ? '.exe' : '';
const rootDir = path.join(__dirname, '..');

const candidateBins = ['vexa', 'vexa-sca', 'sca'];

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

// 3. Fallback to cargo run
if (!cmd) {
  cmd = 'cargo';
  cmdArgs = ['run', '--bin', 'vexa', '--', ...process.argv.slice(2)];
}

const result = spawnSync(cmd, cmdArgs, {
  stdio: 'inherit',
  shell: process.platform === 'win32' && cmd === 'cargo',
});

process.exit(result.status ?? (result.error ? 1 : 0));
