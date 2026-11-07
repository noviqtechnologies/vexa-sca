#!/usr/bin/env node

/**
 * Vexa SCA CLI (`npx vexa-sca scan`) — Cross-OS Native Rust Launcher
 * Supports Windows (win32 x64/arm64), macOS (darwin x64/arm64), and Linux (linux x64/arm64).
 * Brand: Vexa | Product: Vexa SCA & Basics (vexa-sca)
 */
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const isWin = process.platform === 'win32';
const binExt = isWin ? '.exe' : '';
const rootDir = path.join(__dirname, '..');

// Platform-specific asset tag for prebuilt binaries
function resolvePlatformTag() {
  const plat = process.platform;
  const arch = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
  if (plat === 'win32') return `windows-${arch}`;
  if (plat === 'darwin') return `macos-${arch}`;
  return `linux-${arch}`;
}

const candidateBins = ['vexa-sca', 'vexa', 'sca'];
const userArgs = process.argv.slice(2);
// Support both `vexa-sca scan [path]` and Socket-compatible `vexa-sca scan create [path]`
const normalizedArgs =
  userArgs[0] === 'scan' && userArgs[1] === 'create'
    ? ['scan', ...userArgs.slice(2)]
    : userArgs;
const effectiveArgs = normalizedArgs.length === 0 ? ['scan'] : normalizedArgs;

let cmd = null;
let cmdArgs = effectiveArgs;

// 0. Explicit override via VEXA_CLI_PATH
if (process.env.VEXA_CLI_PATH && fs.existsSync(process.env.VEXA_CLI_PATH)) {
  cmd = process.env.VEXA_CLI_PATH;
}

// 1. Check packaged platform binary directory (bin/native/<platform>/vexa-sca[.exe])
if (!cmd) {
  const platformTag = resolvePlatformTag();
  const packagedBin = path.join(__dirname, 'native', platformTag, `vexa-sca${binExt}`);
  if (fs.existsSync(packagedBin)) {
    cmd = packagedBin;
  }
}

// 2. Check workspace target/release and target/debug directories (pick the most recently built binary)
if (!cmd) {
  let newestBin = null;
  let newestMtime = -1;
  for (const profile of ['release', 'debug']) {
    for (const binName of candidateBins) {
      const candidate = path.join(rootDir, 'target', profile, `${binName}${binExt}`);
      if (fs.existsSync(candidate)) {
        try {
          const stat = fs.statSync(candidate);
          if (stat.mtimeMs > newestMtime) {
            newestMtime = stat.mtimeMs;
            newestBin = candidate;
          }
        } catch (_) {
          if (!newestBin) newestBin = candidate;
        }
      }
    }
  }
  if (newestBin) {
    cmd = newestBin;
  }
}

// 4. Check ~/.vexa/bin/vexa-sca[.exe]
if (!cmd) {
  const homeBin = path.join(os.homedir(), '.vexa', 'bin', `vexa-sca${binExt}`);
  if (fs.existsSync(homeBin)) {
    cmd = homeBin;
  }
}

// 5. Fallback to cargo run with primary binary vexa-sca
if (!cmd) {
  cmd = 'cargo';
  cmdArgs = [
    'run',
    '--manifest-path',
    path.join(rootDir, 'Cargo.toml'),
    '--bin',
    'vexa-sca',
    '--',
    ...effectiveArgs,
  ];
}

const result = spawnSync(cmd, cmdArgs, {
  stdio: 'inherit',
  env: process.env,
  shell: isWin && cmd === 'cargo',
});

process.exit(result.status ?? (result.error ? 1 : 0));
