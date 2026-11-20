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

// 4. Check ~/.vexa/bin/vexa-sca[.exe] or LOCALAPPDATA\vexa\bin\vexa-sca.exe
if (!cmd) {
  const candidateDirs = [path.join(os.homedir(), '.vexa', 'bin'), path.join(os.homedir(), '.local', 'bin')];
  if (isWin && process.env.LOCALAPPDATA) {
    candidateDirs.unshift(path.join(process.env.LOCALAPPDATA, 'vexa', 'bin'));
  }
  for (const dir of candidateDirs) {
    const binPath = path.join(dir, `vexa-sca${binExt}`);
    if (fs.existsSync(binPath)) {
      cmd = binPath;
      break;
    }
  }
}

// 4.5. Auto-download prebuilt GitHub release binary with SHA-256 verification if Cargo.toml is not present (e.g. `npx @vexasec/sca`)
if (!cmd && !fs.existsSync(path.join(rootDir, 'Cargo.toml'))) {
  const crypto = require('crypto');
  const pkgVersion = require('../package.json').version || '1.4.1';
  const tag = `v${pkgVersion}`;
  const cacheDir = path.join(os.homedir(), '.vexa', 'bin', tag);
  const cachedBin = path.join(cacheDir, `vexa-sca${binExt}`);
  if (fs.existsSync(cachedBin)) {
    cmd = cachedBin;
  } else {
    try {
      fs.mkdirSync(cacheDir, { recursive: true });
      const baseUrl = `https://github.com/noviqtechnologies/vexa-sca/releases/download/${tag}`;
      const archiveName = isWin
        ? 'vexa-sca-windows-x86_64.zip'
        : `vexa-sca-${process.platform === 'darwin' ? 'darwin' : 'linux'}-${process.arch === 'arm64' ? 'arm64' : 'x86_64'}.tar.gz`;
      const tmpArchive = path.join(os.tmpdir(), `${archiveName}.${process.pid}`);
      const tmpSums = path.join(os.tmpdir(), `vexa-sca-sums-${process.pid}.txt`);
      const curlBin = isWin ? 'curl.exe' : 'curl';

      const dlRes = spawnSync(curlBin, ['-sSLf', '-o', tmpArchive, `${baseUrl}/${archiveName}`], { stdio: 'inherit' });
      if (dlRes.status === 0 && fs.existsSync(tmpArchive)) {
        // Verify SHA-256 against release checksums manifest if published
        let sumsRes = spawnSync(curlBin, ['-sSLf', '-o', tmpSums, `${baseUrl}/SHA256SUMS.txt`], { stdio: 'ignore' });
        if (sumsRes.status !== 0) {
          sumsRes = spawnSync(curlBin, ['-sSLf', '-o', tmpSums, `${baseUrl}/checksums.txt`], { stdio: 'ignore' });
        }
        if (sumsRes.status === 0 && fs.existsSync(tmpSums)) {
          const line = fs
            .readFileSync(tmpSums, 'utf8')
            .split(/\r?\n/)
            .find((l) => l.trim().endsWith(` ${archiveName}`) || l.trim().endsWith(`/${archiveName}`));
          if (line) {
            const expected = line.trim().split(/\s+/)[0].toLowerCase();
            const actual = crypto.createHash('sha256').update(fs.readFileSync(tmpArchive)).digest('hex').toLowerCase();
            if (actual !== expected) {
              fs.rmSync(tmpArchive, { force: true });
              fs.rmSync(tmpSums, { force: true });
              throw new Error(`SHA-256 mismatch for ${archiveName}: expected ${expected}, got ${actual}`);
            }
          }
          fs.rmSync(tmpSums, { force: true });
        }

        if (isWin) {
          spawnSync(
            'powershell',
            ['-NoProfile', '-Command', `Expand-Archive -Path '${tmpArchive}' -DestinationPath '${cacheDir}' -Force`],
            { stdio: 'inherit' }
          );
        } else {
          spawnSync('tar', ['-xzf', tmpArchive, '-C', cacheDir], { stdio: 'inherit' });
          if (fs.existsSync(cachedBin)) {
            fs.chmodSync(cachedBin, 0o755);
          }
        }
        fs.rmSync(tmpArchive, { force: true });
      }
      if (fs.existsSync(cachedBin)) {
        cmd = cachedBin;
      }
    } catch (err) {
      if (err && String(err.message || '').includes('SHA-256 mismatch')) {
        process.stderr.write(`[vexa-sca] SECURITY ERROR: ${err.message}\n`);
        process.exit(1);
      }
      // Proceed to cargo fallback
    }
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
