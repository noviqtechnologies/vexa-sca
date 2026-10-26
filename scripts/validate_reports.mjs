import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import Ajv from 'ajv';
import AjvDraft04 from 'ajv-draft-04';
import addFormats from 'ajv-formats';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

function sha256File(filePath) {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function getBinPath() {
  const exeName = process.platform === 'win32' ? 'vexa-sca.exe' : 'vexa-sca';
  const releasePath = path.join(rootDir, 'target', 'release', exeName);
  if (fs.existsSync(releasePath)) return releasePath;
  const debugPath = path.join(rootDir, 'target', 'debug', exeName);
  if (fs.existsSync(debugPath)) return debugPath;
  throw new Error(`vexa-sca binary not found. Build it first with cargo build.`);
}

console.log('=== Vexa SCA Verifiable Report & Schema Validation Job ===\n');

const bin = getBinPath();
console.log(`Using binary: ${bin}`);

// Pinned Schema definitions
const schemas = {
  sarif: {
    name: 'SARIF 2.1.0',
    file: path.join(rootDir, 'tests', 'schemas', 'sarif-schema-2.1.0.json'),
    expectedSha256: 'c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e',
    sourceUrl: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    draft: 'draft-04'
  },
  cyclonedx: {
    name: 'CycloneDX 1.5',
    file: path.join(rootDir, 'tests', 'schemas', 'bom-1.5.schema.json'),
    expectedSha256: '2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480',
    sourceUrl: 'https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json',
    draft: 'draft-07'
  },
  spdx: {
    name: 'SPDX 2.3',
    file: path.join(rootDir, 'tests', 'schemas', 'spdx-schema.json'),
    expectedSha256: '239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b',
    sourceUrl: 'https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json',
    draft: 'draft-07'
  }
};

// Verify Schema Integrity
console.log('Verifying pinned schema digests...');
for (const [key, meta] of Object.entries(schemas)) {
  if (!fs.existsSync(meta.file)) {
    throw new Error(`Schema file missing: ${meta.file}`);
  }
  const hash = sha256File(meta.file);
  if (hash !== meta.expectedSha256) {
    throw new Error(`Schema digest mismatch for ${meta.name}! Expected ${meta.expectedSha256}, got ${hash}`);
  }
  console.log(`  ✔ [${meta.name}] ${hash.slice(0, 16)}... verified`);
}

// Initialize AJV validators
const ajvStandard = new Ajv({
  allErrors: true,
  strict: false,
  validateFormats: true
});
addFormats(ajvStandard);

const cdxSpdxFile = path.join(rootDir, 'tests', 'schemas', 'cyclonedx-spdx.schema.json');
if (fs.existsSync(cdxSpdxFile)) {
  const cdxSpdx = JSON.parse(fs.readFileSync(cdxSpdxFile, 'utf8'));
  ajvStandard.addSchema(cdxSpdx, 'spdx.schema.json');
}

const jsfFile = path.join(rootDir, 'tests', 'schemas', 'jsf-0.82.schema.json');
if (fs.existsSync(jsfFile)) {
  const jsf = JSON.parse(fs.readFileSync(jsfFile, 'utf8'));
  ajvStandard.addSchema(jsf, 'jsf-0.82.schema.json');
}

const ajvDraft04 = new AjvDraft04({
  allErrors: true,
  strict: false
});
addFormats(ajvDraft04);

const compiledValidators = {};
for (const [key, meta] of Object.entries(schemas)) {
  const schemaContent = JSON.parse(fs.readFileSync(meta.file, 'utf8'));
  if (meta.draft === 'draft-04') {
    compiledValidators[key] = ajvDraft04.compile(schemaContent);
  } else {
    compiledValidators[key] = ajvStandard.compile(schemaContent);
  }
}

// Setup temporary directory for generated artifacts
const tmpDir = path.join(rootDir, 'target', 'schema_validation_artifacts');
fs.mkdirSync(tmpDir, { recursive: true });

const testCases = [
  // 1. Complete Scan (npm-app fixture)
  {
    type: 'sarif',
    scenario: 'Complete Scan',
    fixture: 'test/fixtures/npm-app',
    args: ['scan', 'test/fixtures/npm-app', '--sarif-file', path.join(tmpDir, 'complete_npm_app.sarif'), '--no-fail'],
    outPath: path.join(tmpDir, 'complete_npm_app.sarif')
  },
  {
    type: 'cyclonedx',
    scenario: 'Complete Scan',
    fixture: 'test/fixtures/npm-app',
    args: ['scan', 'test/fixtures/npm-app', '--sbom', 'cyclonedx', '--sbom-file', path.join(tmpDir, 'complete_npm_app_cyclonedx.json'), '--no-fail'],
    outPath: path.join(tmpDir, 'complete_npm_app_cyclonedx.json')
  },
  {
    type: 'spdx',
    scenario: 'Complete Scan',
    fixture: 'test/fixtures/npm-app',
    args: ['scan', 'test/fixtures/npm-app', '--sbom', 'spdx', '--sbom-file', path.join(tmpDir, 'complete_npm_app_spdx.json'), '--no-fail'],
    outPath: path.join(tmpDir, 'complete_npm_app_spdx.json')
  },
  // 2. Incomplete Scan (reachability-app fixture with source-cap triggered)
  {
    type: 'sarif',
    scenario: 'Incomplete Scan (500/1 Source Cap)',
    fixture: 'test/fixtures/reachability-app',
    args: ['scan', 'test/fixtures/reachability-app', '--max-source-files', '1', '--sarif-file', path.join(tmpDir, 'incomplete_reachability.sarif'), '--no-fail'],
    outPath: path.join(tmpDir, 'incomplete_reachability.sarif'),
    expectIncomplete: true
  },
  {
    type: 'cyclonedx',
    scenario: 'Incomplete Scan (500/1 Source Cap)',
    fixture: 'test/fixtures/reachability-app',
    args: ['scan', 'test/fixtures/reachability-app', '--max-source-files', '1', '--sbom', 'cyclonedx', '--sbom-file', path.join(tmpDir, 'incomplete_reachability_cyclonedx.json'), '--no-fail'],
    outPath: path.join(tmpDir, 'incomplete_reachability_cyclonedx.json'),
    expectIncomplete: true
  },
  {
    type: 'spdx',
    scenario: 'Incomplete Scan (500/1 Source Cap)',
    fixture: 'test/fixtures/reachability-app',
    args: ['scan', 'test/fixtures/reachability-app', '--max-source-files', '1', '--sbom', 'spdx', '--sbom-file', path.join(tmpDir, 'incomplete_reachability_spdx.json'), '--no-fail'],
    outPath: path.join(tmpDir, 'incomplete_reachability_spdx.json'),
    expectIncomplete: true
  }
];

const results = [];
let allValid = true;

console.log('\nGenerating and validating test artifacts:');
for (const tc of testCases) {
  if (fs.existsSync(tc.outPath)) fs.unlinkSync(tc.outPath);
  
  let exitCode = 0;
  try {
    execFileSync(bin, tc.args, { cwd: rootDir, stdio: 'pipe' });
  } catch (err) {
    exitCode = err.status || -1;
  }

  if (tc.expectIncomplete) {
    if (exitCode !== 3) {
      console.warn(`  ⚠️ Expected exit code 3 for incomplete scan, got ${exitCode}`);
    }
  }

  if (!fs.existsSync(tc.outPath)) {
    throw new Error(`Report generation failed for ${tc.scenario} [${tc.type}], file not created: ${tc.outPath}`);
  }

  const reportRaw = fs.readFileSync(tc.outPath, 'utf8');
  const reportDigest = sha256File(tc.outPath);
  const parsed = JSON.parse(reportRaw);

  const validate = compiledValidators[tc.type];
  const isValid = validate(parsed);

  const errorMessages = isValid ? [] : validate.errors.map(e => `${e.instancePath || '/'}: ${e.message}`);
  if (!isValid) allValid = false;

  console.log(`  ${isValid ? '✔' : '✖'} [${schemas[tc.type].name}] ${tc.scenario}: ${isValid ? 'VALID' : 'INVALID'}`);
  if (!isValid) {
    console.error('    Errors:', errorMessages.slice(0, 5));
  }

  results.push({
    format: schemas[tc.type].name,
    scenario: tc.scenario,
    command: `vexa-sca ${tc.args.join(' ')}`,
    exitCode,
    reportFile: path.basename(tc.outPath),
    reportSha256: reportDigest,
    schemaSha256: schemas[tc.type].expectedSha256,
    validator: 'ajv@8.17.1 (ajv-formats@3.0.1, ajv-draft-04@1.0.0)',
    status: isValid ? 'VALID' : 'INVALID',
    errors: errorMessages
  });
}

// Generate Markdown Validation Record
const mdLines = [
  '# Report Schema Validation Evidence',
  '',
  `**Execution Timestamp:** ${new Date().toISOString()}`,
  `**Validator Engine:** \`ajv@8.17.1\` + \`ajv-formats@3.0.1\` + \`ajv-draft-04@1.0.0\``,
  '',
  '## Pinned Specifications & Schema Digests',
  '',
  '| Specification | Standard Version | Official Source | Pinned Schema SHA-256 |',
  '|---|---|---|---|',
  `| **SARIF** | 2.1.0 | [OASIS Spec](${schemas.sarif.sourceUrl}) | \`${schemas.sarif.expectedSha256}\` |`,
  `| **CycloneDX** | 1.5 JSON | [CycloneDX Specification](${schemas.cyclonedx.sourceUrl}) | \`${schemas.cyclonedx.expectedSha256}\` |`,
  `| **SPDX** | 2.3 JSON | [SPDX 2.3 Specification](${schemas.spdx.sourceUrl}) | \`${schemas.spdx.expectedSha256}\` |`,
  '',
  '## Validation Test Results',
  '',
  '| Report Type | Scenario | Exit Code | Generated File SHA-256 | Schema SHA-256 | Verdict |',
  '|---|---|---|---|---|---|'
];

for (const r of results) {
  mdLines.push(`| **${r.format}** | ${r.scenario} | \`${r.exitCode}\` | \`${r.reportSha256}\` | \`${r.schemaSha256.slice(0, 16)}...\` | **${r.status}** |`);
}

mdLines.push('');
mdLines.push('## Reproducibility Command');
mdLines.push('```bash');
mdLines.push('npm run validate:schemas');
mdLines.push('```');

const outMdPath = path.join(rootDir, 'REPORT_SCHEMA_VALIDATION.md');
fs.writeFileSync(outMdPath, mdLines.join('\n'), 'utf8');
console.log(`\nValidation evidence written to ${outMdPath}`);

if (!allValid) {
  console.error('\n✖ One or more reports failed schema validation!');
  process.exit(1);
} else {
  console.log('\n✔ All generated SARIF 2.1.0, CycloneDX 1.5, and SPDX 2.3 reports conform strictly to pinned official schemas with 0 errors.');
}
