#!/usr/bin/env node
"use strict";

function validateInputs(env) {
  const version = (env.INPUT_VERSION || "latest").trim();
  const validVersion =
    version === "latest" ||
    version === "source" ||
    /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version);
  if (!validVersion) {
    throw new Error(
      `Invalid 'version' input: '${version}'. Expected 'latest', 'source', or a semver tag like 'v1.7.0'.`
    );
  }

  const failOn = (env.INPUT_FAIL_ON || "").trim().toLowerCase();
  const allowedFailOn = new Set([
    "",
    "low",
    "medium",
    "high",
    "critical",
    "reachable",
    "reachable-critical",
  ]);
  if (!allowedFailOn.has(failOn)) {
    throw new Error(
      `Invalid 'fail-on' input: '${failOn}'. Allowed: low, medium, high, critical, reachable, reachable-critical, or empty.`
    );
  }

  const failOnLicenses = (env.INPUT_FAIL_ON_LICENSES || "").trim().toLowerCase();
  const allowedLicenses = new Set(["", "strong-copyleft", "weak-copyleft", "unknown"]);
  if (!allowedLicenses.has(failOnLicenses)) {
    throw new Error(
      `Invalid 'fail-on-licenses' input: '${failOnLicenses}'. Allowed: strong-copyleft, weak-copyleft, unknown, or empty.`
    );
  }

  const boolKeys = [
    "INPUT_REACHABLE_ONLY",
    "INPUT_FAIL_ON_REACHABLE",
    "INPUT_SAST",
    "INPUT_SECRETS",
    "INPUT_UPLOAD_SARIF",
    "INPUT_UPLOAD_FACTS",
    "INPUT_COMMENT_PR",
  ];
  for (const key of boolKeys) {
    const val = (env[key] || "").trim().toLowerCase();
    if (val !== "" && val !== "true" && val !== "false") {
      throw new Error(`Invalid boolean input ${key}='${val}'. Expected 'true' or 'false'.`);
    }
  }
}

if (require.main === module) {
  try {
    validateInputs(process.env);
  } catch (err) {
    process.stderr.write(`[vexa-sca-action] ${err.message}\n`);
    process.exit(1);
  }
}

module.exports = { validateInputs };
