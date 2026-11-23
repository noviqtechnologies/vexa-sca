"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const installSh = fs.readFileSync(path.join(root, "install.sh"), "utf8");
const installPs1 = fs.readFileSync(path.join(root, "install.ps1"), "utf8");
const slsaYml = fs.readFileSync(
  path.join(root, ".github", "workflows", "release-slsa-cosign.yml"),
  "utf8"
);

// 1. Fail-closed checksum & rollback protection in install.sh
assert.ok(installSh.includes("failing closed"), "install.sh must fail closed on missing checksum/signature");
assert.ok(installSh.includes("@refs/tags/${VERSION_TAG}"), "install.sh must pin exact release tag identity");
assert.ok(installSh.includes("Rollback rejected"), "install.sh must include rollback protection");
assert.strictEqual(installSh.includes("sort -V"), false, "install.sh must use POSIX awk semver check, not GNU-only sort -V");

// 2. Fail-closed checksum, signature, and no -SkipHashCheck in install.ps1
assert.strictEqual(installPs1.includes("SkipHashCheck"), false, "install.ps1 must not expose -SkipHashCheck bypass");
assert.ok(installPs1.includes("@refs/tags/$VersionTag"), "install.ps1 must pin exact release tag identity");
assert.ok(installPs1.includes("cosign") && installPs1.includes("attestation verify"), "install.ps1 must enforce signature/provenance verification");
assert.ok(installPs1.includes("Rollback rejected"), "install.ps1 must include rollback protection");

// 3. Fail-closed Cosign signing in release-slsa-cosign.yml
assert.strictEqual(slsaYml.includes("Skipping local dummy blob"), false, "release-slsa-cosign.yml must not fail open on cosign error");
assert.ok(slsaYml.includes("VEXA_RELEASE_SIGNING_KEY_PEM"), "release-slsa-cosign.yml must support zero-dependency Ed25519 release signing");

console.log("vexa-sca installer-security.test.js: all assertions passed");
