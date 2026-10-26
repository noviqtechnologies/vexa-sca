# Vexa SCA Container Deployment: Pre-GA Notice

## Status

Container distribution and container/OS package scanning are **not approved for production use by this guide**. The previous instructions that used `ghcr.io/noviqtechnologies/vexa-sca:latest`, described a production-hardened image, or presented OS-package scans as complete are withdrawn. Do not copy those commands into CI/CD.

The source tree and release workflow must be reviewed for the exact image build, target binary, platform coverage, provenance, and scan semantics. A mutable tag, Dockerfile label, or successful `docker pull` does not establish that an image corresponds to reviewed source or was built/tested reproducibly. Current release checksums alone are not a signed provenance chain.

## If you are evaluating container support

Before running any image, require and record all of the following:

1. An immutable image digest, not `:latest` or another moving tag.
2. A verified link from that digest to a reviewed full source commit.
3. Cryptographically verifiable signing/attestation and build provenance.
4. Release tests for the exact image and supported host architectures.
5. A non-privileged runtime, read-only scanner filesystem where practical, minimal mounts, and no unnecessary credentials.
6. Independent fixture comparisons for each supported Linux distribution and package database, including distroless/scratch behavior and image archive edge cases.
7. A test showing incomplete/unsupported image data cannot be reported as a clean complete scan.

If any condition is unmet, do not deploy the published image. If you choose to evaluate from source, build from a reviewed full commit in your own controlled pipeline; review the Dockerfile, base-image digests, dependencies, user/permissions, build output, and resulting binary before execution. This guide intentionally provides no copy-paste build recipe because the project's container release/provenance path has not been independently validated.

## Safer evaluation posture

Prefer a controlled runner with a reviewed source build and non-blocking report-only scans. Limit filesystem mounts to the target repository and report directory. Do not mount host Docker sockets, pass broad access tokens, run untrusted package lifecycle scripts, or automatically apply fixes. Package-coordinate requests to OSV disclose dependency names and versions; check egress and privacy policy.

The `.sca-cache/` directory can reduce repeat network calls but is not a signed or complete offline advisory database. A containerized scanner does not make OSV data available offline and does not establish complete vulnerability coverage.

## Reassessment criteria

Revisit this guide only after immutable, verifiable images exist; a release-matched cross-OS test matrix passes; image/OS package parsers have distribution-specific conformance tests; and failure injection demonstrates that malformed, unsupported, or unreadable image content is reported as incomplete. Until then, container and OS-package findings are experimental and must not be the sole security control.
