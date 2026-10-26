# Vexa SCA Container Deployment Guide (GA v1.2.0)

## Overview & Support Scope

Vexa SCA provides container images and rootless containerization capabilities for running dependency security scans in containerized CI/CD runners (e.g., Kubernetes runners, AWS CodeBuild, GitLab runners).

### Support Tier Delineation
1. **Containerized Scanner Execution (GA / Tier 1):** Running `vexa-sca` inside a container to scan mounted project repositories (`package-lock.json`, `pnpm-lock.yaml`) is fully supported and recommended for isolated CI pipelines.
2. **Container OS Package Auditing (`vexa-sca container` - Experimental / Tier 2):** Auditing container filesystem layers (`apk` database, `dpkg` status, Dockerfile base image analysis) is available as an experimental preview.

### Best Practices for Containerized CI
- **Immutable Tags / Digest Pinning:** In production pipelines, pin container images by digest (`sha256:...`) or release version tag (`v1.2.0`), avoiding moving tags like `:latest`.
- **Rootless & Non-Privileged:** Run scanner containers with non-root user permissions (`--user 1000:1000`) and read-only host mounts (`-v "${PWD}:/workspace:ro"`).
- **Zero Host Socket Mounting:** Do not mount `/var/run/docker.sock` into scanner containers. Vexa SCA analyzes lockfiles and uncompressed tarballs directly without requiring access to Docker daemons.

If any condition is unmet, do not deploy the published image. If you choose to evaluate from source, build from a reviewed full commit in your own controlled pipeline; review the Dockerfile, base-image digests, dependencies, user/permissions, build output, and resulting binary before execution. This guide intentionally provides no copy-paste build recipe because the project's container release/provenance path has not been independently validated.

## Safer evaluation posture

Prefer a controlled runner with a reviewed source build and non-blocking report-only scans. Limit filesystem mounts to the target repository and report directory. Do not mount host Docker sockets, pass broad access tokens, run untrusted package lifecycle scripts, or automatically apply fixes. Package-coordinate requests to OSV disclose dependency names and versions; check egress and privacy policy.

The `.sca-cache/` directory can reduce repeat network calls but is not a signed or complete offline advisory database. A containerized scanner does not make OSV data available offline and does not establish complete vulnerability coverage.

## Reassessment criteria

Revisit this guide only after immutable, verifiable images exist; a release-matched cross-OS test matrix passes; image/OS package parsers have distribution-specific conformance tests; and failure injection demonstrates that malformed, unsupported, or unreadable image content is reported as incomplete. Until then, container and OS-package findings are experimental and must not be the sole security control.
