# Security Policy & Vulnerability Disclosure

Vexa SCA (`vexa-sca`) is dedicated to upholding the highest standards of software supply chain security, integrity, and transparency. This document details our security practices, supported releases, vulnerability reporting procedures, and response SLAs.

---

## Supported Versions

Only the latest Generally Available (GA) release receives critical security updates and advisory patches:

| Version | Status | Security Support |
| :--- | :--- | :--- |
| **`1.2.x` (GA)** | **Current Stable GA** | :white_check_mark: Fully Supported |
| `< 1.2.0` | Superseded Candidates / Beta | :x: End of Life (Upgrade to v1.2.0+) |

---

## Reporting a Vulnerability

We deeply appreciate the efforts of the security research community and practicing DevSecOps engineers in identifying vulnerabilities responsibly.

### How to Report

If you discover a security vulnerability within Vexa SCA, **please do not disclose it publicly via GitHub issues or discussions**.

Instead, please submit your findings through one of our private channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Navigate to the [Security Tab](https://github.com/noviqtechnologies/vexa-sca/security) of the repository and click **"Report a vulnerability"** to open a confidential advisory draft.
2. **Security Response Email:**
   Send an encrypted report to **`security@noviq.tech`** (or your designated security contact).

### What to Include

To facilitate rapid triage and validation, please include:
- A clear description of the vulnerability and its potential impact.
- Exact version(s) of `vexa-sca` affected and target platform (Linux, macOS, Windows).
- A minimal, reproducible Proof-of-Concept (PoC), such as a crafted manifest, lockfile, or CLI invocation.
- Remediation suggestions or proof-of-fix patches if available.

---

## Response SLAs & Handling Timeline

Our security team adheres to coordinated disclosure timelines:

| Stage | SLA Target | Action |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **Within 24 hours** | Confirmation of report receipt and initial assessment assignment. |
| **Triage & Validation** | **Within 72 hours** | Reproduction of the PoC, severity determination (CVSS v3.1), and scope analysis. |
| **Fix & Advisory Preparation** | **Within 7 calendar days** | Remediation patch authored, automated regression suite executed, and private advisory drafted. |
| **Release & Disclosure** | **Coordinated (typically 14–30 days)** | Release of patched binary/package, CVE publication, and public advisory release. |

---

## Software Supply Chain & Artifact Integrity

Vexa SCA enforces rigorous supply chain defenses across its build and release pipeline:

1. **Zero External C / OpenSSL Dependencies:** Built purely in Rust using memory-safe `rustls-tls` and `miniz_oxide`. The scanner does not link against libssl, libcrypto, or unmanaged C libraries.
2. **Cryptographic Build Attestations:** Official GitHub Releases are signed using GitHub Artifact Attestations (`actions/attest-build-provenance@v2`). You can verify release artifact provenance with the GitHub CLI:
   ```bash
   gh attestation verify vexa-sca-linux-x86_64.tar.gz --owner noviqtechnologies
   ```
3. **Immutable Workflow References:** All GitHub Actions workflows are strictly pinned to immutable full commit SHAs, preventing tag-mutation supply chain injection.
4. **Reproducible Locked Builds:** All release builds enforce `cargo build --locked --release`, ensuring dependencies match `Cargo.lock` cryptographic digests exactly.

---

## Data Handling, Privacy & Network Boundaries

- **Advisory Enrichment:** Scans transmit only package coordinates (`ecosystem`, `name`, `version`) over TLS to the public OSV API (`api.osv.dev`).
- **Zero First-Party Code Egress:** First-party source code, filenames, git commit histories, developer credentials, and environment variables are **never transmitted** over the network.
- **Local Disk Cache:** Lookups are cached locally under `.sca-cache/` using SHA-256 keys to minimize external network calls.
