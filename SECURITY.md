# Security Policy & Vulnerability Disclosure

Vexa SCA (`vexa-sca`) is dedicated to upholding the highest standards of software supply chain security, integrity, and transparency. This document details our security practices, supported releases, vulnerability reporting procedures, and response SLAs.

---

## Supported Versions

Only the latest Generally Available (GA) release receives critical security updates and advisory patches:

| Version | Status | Security Support |
| :--- | :--- | :--- |
| **`1.3.x` (GA)** | **Current Stable GA** | :white_check_mark: Fully Supported |
| `< 1.3.0` | Superseded Candidates / Beta | :x: End of Life (Upgrade to v1.3.x+) |

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

1. **Zero Unsafe Code Policy:** All source modules across `vexa-sca` are compiled with crate-root `#![forbid(unsafe_code)]`. Memory safety is enforced by the Rust compiler with zero `unsafe` blocks.
2. **Job Zero Parser Hardening:**
   - **Billion Laughs & ReDoS Protection:** Manifest and lockfile parsers reject recursive YAML entity expansion and cyclic references.
   - **Manifest Size Guard:** Manifests exceeding 15MB (`MAX_MANIFEST_SIZE_BYTES`) are rejected immediately before parsing.
   - **Recursion Depth Ceiling:** JSON/YAML parsing depth is strictly capped at 64 levels (`MAX_RECURSION_DEPTH`) to prevent stack overflow vulnerabilities.
   - **Command Injection Guard:** All package names in the firewall wrapper are validated against ecosystem-aware regexes before package manager invocation.
3. **Cryptographic Advisory Bundle Integrity:**
   - Offline vulnerability databases (`.vexadb`) are signed with asymmetric Ed25519 signatures and SHA-256 digests.
   - Bundles must pass `vexa-sca db verify` before ingestion, guaranteeing resistance to tampering or man-in-the-middle attacks.
4. **Keyed BLAKE3 Authentication:**
   - Personal Access Tokens (PATs) are hashed locally and in the cloud using keyed BLAKE3 (`TokenSecurity`), guaranteeing that plaintext tokens never exist at rest in any database.
5. **Zero External C / OpenSSL Dependencies:** Built purely in Rust using memory-safe `rustls-tls` and `miniz_oxide`. The scanner does not link against libssl, libcrypto, or unmanaged C libraries.
6. **Cryptographic Build Attestations:** Official GitHub Releases are signed using GitHub Artifact Attestations (`actions/attest-build-provenance@v2`). You can verify release artifact provenance with the GitHub CLI:
   ```bash
   gh attestation verify vexa-sca-linux-x86_64.tar.gz --owner vexasec
   ```
7. **Immutable Workflow References:** All GitHub Actions workflows are strictly pinned to immutable full commit SHAs, preventing tag-mutation supply chain injection.
8. **Reproducible Locked Builds:** All release builds enforce `cargo build --locked --release`, ensuring dependencies match `Cargo.lock` cryptographic digests exactly.

---

## Data Handling, Privacy & Zero-Code-Retention Protocol

- **Advisory Enrichment:** Scans transmit only package coordinates (`ecosystem`, `name`, `version`) over TLS to the public OSV API (`api.osv.dev`).
- **Zero First-Party Code Egress:** First-party source code, filenames, git commit histories, developer credentials, and environment variables are **never transmitted** over the network.
- **Zero-Code-Retention Scan Facts (`.vexa.facts.json`):** When syncing to Vexa SCA Cloud (`--upload`), only dependency tree topology and redacted call-site line numbers are transmitted. No AST source tokens or code contents leave your machine.
- **Local Disk Cache:** Lookups are cached locally under `.sca-cache/` using SHA-256 keys to minimize external network calls.
