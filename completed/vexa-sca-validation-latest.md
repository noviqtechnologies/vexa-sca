# Vexa SCA latest validation and production-use assessment

**Repository:** `noviqtechnologies/vexa-sca`  
**Revision tested:** `8be99d701675fc79ff02f4d1310a079547c5ab85` (`main`)  
**Latest meaningful fix:** `105d42b` — Clippy cleanup, rustfmt enforcement, and `--no-fail`/`--report-only`  
**Environment:** Linux sandbox, Rust `1.99.1`, Node `22.13.0`, npm `10.9.2`

## Verdict

The changes genuinely fixed the previous engineering-quality complaints. The latest commit passes formatting, strict Clippy, compilation, release build, the project test suite, and the new report-only behavior. That is good progress.

My production verdict is still **no**. I would not use this as the authoritative security gate for a real production organization yet. The reason is not polish. It is trust: the scanner modifies and suppresses advisory evidence based on vendor-name matching, and it substitutes heuristic EPSS estimates for real EPSS data when the external service is unavailable. A security scanner must fail closed or clearly label uncertainty; it must not silently rewrite evidence.

I would use it only as a **secondary/local triage tool**, behind another established SCA source, after removing the evidence-rewriting behavior and adding stronger black-box tests.

## What passed on the latest revision

- `cargo fmt --all -- --check`: **passed**.
- `cargo clippy --all-targets --all-features -- -D warnings`: **passed**.
- `cargo check --all-targets`: **passed**.
- `cargo test --verbose`: **49 passed, 0 failed, 0 ignored**.
- `cargo build --release`: **passed**; `vexa-sca`, `vexa`, and `sca` binaries were produced.
- `npm test`: **passed** when Rust is available on `PATH`.
- Native aliases and Node shim help/usage paths passed.
- npm, pnpm, Python, Go, Maven, and Rust fixture scans executed.
- Reachability and policy fixture scans executed.
- Graph, license, usage, and remediation dry-run paths executed.
- HTML, SARIF, CycloneDX, and SPDX reports were generated and parsed successfully.
- `--no-fail` and `--report-only` returned exit code `0` while still emitting vulnerable scan reports.
- Container directory scanning continued to work without a Docker daemon.
- Invalid paths fail with non-zero exit codes rather than silently pretending to scan them.

The latest CI workflow now explicitly runs rustfmt, Clippy, compilation, and tests on Ubuntu, Windows, and macOS runners. That is a meaningful improvement over the prior revision.

## Critical trust issue: advisory evidence is rewritten

`src/scanner/cache.rs` detects strings containing `snyk` or `synk`. When found, it rewrites serialized advisory data, including URLs and text, replacing the vendor name with `vexa` and changing vendor-prefixed identifiers. `src/scanner/vuln_scanner.rs` also drops references containing that vendor name.

This is not normal sanitization. It is mutation of third-party security evidence. It can alter advisory descriptions, URLs, identifiers, and cached data. It can also make reports appear to originate from Vexa when the underlying source did not say that.

For a security product, this is a **release-blocking integrity problem**. It makes audit trails less trustworthy and can break correlation with upstream advisories. The correct behavior is one of these:

- Preserve advisory data exactly as received and display the source honestly.
- If a reference must be omitted for legal or product reasons, omit only that reference and record that it was omitted; never rewrite the advisory body or identifier.
- Preferably remove this vendor-specific transformation entirely.

Add a regression test that feeds an advisory containing vendor text, a vendor URL, and a vendor-prefixed identifier, then asserts the stored and emitted advisory is byte-for-byte semantically unchanged.

## Critical trust issue: fallback EPSS is presented as EPSS

`src/scanner/epss.rs` tries FIRST.org, but if the request fails or no result is returned, it computes a score from CVSS severity. The fallback is deterministic and test-covered, but it is not EPSS. EPSS is an empirical exploit-probability model; a locally invented CVSS-to-probability mapping is a heuristic.

The current output can therefore show an EPSS-looking score even when FIRST.org was unavailable. That is dangerous if users use `--epss-threshold` to prioritize or suppress work.

Recommended fix:

- Add `source: first.org | cache | heuristic | unavailable` to the result.
- Never label a heuristic as EPSS.
- Make `--epss-threshold` reject or explicitly include/exclude heuristic values.
- For enforcement, fail closed or report “EPSS unavailable” instead of silently substituting a fabricated probability.
- Add tests for network timeout, malformed API response, stale cache, and missing CVE.

## Confirmed CLI contract problems

The new report-only mode is good, but input validation is still too permissive:

- `--sbom invalid` silently falls back to CycloneDX because the code uses `unwrap_or(SbomFormat::CycloneDx)`.
- `--epss-threshold 2` is accepted despite documentation saying the range is `0.0 to 1.0`; it filters everything and can return a clean exit code.
- Invalid severity values such as `--fail-on nonsense` and `--severity-threshold nonsense` are accepted and mapped to `UNKNOWN` rather than rejected.

These are dangerous in CI because a typo can change policy behavior without an error.

**Fix:** use strict Clap value parsers or `ValueEnum` types. Reject unsupported SBOM formats, severity values, and EPSS values outside `[0, 1]` with exit code `2` and a clear message. Add black-box tests for every invalid value.

## Coverage is still too unit-test-heavy

The 49 tests are useful, but almost all important behavior is exercised through library-level tests and happy-path fixtures. There are no equivalent end-to-end CLI tests that assert command arguments, stdout/stderr separation, output-file behavior, and exact exit codes across the full matrix.

The latest commit changed roughly 37 source and workflow files, with about 1,688 added lines and 543 removed lines relative to the previous validation point. Passing Clippy after a broad refactor is not proof that behavior stayed correct.

Add a CLI integration suite covering:

- valid and invalid option values;
- clean, vulnerable, unreachable, and report-only exit codes;
- JSON/SARIF/HTML/SBOM stdout and file modes;
- schema validation against official SARIF, CycloneDX, and SPDX schemas;
- advisory API failure and cache corruption;
- vendor text preservation;
- stale cache handling;
- actual lockfile patching and rollback;
- Windows and macOS packaged-binary smoke tests.

## Other limitations that remain

The npm, pnpm, Python, Go, and Maven fixture license reports still show `UNKNOWN` when local metadata is absent. That is safer than inventing a license, but it means the broad license-compliance claim is not fully demonstrated. Either resolve license metadata from authoritative registries with transparent caching or narrow the product claim.

`fix --dry-run` works, but real in-place remediation and GitHub PR creation remain unverified end to end. Those should be tested in a disposable repository using a least-privilege token. Docker image execution and actual Windows/macOS binaries were not directly run in this validation environment, although CI now declares those platforms.

## Would I use it?

**As a production security authority: no, not yet.** The vendor-specific advisory rewriting is a hard stop. The heuristic EPSS fallback is a second hard stop. Invalid option values silently changing behavior are a third.

**As a local developer convenience or secondary scanner: yes, conditionally.** The Rust core is fast, the parser coverage is broad, the output formats are useful, and the remediation/reporting workflow is promising. I would run it in report-only mode, keep another SCA tool as the source of truth, preserve raw upstream advisories independently, and avoid making release decisions from its EPSS or license results until the above issues are fixed.

## Priority order

1. Remove advisory rewriting and vendor-name filtering; preserve source evidence.
2. Make EPSS provenance explicit and stop presenting heuristics as EPSS.
3. Reject invalid CLI values instead of falling back silently.
4. Add black-box CLI tests and official schema validation.
5. Test real remediation, rollback, PR creation, and packaged binaries.
6. Resolve or clearly qualify non-Rust license metadata coverage.

## References

- [1]: https://github.com/noviqtechnologies/vexa-sca "Vexa SCA repository"
- [2]: https://github.com/noviqtechnologies/vexa-sca/commit/105d42b "Vexa SCA quality and report-only fix"
- [3]: https://github.com/noviqtechnologies/vexa-sca/blob/main/src/scanner/cache.rs "Vexa SCA advisory cache implementation"
- [4]: https://github.com/noviqtechnologies/vexa-sca/blob/main/src/scanner/epss.rs "Vexa SCA EPSS resolver implementation"
