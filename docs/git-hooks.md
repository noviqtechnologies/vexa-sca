# Vexa SCA and Git Hooks

## Security position

Client-side Git hooks are **optional developer feedback**, not an enforcement boundary. They can be missing, disabled, or bypassed (for example with `--no-verify`), and their local environment/network/cache may differ from CI. Do not use them as the control that prevents vulnerable code from merging or shipping.

Vexa SCA is pre-GA. Keep evaluation report-only and use your existing CI SCA control for enforcement. Do not block a commit or push based on `--reachable-only`, `--fail-on-reachable`, or an assumption that unmatched packages are safe. Heuristic repository usage signals are not runtime reachability or exploitability proof.

## Optional local feedback

If your team elects to run a local scan from a hook, treat its output as a convenience report only. Keep the hook behavior explicit, easy to bypass for development continuity, and free of automatic dependency changes. Do not place tokens or credentials in hook scripts. Avoid scanning on every commit if it materially slows the developer workflow; a hook that only runs when dependency files change can reduce noise, but it does not establish coverage for source-only changes or indirect entry points.

Before distributing a hook, validate on each supported developer OS and shell. Test paths with spaces, Windows PowerShell/Git Bash behavior, line endings, nonzero exits, network outages, and missing scanner binaries. Document that a local result is advisory and that CI is authoritative.

## CI remains the enforcement point

Use a reviewed and pinned scanner source/artifact, preserve raw outputs, and test incomplete-scan behavior before enabling gates. Enforce severity policy over the complete unsuppressed finding set only after the scanner's completeness and exit-code behavior meet your organization's acceptance criteria. Keep established controls in place during a pilot.

See [CI/CD Integration](cicd-integration.md) for a non-blocking evaluation pattern and [CLI Usage](cli-usage.md) for the pre-GA exit-code and completeness caveats.
