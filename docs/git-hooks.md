# Vexa SCA Git Hooks Integration Guide (GA v1.2.0)

## Security Architecture & Best Practices

Client-side Git hooks provide **immediate developer feedback** directly on workstations before code reaches review. However, because developer hooks can be bypassed (e.g. `git commit --no-verify`) or configured differently across local machines, **automated CI/CD pipelines (`vexa-sca ci`) remain the authoritative enforcement gate**.

### Recommended Local Workflow
- **Pre-Push Triage:** Running `vexa-sca scan --fail-on high` in a pre-push hook catches newly introduced high/critical vulnerabilities before opening a pull request.
- **Fast Local Feedback:** Using the native compiled binary (`./target/release/vexa-sca`) or local npx shim executes scans in milliseconds.
- **Usage Signals in Development:** AST Repository Usage Signals highlight which packages have active import or script references, giving engineers actionable context to upgrade immediately.

## Example Native Pre-Push Hook (`.git/hooks/pre-push`)

```sh
#!/bin/sh
# .git/hooks/pre-push - Run Vexa SCA before pushing to remote
echo "🔍 Running Vexa SCA dependency security check..."

# Run scan using local compiled binary or npx wrapper:
if command -v vexa-sca >/dev/null 2>&1; then
    vexa-sca scan --fail-on high
else
    npx vexa-sca scan --fail-on high
fi

STATUS=$?
if [ $STATUS -eq 1 ]; then
    echo "❌ Push blocked: High or Critical security vulnerabilities detected in dependencies."
    echo "💡 Run 'vexa-sca scan --html-file report.html' to inspect findings or 'vexa-sca fix' to propose updates."
    exit 1
elif [ $STATUS -eq 2 ] || [ $STATUS -eq 3 ]; then
    echo "⚠️ Scan incomplete or configuration error (code $STATUS)."
    exit $STATUS
fi

echo "✔ Vexa SCA quality gate passed."
exit 0
```

See [CI/CD Integration](cicd-integration.md) for automated pipeline enforcement and [CLI Usage](cli-usage.md) for full flag references.
