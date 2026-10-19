# Vexa SCA Git Hooks Setup Guide

## Executive Summary
This guide explains how to configure automated client-side Git hooks using Vexa SCA to block vulnerable code and non-compliant open source licenses before commits or pushes are finalized. Implementing shift-left Git hooks prevents security regressions locally on developer machines, reducing CI/CD pipeline breakage and eliminating remediation turnaround delays.

---

## Prerequisites
Before installing Git hooks, ensure your development workstation meets these criteria:

### Software Requirements
- **Git**: Version `2.20.0+` installed on Linux, macOS, or Windows.
- **Vexa SCA CLI**: Installed and accessible on your system `PATH` (see [CLI Usage Guide](cli-usage.md) for installation options).
- **Permissions**: Write access to the local `.git/hooks/` directory or root workspace configuration files.

### OS-Specific Tooling
| Operating System | Recommended Hook Mechanism | Shell Requirements |
| :--- | :--- | :--- |
| **Linux** (All distros) | Native `.git/hooks/pre-commit` or Husky | Standard POSIX `/bin/sh` or `/bin/bash` |
| **macOS** | Native `.git/hooks/pre-commit` or Husky | Zsh or Bash (`/bin/sh`) |
| **Windows** | Native Bash via Git Bash, PowerShell hook, or Husky | Git Bash (installed with Git for Windows) or PowerShell 5.1/7+ |

---

## Installation / Initialization

### Option 1: Native Raw Git Hook (`.git/hooks/`)
Standard Git hooks are located in `.git/hooks/` inside any cloned Git repository. This method requires zero external dependencies or framework installations.

#### Linux & macOS (Bash)
```bash
# Navigate to your project root
cd [project-root]

# Ensure the hooks directory exists
mkdir -p .git/hooks

# Create the pre-commit hook file
touch .git/hooks/pre-commit

# CRITICAL: Grant executable permissions (POSIX systems require +x)
chmod +x .git/hooks/pre-commit
```

#### Windows (PowerShell)
```powershell
Set-Location [project-root]
New-Item -ItemType File -Force -Path ".git\hooks\pre-commit"
```

---

### Option 2: Framework Integration via Husky (Node.js Ecosystem)
Husky automatically tracks hooks in version control under `.husky/`, ensuring every team member automatically inherits the security hooks upon running `npm install`.

```bash
# Initialize husky in project
npx husky init

# Add Vexa SCA pre-commit hook command
echo "vexa-sca scan --fail-on high --fail-on-reachable" > .husky/pre-commit
```

---

### Option 3: Python `pre-commit` Framework
If your repository utilizes Python's `pre-commit` tool (`pip install pre-commit`):

```bash
pre-commit install
```

---

## Step-by-Step Implementation Guide

### 1. Standalone Native Pre-Commit Hook

Place the following script into `.git/hooks/pre-commit`:

```bash
#!/bin/sh
# ==============================================================================
# Vexa SCA Pre-Commit Security Hook
# Blocks commits if High/Critical reachable vulnerabilities or copyleft licenses
# are introduced into the dependency tree.
# ==============================================================================

# Ensure standard binary search paths are available in non-interactive shells
export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"

echo "🔍 [Vexa SCA] Auditing dependency security and reachability..."

# Check if vexa-sca is available
if ! command -v vexa-sca >/dev/null 2>&1; then
    echo "⚠️  [Vexa SCA] 'vexa-sca' binary not found on PATH."
    echo "   Please install via 'cargo install --git https://github.com/noviqtechnologies/vexa-sca.git'"
    echo "   or bypass with 'git commit --no-verify' in an emergency."
    exit 1
fi

# Execute scan with quality gates
vexa-sca scan . \
    --fail-on high \
    --fail-on-reachable \
    --fail-on-licenses copyleft

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ [Vexa SCA] Commit rejected by Security Quality Gate!"
    echo "   Remediate vulnerabilities before committing:"
    echo "     1. Run 'vexa-sca fix' to automatically patch manifests and lockfiles."
    echo "     2. Or suppress accepted risks in '.vexa-sca' with an expiry date."
    echo ""
    exit 1
fi

echo "✔ [Vexa SCA] Pre-commit security check passed."
exit 0
```

> [!IMPORTANT]
> On Linux and macOS, always run `chmod +x .git/hooks/pre-commit` after saving. Without executable permissions, Git will ignore the hook file completely.

---

### 2. Multi-Tier Hook Strategy: Fast Pre-Commit vs Deep Pre-Push

To maintain developer velocity, many organizations split checks into two tiers:
1. **Pre-Commit Hook**: Lightweight, verifying only staged lockfiles or fast local dependency graphs.
2. **Pre-Push Hook**: Comprehensive deep scan, verifying AST reachability, container layers, and full CycloneDX SBOM integrity before code leaves the developer's computer.

#### Pre-Push Hook (`.git/hooks/pre-push`)

```bash
#!/bin/sh
# ==============================================================================
# Vexa SCA Pre-Push Hook
# Runs comprehensive reachability analysis and license verification before push
# ==============================================================================
export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"

echo "🚀 [Vexa SCA] Running pre-push comprehensive audit..."

vexa-sca scan . \
    --fail-on critical \
    --fail-on-reachable \
    --fail-on-licenses copyleft \
    --html-file .git/sca-push-report.html

if [ $? -ne 0 ]; then
    echo "❌ Push blocked! Review offline report at .git/sca-push-report.html"
    exit 1
fi

exit 0
```

Make it executable:
```bash
chmod +x .git/hooks/pre-push
```

---

### 3. Integration with Python `pre-commit` Framework

Add a local hook definition to `.pre-commit-config.yaml` in your repository root:

```yaml
repos:
  - repo: local
    hooks:
      - id: vexa-sca-audit
        name: Vexa SCA Security & Reachability Gate
        entry: vexa-sca scan . --fail-on high --fail-on-reachable --fail-on-licenses copyleft
        language: system
        files: (package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Cargo\.(toml|lock)|go\.(mod|sum)|pom\.xml)$
        pass_filenames: false
```

---

## Advanced Configuration & Edge Cases

### Incremental / Staged Manifest Filtering
If you only want the hook to fire when dependency files have actually been modified and staged:

```bash
#!/bin/sh
# Check if any dependency manifest or lockfile is staged in git
STAGED_DEPS=$(git diff --cached --name-only | grep -E '(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Cargo\.(toml|lock)|go\.(mod|sum)|pom\.xml)$')

if [ -z "$STAGED_DEPS" ]; then
    # No dependency changes staged; skip scan to keep commit instant
    exit 0
fi

echo "📦 Dependency manifest modification detected in git stage:"
echo "$STAGED_DEPS"
echo "🔍 Running Vexa SCA verification..."

vexa-sca scan . --fail-on high --fail-on-reachable
exit $?
```

### Policy-Driven Suppressions vs `--no-verify`
Developers frequently bypass Git hooks using `git commit --no-verify` when blocked by known, non-exploitable vulnerabilities. **This breaks security posture.**

Instead of bypassing the hook, instruct developers to document the accepted risk in `.vexa-sca`:

```yaml
version: v1.0.0
ignore:
  CVE-2023-12345:
    - reason: "False positive: vulnerable XML parser is never initialized"
      expires: 2026-12-31
```
Once added to `.vexa-sca`, `vexa-sca scan` automatically respects the active suppression and allows the commit to proceed cleanly.

### Handling Windows CRLF Line Endings
Git hooks executed by Git Bash on Windows will fail with `\r: command not found` if saved with Windows CRLF line endings.
- Ensure all `.git/hooks/*` files are saved with Unix LF line endings.
- Configure Git to prevent automatic conversion of hook files:
  ```bash
  git config core.autocrlf input
  ```

---

## Troubleshooting & FAQs

### 1. `permission denied: .git/hooks/pre-commit`
- **Cause**: The hook file was created without POSIX execution permissions (`+x`).
- **Resolution**:
  ```bash
  chmod +x .git/hooks/pre-commit
  ```

### 2. `'vexa-sca' is not recognized` on Windows Git Bash
- **Cause**: Git Bash on Windows executes in a MinGW environment where standard Windows user `PATH` additions (such as `%USERPROFILE%\.cargo\bin`) may not be sourced automatically.
- **Resolution**: Add the Cargo bin directory to your `~/.bashrc` or export it at the top of the hook script:
  ```bash
  export PATH="$PATH:$USERPROFILE/.cargo/bin:/c/Users/$USERNAME/.cargo/bin"
  ```

### 3. Hook execution adds noticeable latency to every local commit
- **Cause**: Running full scans on large repositories on every single commit slows developer iteration.
- **Resolution**:
  - Implement the **Incremental / Staged Manifest Filtering** script shown above so that scans only execute when dependency manifests or lockfiles are staged.
  - Move deep reachability and container scans to the `pre-push` hook instead of `pre-commit`.
