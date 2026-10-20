# Vexa SCA Container Deployment Guide

## Executive Summary
This guide outlines the deployment and execution of Vexa SCA within containerized infrastructures. Container deployment ensures deterministic, isolated vulnerability scanning across developer workstations, automated Kubernetes jobs, and CI/CD runners without requiring local Rust or Node.js toolchains. Additionally, this guide details how to scan container root filesystems, Alpine/Debian package databases, and Docker images for operating system vulnerabilities.

---

## Prerequisites
Ensure the host platform meets the following container runtime specifications:

### Software & Hardware Specifications
- **Container Engine**: Docker Engine `20.10.0+` or Podman `4.0.0+`.
- **Docker Compose**: Version `v2.20.0+` (optional, for batch or service-based scans).
- **Operating Systems**:
  - **Linux**: Kernel 5.4+ (x86_64, aarch64).
  - **macOS**: Docker Desktop on Apple Silicon (M1/M2/M3/M4) or Intel.
  - **Windows**: Windows 10/11 64-bit with Docker Desktop configured with the WSL2 backend.

---

## Installation / Initialization

### Option 1: Pull Pre-Built Image from GitHub Container Registry (GHCR)
The fastest mechanism to run Vexa SCA in a containerized environment:

#### Linux & macOS
```bash
docker pull ghcr.io/noviqtechnologies/vexa-sca:latest
docker run --rm ghcr.io/noviqtechnologies/vexa-sca:latest --version
```

#### Windows (PowerShell)
```powershell
docker pull ghcr.io/noviqtechnologies/vexa-sca:latest
docker run --rm ghcr.io/noviqtechnologies/vexa-sca:latest --version
```

---

### Option 2: Build Native Multi-Stage Image from Source
If building in air-gapped environments or customizing base security policies, build locally:

#### Linux & macOS (Bash)
```bash
git clone https://github.com/noviqtechnologies/vexa-sca.git
cd vexa-sca
docker build -t vexa-sca:local .
```

#### Windows (PowerShell)
```powershell
git clone https://github.com/noviqtechnologies/vexa-sca.git
Set-Location vexa-sca
docker build -t vexa-sca:local .
```

---

## Step-by-Step Implementation Guide

### 1. Production-Optimized Multi-Stage `Dockerfile`
Vexa SCA utilizes a multi-stage Docker build that isolates compiler toolchains from the final runtime image. This produces a lightweight, hardened production container (~65 MB) free of development dependencies.

Below is the production `Dockerfile`:

```dockerfile
# ==========================================
# Stage 1: Build Native Rust Binaries
# ==========================================
FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# Copy dependency manifests first for optimal layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source files to cache dependency compilation
RUN mkdir -p src/bin && \
    echo "pub fn lib() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/vexa_sca.rs && \
    echo "fn main() {}" > src/bin/sca.rs && \
    cargo build --release && \
    rm -rf src

# Copy real source code
COPY src ./src

# Touch source files to force cargo to rebuild binaries
RUN touch src/lib.rs src/main.rs src/bin/vexa_sca.rs src/bin/sca.rs && \
    cargo build --release

# ==========================================
# Stage 2: Hardened Minimal Runtime Image
# ==========================================
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Vexa SCA" \
      org.opencontainers.image.description="Vexa SCA - Software Composition Analysis & Security Engine" \
      org.opencontainers.image.source="https://github.com/noviqtechnologies/vexa-sca" \
      org.opencontainers.image.licenses="Apache-2.0"

# Install baseline CA certificates and git for patch generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged security user
RUN groupadd -g 10001 vexa && \
    useradd -u 10001 -g vexa -m -s /bin/bash vexa

# Copy compiled binaries from builder stage
COPY --from=builder /app/target/release/vexa-sca /usr/local/bin/vexa-sca
COPY --from=builder /app/target/release/vexa /usr/local/bin/vexa
COPY --from=builder /app/target/release/sca /usr/local/bin/sca

WORKDIR /workspace
USER vexa:vexa

ENTRYPOINT ["vexa-sca"]
CMD ["--help"]
```

---

### 2. Scanning Local Host Projects via `docker run`

Mount your project directory to `/workspace` inside the container:

#### Linux & macOS (Bash)
```bash
# Basic scan
docker run --rm \
  -v "${PWD}:/workspace" \
  -u $(id -u):$(id -g) \
  ghcr.io/noviqtechnologies/vexa-sca:latest scan .

# Scan with HTML and SARIF report generation
docker run --rm \
  -v "${PWD}:/workspace" \
  -u $(id -u):$(id -g) \
  ghcr.io/noviqtechnologies/vexa-sca:latest scan . \
    --html-file sca-report.html \
    --sarif-file results.sarif \
    --fail-on high
```

#### Windows (PowerShell)
```powershell
# Basic scan
docker run --rm `
  -v "${PWD}:/workspace" `
  ghcr.io/noviqtechnologies/vexa-sca:latest scan .

# Scan with HTML and SARIF report generation
docker run --rm `
  -v "${PWD}:/workspace" `
  ghcr.io/noviqtechnologies/vexa-sca:latest scan . `
    --html-file sca-report.html `
    --sarif-file results.sarif `
    --fail-on high
```

#### Windows (Command Prompt - CMD)
```cmd
docker run --rm -v "%cd%:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan . --html-file sca-report.html --fail-on high
```

---

### 3. Docker Compose Orchestration

For development teams or staging servers, define a `docker-compose.yml` to standardize scans across multiple microservices:

```yaml
version: "3.8"

services:
  sca-audit:
    image: ghcr.io/noviqtechnologies/vexa-sca:latest
    container_name: vexa-sca-scanner
    volumes:
      - ./:/workspace
      - vexa-cache:/workspace/.sca-cache
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN}
    command: >
      scan .
      --html-file /workspace/sca-report.html
      --sarif-file /workspace/sca-results.sarif
      --fail-on high
      --fail-on-reachable
      --epss-threshold 0.50

volumes:
  vexa-cache:
    name: vexa_sca_cache
```

Execute the scan using Compose:
```bash
docker compose run --rm sca-audit
```

To inspect your scan quota status from a container:
```bash
docker run --rm ghcr.io/noviqtechnologies/vexa-sca:latest usage
```


---

### 4. Container & OS Package Auditing (`vexa-sca container`)

Vexa SCA includes a dedicated engine for auditing Linux operating system packages inside containers, Dockerfiles, and image tarballs without requiring root privileges.

#### A. Scanning an Exported Container Image Archive (`.tar` / `.tar.gz`)
Save any local Docker image to a tarball and audit its Alpine or Debian packages:

```bash
# 1. Export container image
docker save my-web-app:latest -o my-web-app.tar

# 2. Audit the image archive using Vexa SCA
docker run --rm \
  -v "${PWD}:/workspace" \
  ghcr.io/noviqtechnologies/vexa-sca:latest container my-web-app.tar \
    --html-file container-report.html \
    --fail-on high
```

#### B. Auditing an Extracted Rootfs or Sysroot
```bash
vexa-sca container /var/chroot/alpine-rootfs --severity-threshold high
```

#### C. Auditing Dockerfile Base Images
Vexa SCA parses `FROM` directives in Dockerfiles to identify known vulnerabilities in parent base images:
```bash
vexa-sca container ./Dockerfile
```

---

## Advanced Configuration & Edge Cases

### Running with Persistent Cache Volumes
To prevent downloading vulnerability intelligence repeatedly across container executions, mount a persistent volume for `.sca-cache`:

```bash
docker volume create vexa_cache

docker run --rm \
  -v "${PWD}:/workspace" \
  -v vexa_cache:/workspace/.sca-cache \
  ghcr.io/noviqtechnologies/vexa-sca:latest scan .
```

### Passing Authentication Tokens for Automated Fixes
When invoking `vexa-sca fix --create-pr` from inside a container, pass the `GITHUB_TOKEN` environment variable:

```bash
docker run --rm \
  -v "${PWD}:/workspace" \
  -e GITHUB_TOKEN="<YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>" \
  ghcr.io/noviqtechnologies/vexa-sca:latest fix \
    --create-pr \
    --repo "<OWNER>/<REPO>"
```

### Corporate Proxies & Custom Certificate Authorities
If your organization requires an egress HTTP/HTTPS proxy or custom corporate root CA certificates:

```bash
docker run --rm \
  -v "${PWD}:/workspace" \
  -v /etc/ssl/certs/corporate-ca.crt:/etc/ssl/certs/corporate-ca.crt:ro \
  -e HTTP_PROXY="http://proxy.internal.corp:8080" \
  -e HTTPS_PROXY="http://proxy.internal.corp:8080" \
  -e NO_PROXY="localhost,127.0.0.1,internal.corp" \
  ghcr.io/noviqtechnologies/vexa-sca:latest scan .
```

---

## Troubleshooting & FAQs

### 1. `Permission denied` when generating reports on Linux/macOS
- **Cause**: The container process runs as `root` (or a different UID) by default, creating generated files (`sca-report.html`, `results.sarif`) with root ownership on the host filesystem.
- **Resolution**: Pass host user and group IDs via the `-u` flag:
  ```bash
  docker run --rm -u $(id -u):$(id -g) -v "${PWD}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan . --html-file report.html
  ```

### 2. Windows PowerShell path mounting syntax error
- **Cause**: PowerShell syntax `$PWD` requires quotes or may not resolve properly if backslashes are passed directly.
- **Resolution**: Always wrap `${PWD}` in quotes:
  ```powershell
  docker run --rm -v "${PWD}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan .
  ```

### 3. Container scanner reports `Zero OS packages detected` for a scratch image
- **Cause**: Container images built `FROM scratch` or distroless images without package managers do not contain `/lib/apk/db/installed` (Alpine) or `/var/lib/dpkg/status` (Debian).
- **Resolution**:
  - This is expected behavior for scratch/distroless runtimes.
  - Scan the application dependencies (e.g., `package-lock.json` or `Cargo.lock`) using `vexa-sca scan .` rather than `vexa-sca container`.
