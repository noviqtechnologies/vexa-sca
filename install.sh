#!/usr/bin/env sh
# Vexa SCA CLI Official POSIX Installer with Checksum Verification
# Usage: curl -sSf https://raw.githubusercontent.com/noviqtechnologies/vexa-sca/main/install.sh | sh
# Or:    curl -sSf https://vexasec.io/sca/install.sh | sh
set -e

REPO="noviqtechnologies/vexa-sca"
VERSION="${VERSION:-latest}"

if [ "$VERSION" = "latest" ]; then
    VERSION_TAG=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -n 1)
    if [ -z "$VERSION_TAG" ]; then
        echo "Error: Failed to resolve latest release tag from GitHub; failing closed." >&2
        exit 1
    fi
else
    case "$VERSION" in
        v*) VERSION_TAG="$VERSION" ;;
        *)  VERSION_TAG="v$VERSION" ;;
    esac
fi

if ! printf '%s' "$VERSION_TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$'; then
    echo "Error: Invalid release tag format '$VERSION_TAG' (expected vX.Y.Z); failing closed." >&2
    exit 1
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH_SLUG="x86_64" ;;
    aarch64|arm64) ARCH_SLUG="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
    linux)  OS_SLUG="linux" ;;
    darwin) OS_SLUG="darwin" ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

TAR_NAME="vexa-sca-${OS_SLUG}-${ARCH_SLUG}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION_TAG/$TAR_NAME"
CHECKSUM_URL="https://github.com/$REPO/releases/download/$VERSION_TAG/${TAR_NAME}.sha256"

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'vexa-sca')"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Vexa SCA $VERSION_TAG (${OS_SLUG}-${ARCH_SLUG})..."
if ! curl -sSLf "$DOWNLOAD_URL" -o "$TMP_DIR/$TAR_NAME" 2>/dev/null; then
    echo "Prebuilt release binary for ${OS_SLUG}-${ARCH_SLUG} not found; attempting cargo install from Git tag $VERSION_TAG..." >&2
    if command -v cargo >/dev/null 2>&1; then
        cargo install --git "https://github.com/$REPO.git" --tag "$VERSION_TAG" --locked --bin vexa-sca
        echo "✔ vexa-sca installed successfully via cargo!"
        exit 0
    else
        echo "Error: Failed to download prebuilt binary ($DOWNLOAD_URL) and cargo is not available." >&2
        exit 1
    fi
fi

if ! curl -sSLf "$CHECKSUM_URL" -o "$TMP_DIR/${TAR_NAME}.sha256"; then
    echo "Error: Failed to download required SHA-256 checksum ($CHECKSUM_URL); failing closed." >&2
    exit 1
fi
EXPECTED_HASH=$(awk '{print $1}' "$TMP_DIR/${TAR_NAME}.sha256" | tr '[:upper:]' '[:lower:]' | head -n 1)
if ! printf '%s' "$EXPECTED_HASH" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "Error: Invalid or missing SHA-256 digest in ${TAR_NAME}.sha256; failing closed." >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_HASH=$(sha256sum "$TMP_DIR/$TAR_NAME" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_HASH=$(shasum -a 256 "$TMP_DIR/$TAR_NAME" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
elif command -v openssl >/dev/null 2>&1; then
    ACTUAL_HASH=$(openssl dgst -sha256 "$TMP_DIR/$TAR_NAME" | awk '{print tolower($NF)}')
else
    echo "Error: No SHA-256 tool found (sha256sum, shasum, or openssl required); failing closed." >&2
    exit 1
fi
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    echo "Error: SHA256 verification failed! Expected $EXPECTED_HASH, got $ACTUAL_HASH" >&2
    exit 1
fi
echo "✔ Checksum verified ($ACTUAL_HASH)."

# Rollback protection (POSIX-portable across Linux/macOS/BSD)
if [ -x "$INSTALL_DIR/vexa-sca" ] && [ "${VEXA_ALLOW_DOWNGRADE:-0}" != "1" ]; then
    EXISTING_VER="$("$INSTALL_DIR/vexa-sca" --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    REQUESTED_VER="$(printf '%s' "$VERSION_TAG" | sed 's/^v//' | cut -d- -f1)"
    if [ -n "$EXISTING_VER" ] && [ -n "$REQUESTED_VER" ] && [ "$EXISTING_VER" != "$REQUESTED_VER" ]; then
        IS_DOWNGRADE="$(awk -v cur="$EXISTING_VER" -v req="$REQUESTED_VER" 'BEGIN {
          split(cur, c, "."); split(req, r, ".");
          for (i = 1; i <= 3; i++) {
            if ((r[i] + 0) < (c[i] + 0)) { print "1"; exit }
            if ((r[i] + 0) > (c[i] + 0)) { print "0"; exit }
          }
          print "0";
        }')"
        if [ "$IS_DOWNGRADE" = "1" ]; then
            echo "Error: Rollback rejected: installed v$EXISTING_VER is newer than $VERSION_TAG (set VEXA_ALLOW_DOWNGRADE=1 to override)." >&2
            exit 1
        fi
    fi
fi

# Mandatory publisher signature & provenance verification (fail-closed)
BASE_URL="https://github.com/$REPO/releases/download/$VERSION_TAG"
CERT_IDENTITY="https://github.com/${REPO}/.github/workflows/release-slsa-cosign.yml@refs/tags/${VERSION_TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

if command -v cosign >/dev/null 2>&1; then
    if ! curl -sSLf "$BASE_URL/${TAR_NAME}.sigstore.json" -o "$TMP_DIR/${TAR_NAME}.sigstore.json"; then
        echo "Error: Failed to download required Cosign bundle ${TAR_NAME}.sigstore.json; failing closed." >&2
        exit 1
    fi
    cosign verify-blob \
        --bundle "$TMP_DIR/${TAR_NAME}.sigstore.json" \
        --certificate-identity "$CERT_IDENTITY" \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        "$TMP_DIR/$TAR_NAME" >/dev/null
elif command -v gh >/dev/null 2>&1; then
    gh attestation verify "$TMP_DIR/$TAR_NAME" \
        --repo "$REPO" \
        --signer-workflow "${REPO}/.github/workflows/release-slsa-cosign.yml" \
        --source-ref "refs/tags/${VERSION_TAG}" >/dev/null
elif command -v openssl >/dev/null 2>&1 && [ -n "${VEXA_RELEASE_PUBLIC_KEY_FILE:-}" ] && [ -f "${VEXA_RELEASE_PUBLIC_KEY_FILE:-}" ]; then
    if ! curl -sSLf "$BASE_URL/${TAR_NAME}.ed25519.sig" -o "$TMP_DIR/${TAR_NAME}.ed25519.sig"; then
        echo "Error: Failed to download ${TAR_NAME}.ed25519.sig; failing closed." >&2
        exit 1
    fi
    openssl pkeyutl -verify -pubin -inkey "$VEXA_RELEASE_PUBLIC_KEY_FILE" \
        -rawin -in "$TMP_DIR/$TAR_NAME" -sigfile "$TMP_DIR/${TAR_NAME}.ed25519.sig" >/dev/null
else
    echo "Error: Mandatory publisher signature verification requires 'cosign', 'gh', or VEXA_RELEASE_PUBLIC_KEY_FILE with 'openssl'; failing closed." >&2
    exit 1
fi

tar -xzf "$TMP_DIR/$TAR_NAME" -C "$TMP_DIR"
if [ -f "$TMP_DIR/vexa-sca" ]; then
    install -m 0755 "$TMP_DIR/vexa-sca" "$INSTALL_DIR/vexa-sca"
    ln -sf "$INSTALL_DIR/vexa-sca" "$INSTALL_DIR/sca"
elif [ -f "$TMP_DIR/bin/vexa-sca" ]; then
    install -m 0755 "$TMP_DIR/bin/vexa-sca" "$INSTALL_DIR/vexa-sca"
    ln -sf "$INSTALL_DIR/vexa-sca" "$INSTALL_DIR/sca"
fi

echo ""
echo "✔ Vexa SCA successfully installed to $INSTALL_DIR/vexa-sca"
case ":$PATH:" in
    *":$INSTALL_DIR:"*)
        RESOLVED_BIN="$(command -v vexa-sca 2>/dev/null || true)"
        if [ -n "$RESOLVED_BIN" ] && [ "$RESOLVED_BIN" != "$INSTALL_DIR/vexa-sca" ]; then
            echo "[WARN] Another 'vexa-sca' binary earlier in PATH is shadowing this installation:" >&2
            echo "       Shadowing: $RESOLVED_BIN" >&2
            echo "       Installed: $INSTALL_DIR/vexa-sca" >&2
            echo "       Remove the older binary or prepend $INSTALL_DIR to your PATH." >&2
        fi
        ;;
    *) echo "Notice: Add $INSTALL_DIR to your PATH in ~/.bashrc or ~/.zshrc:"
       echo "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
echo "Run 'vexa-sca --version' to get started."
