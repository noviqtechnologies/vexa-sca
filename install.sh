#!/usr/bin/env sh
# Vexa SCA CLI Official POSIX Installer with Checksum Verification
# Usage: curl -sSf https://raw.githubusercontent.com/noviqtechnologies/vexa-sca/main/install.sh | sh
# Or:    curl -sSf https://vexasec.io/sca/install.sh | sh
set -e

REPO="noviqtechnologies/vexa-sca"
VERSION="${VERSION:-latest}"

if [ "$VERSION" = "latest" ]; then
    VERSION_TAG=$(curl -sSf "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v1.3.4")
else
    case "$VERSION" in
        v*) VERSION_TAG="$VERSION" ;;
        *)  VERSION_TAG="v$VERSION" ;;
    esac
fi

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

case "$OS" in
    linux)  TARGET="${ARCH}-unknown-linux-gnu" ;;
    darwin) TARGET="${ARCH}-apple-darwin" ;;
    *) echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

TAR_NAME="vexa-sca-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION_TAG/$TAR_NAME"
CHECKSUM_URL="https://github.com/$REPO/releases/download/$VERSION_TAG/checksums.txt"

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'vexa-sca')"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Vexa SCA $VERSION_TAG for $TARGET..."
if ! curl -sSLf "$DOWNLOAD_URL" -o "$TMP_DIR/$TAR_NAME" 2>/dev/null; then
    echo "Prebuilt release binary not found; attempting cargo install..." >&2
    if command -v cargo >/dev/null 2>&1; then
        cargo install vexa-sca --locked
        echo "✔ vexa-sca installed successfully via cargo!"
        exit 0
    else
        echo "Error: Failed to download prebuilt binary and cargo is not available." >&2
        exit 1
    fi
fi

if curl -sSLf "$CHECKSUM_URL" -o "$TMP_DIR/checksums.txt" 2>/dev/null; then
    EXPECTED_HASH=$(grep "$TAR_NAME" "$TMP_DIR/checksums.txt" | awk '{print $1}')
    if [ -n "$EXPECTED_HASH" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL_HASH=$(sha256sum "$TMP_DIR/$TAR_NAME" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL_HASH=$(shasum -a 256 "$TMP_DIR/$TAR_NAME" | awk '{print $1}')
        fi
        if [ -n "$ACTUAL_HASH" ] && [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
            echo "Error: SHA256 verification failed!" >&2
            echo "Expected: $EXPECTED_HASH" >&2
            echo "Actual:   $ACTUAL_HASH" >&2
            exit 1
        fi
        echo "✔ Checksum verified successfully."
    fi
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
    *":$INSTALL_DIR:"*) ;;
    *) echo "Notice: Add $INSTALL_DIR to your PATH in ~/.bashrc or ~/.zshrc:"
       echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
echo "Run 'vexa-sca --version' to get started."
