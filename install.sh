#!/usr/bin/env bash
set -euo pipefail

REPO="jericbas/ufw-guard"
INSTALL_BIN="/usr/local/sbin/ufw"

log() {
    echo -e "\033[1;32m[ufw-guard]\033[0m $*"
}

warn() {
    echo -e "\033[1;33m[ufw-guard WARN]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ufw-guard ERROR]\033[0m $*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    error "Installation requires root privileges. Please run with sudo: curl ... | sudo bash"
fi

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        DEB_ARCH="amd64"
        RPM_ARCH="x86_64"
        TAR_ARCH="x86_64"
        ;;
    *)
        error "Unsupported system architecture: ${ARCH}. Only x86_64 is supported currently."
        ;;
esac

log "Detecting latest release version from GitHub..."
LATEST_TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
    | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)"

if [ -z "${LATEST_TAG}" ]; then
    LATEST_TAG="v0.1.0"
    warn "Could not fetch latest release from GitHub API; falling back to default ${LATEST_TAG}"
fi

VERSION="${LATEST_TAG#v}"
log "Installing ufw-guard version ${VERSION} (${ARCH})..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
cd "${TMP_DIR}"

if command -v apt-get >/dev/null 2>&1; then
    DEB_NAME="ufw-guard_${VERSION}_${DEB_ARCH}.deb"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${DEB_NAME}"
    log "Downloading Debian package: ${DEB_NAME}..."
    if curl -fsSL -o "${DEB_NAME}" "${DOWNLOAD_URL}"; then
        log "Installing via apt..."
        apt-get update -qq || true
        apt-get install -y ./"${DEB_NAME}"
    else
        warn "Could not download ${DEB_NAME}; falling back to standalone binary installation."
        FALLBACK_NEEDED=1
    fi
elif command -v dnf >/dev/null 2>&1 || command -v rpm >/dev/null 2>&1; then
    RPM_NAME="ufw-guard-${VERSION}-1.${RPM_ARCH}.rpm"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${RPM_NAME}"
    log "Downloading RPM package: ${RPM_NAME}..."
    if curl -fsSL -o "${RPM_NAME}" "${DOWNLOAD_URL}"; then
        if command -v dnf >/dev/null 2>&1; then
            log "Installing via dnf..."
            dnf install -y ./"${RPM_NAME}"
        else
            log "Installing via rpm..."
            rpm -Uvh ./"${RPM_NAME}"
        fi
    else
        warn "Could not download ${RPM_NAME}; falling back to standalone binary installation."
        FALLBACK_NEEDED=1
    fi
else
    FALLBACK_NEEDED=1
fi

if [ "${FALLBACK_NEEDED:-0}" -eq 1 ]; then
    TAR_NAME="ufw-guard-${VERSION}-${TAR_ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${TAR_NAME}"
    log "Downloading binary tarball: ${TAR_NAME}..."
    curl -fsSL -o "${TAR_NAME}" "${DOWNLOAD_URL}"
    tar -xzf "${TAR_NAME}"
    mkdir -p /usr/local/sbin
    install -m 755 "ufw-guard-${VERSION}-${TAR_ARCH}/ufw" "${INSTALL_BIN}"
fi

if [ -x "${INSTALL_BIN}" ]; then
    log "ufw-guard successfully installed at ${INSTALL_BIN}!"
    log "To uninstall in the future:"
    log "  Debian/Ubuntu: sudo apt remove ufw-guard"
    log "  RHEL/Fedora:   sudo dnf remove ufw-guard"
    log "  Manual:        sudo rm -f ${INSTALL_BIN}"
else
    error "Installation failed: ${INSTALL_BIN} not found or not executable."
fi
