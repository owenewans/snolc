#!/bin/sh
# snolc installer.
#
#   curl -fsSL https://raw.githubusercontent.com/owenewans/snolc/master/scripts/install.sh | sh
#
# Downloads the release build for this machine and installs the `snolc` and
# `snolc-geoconv` binaries into ~/.local/bin.
#
# Environment:
#   SNOLC_VERSION      tag to install, defaults to the latest release
#   SNOLC_INSTALL_DIR  install directory, defaults to ~/.local/bin
#   SNOLC_DOWNLOAD_BASE  base URL for release assets, for mirrors

set -eu

REPO="owenewans/snolc"
INSTALL_DIR="${SNOLC_INSTALL_DIR:-${HOME}/.local/bin}"
BINARIES="snolc snolc-geoconv"

die() {
    printf 'snolc: %s\n' "$1" >&2
    exit 1
}

info() {
    printf 'snolc: %s\n' "$1"
}

# The script is delivered through a pipe, so stdin is the script itself and
# must never be read. Everything below is non-interactive by construction.

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
    fetch_stdout() { wget -q -O - "$1"; }
else
    die "curl or wget is required"
fi

os="$(uname -s)"
[ "$os" = "Linux" ] || die "unsupported operating system: $os (Linux only)"

machine="$(uname -m)"
case "$machine" in
    x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
    aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
    *) die "unsupported architecture: $machine" ;;
esac

version="${SNOLC_VERSION:-}"
if [ -z "$version" ]; then
    info "resolving latest release"
    version="$(
        fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
            sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
            head -n1
    )" || die "could not reach the GitHub API"
    [ -n "$version" ] || die "could not determine the latest release"
fi

base="${SNOLC_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download/${version}}"
archive="snolc-${target}.tar.gz"

tmp="$(mktemp -d)" || die "could not create a temporary directory"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

info "downloading ${version} for ${target}"
fetch "${base}/${archive}" "${tmp}/${archive}" ||
    die "could not download ${base}/${archive}"

# The checksum is published next to the archive. Verify it when we have a
# tool for it, but do not fail the install on a missing checksum file.
if fetch "${base}/${archive}.sha256" "${tmp}/${archive}.sha256" 2>/dev/null; then
    if command -v sha256sum >/dev/null 2>&1; then
        expected="$(cut -d' ' -f1 <"${tmp}/${archive}.sha256")"
        actual="$(sha256sum "${tmp}/${archive}" | cut -d' ' -f1)"
        [ "$expected" = "$actual" ] || die "checksum mismatch for ${archive}"
        info "checksum verified"
    fi
fi

tar -xzf "${tmp}/${archive}" -C "$tmp" || die "could not extract ${archive}"

mkdir -p "$INSTALL_DIR" || die "could not create ${INSTALL_DIR}"
for binary in $BINARIES; do
    [ -f "${tmp}/${binary}" ] || die "${binary} missing from ${archive}"
    chmod 755 "${tmp}/${binary}"
    # Replace by rename so an running copy of the old binary is not corrupted.
    mv -f "${tmp}/${binary}" "${INSTALL_DIR}/${binary}" ||
        die "could not install into ${INSTALL_DIR}"
done

info "installed ${BINARIES} into ${INSTALL_DIR}"

case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        printf '\n'
        info "${INSTALL_DIR} is not in PATH, add it with:"
        printf '\n    export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
        ;;
esac

"${INSTALL_DIR}/snolc" version
