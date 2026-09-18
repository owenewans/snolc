#!/bin/sh

set -eu

repo=https://github.com/owenewans/snolc
version=0.0.3
mode=binary
prefix=${HOME:-}/.local

usage() {
    echo "usage: install.sh [--binary|--source] [--prefix DIR] [--version VERSION]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) mode=binary ;;
        --source) mode=source ;;
        --prefix)
            [ "$#" -ge 2 ] || usage
            prefix=$2
            shift
            ;;
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift
            ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
    shift
done

[ -n "$prefix" ] || usage
tmp=$(mktemp -d "${TMPDIR:-/tmp}/snolc-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

install_binary() {
    command -v curl >/dev/null
    command -v openssl >/dev/null
    command -v sha256sum >/dev/null
    command -v tar >/dev/null

    os=$(uname -s)
    arch=$(uname -m)
    case "$os:$arch" in
        Linux:x86_64) target=x86_64-unknown-linux-gnu ;;
        Linux:i386|Linux:i486|Linux:i586) target=i586-unknown-linux-gnu ;;
        Linux:i686) target=i686-unknown-linux-gnu ;;
        Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
        Linux:armv7l|Linux:armv7*) target=armv7-unknown-linux-gnueabihf ;;
        Linux:riscv64) target=riscv64gc-unknown-linux-gnu ;;
        Darwin:x86_64) target=x86_64-apple-darwin ;;
        Darwin:arm64) target=aarch64-apple-darwin ;;
        FreeBSD:amd64) target=x86_64-unknown-freebsd ;;
        FreeBSD:arm64) target=aarch64-unknown-freebsd ;;
        NetBSD:amd64) target=x86_64-unknown-netbsd ;;
        *) echo "unsupported binary target: $os $arch" >&2; exit 1 ;;
    esac
    if [ "$os" = Linux ] && ldd --version 2>&1 | grep -qi musl; then
        case "$target" in
            i586-unknown-linux-gnu) target=i586-unknown-linux-musl ;;
            i686-unknown-linux-gnu) target=i686-unknown-linux-musl ;;
            x86_64-unknown-linux-gnu) target=x86_64-unknown-linux-musl ;;
            aarch64-unknown-linux-gnu) target=aarch64-unknown-linux-musl ;;
            armv7-unknown-linux-gnueabihf) target=armv7-unknown-linux-musleabihf ;;
            riscv64gc-unknown-linux-gnu) target=riscv64gc-unknown-linux-musl ;;
        esac
    fi

    base=$repo/releases/download/v$version
    asset=snolc-$version-$target.tar.gz
    curl --proto '=https' --tlsv1.2 -fsSL "$base/$asset" -o "$tmp/$asset"
    curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
    curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS.sig" -o "$tmp/SHA256SUMS.sig"
    cat >"$tmp/release-ed25519.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAk3rH7/T0QfUp+igwhN/9KNPhgrerUkkXjDgfadFv258=
-----END PUBLIC KEY-----
EOF
    openssl pkeyutl -verify -rawin -pubin -inkey "$tmp/release-ed25519.pem" \
        -in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null
    expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/SHA256SUMS")
    [ -n "$expected" ] || { echo "release checksum is missing: $asset" >&2; exit 1; }
    actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
    [ "$actual" = "$expected" ] || { echo "release checksum failed: $asset" >&2; exit 1; }
    tar -xzf "$tmp/$asset" -C "$tmp" bin/snolc
    install -d "$prefix/bin"
    install -m 755 "$tmp/bin/snolc" "$prefix/bin/snolc"
}

install_source() {
    command -v cargo >/dev/null
    command -v git >/dev/null
    git clone --depth 1 --branch "v$version" "$repo.git" "$tmp/source"
    cargo +1.98.1 build --manifest-path "$tmp/source/Cargo.toml" --locked --release -p snolc-cli
    install -d "$prefix/bin"
    install -m 755 "$tmp/source/target/release/snolc" "$prefix/bin/snolc"
}

case "$mode" in
    binary) install_binary ;;
    source) install_source ;;
    *) usage ;;
esac

echo "installed $prefix/bin/snolc"
