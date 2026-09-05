#!/usr/bin/env bash
set -euo pipefail

target="aarch64-linux-android"
api="${ANDROID_API:-24}"
ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if [[ ! "$api" =~ ^[0-9]+$ ]]; then
    printf 'ANDROID_API must be a number\n' >&2
    exit 1
fi

if [[ -z "$ndk" ]]; then
    printf 'set ANDROID_NDK_HOME to an Android NDK directory\n' >&2
    exit 1
fi

case "$(uname -s):$(uname -m)" in
    Linux:x86_64) host_tag="linux-x86_64" ;;
    Darwin:*) host_tag="darwin-x86_64" ;;
    *)
        printf 'unsupported Android NDK host: %s/%s\n' "$(uname -s)" "$(uname -m)" >&2
        exit 1
        ;;
esac

toolchain="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
cc="$toolchain/aarch64-linux-android${api}-clang"
cxx="$cc++"
strip="$toolchain/llvm-strip"
readelf="$toolchain/llvm-readelf"

for tool in "$cc" "$cxx" "$strip" "$readelf"; do
    if [[ ! -x "$tool" ]]; then
        printf 'missing Android NDK tool: %s\n' "$tool" >&2
        exit 1
    fi
done

export PATH="$toolchain:$PATH"
export ANDROID_NDK_HOME="$ndk"
export CC_aarch64_linux_android="$(basename "$cc")"
export CXX_aarch64_linux_android="$(basename "$cxx")"
export AR_aarch64_linux_android="llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$(basename "$cc")"

# boring-sys overrides the API-bearing compiler wrapper with a bare target
# triple. Put API 24 back explicitly and avoid compiler-rt outlined atomics.
export CFLAGS_aarch64_linux_android="--target=aarch64-linux-android${api} -mno-outline-atomics"
export CXXFLAGS_aarch64_linux_android="$CFLAGS_aarch64_linux_android"
export BORING_BSSL_RUST_CPPLIB="c++_static"

libcxxabi="$($cxx --print-file-name=libc++abi.a)"
builtins="$($cc --print-libgcc-file-name)"
for library in "$libcxxabi" "$builtins"; do
    if [[ ! -f "$library" ]]; then
        printf 'missing Android NDK runtime: %s\n' "$library" >&2
        exit 1
    fi
done

cargo_args=(rustc)
target_libdir="$(rustc --print target-libdir --target "$target")"
target_std=("$target_libdir"/libstd-*.rlib)
if [[ ! -e "${target_std[0]}" ]]; then
    rust_src="$(rustc --print sysroot)/lib/rustlib/src/rust/library"
    if [[ ! -d "$rust_src" ]]; then
        printf 'install the %s Rust target or the rust-src component\n' "$target" >&2
        exit 1
    fi
    export RUSTC_BOOTSTRAP=1
    cargo_args+=(-Z build-std)
fi

cargo_args+=(
    --release
    --target "$target"
    --bin snolc
    --
    -C "link-arg=$libcxxabi"
    -C "link-arg=$builtins"
)
cargo "${cargo_args[@]}"

artifact="target/$target/release/snolc"
"$strip" --strip-all "$artifact"
if "$readelf" -d "$artifact" | grep -q 'libc++_shared\.so'; then
    printf 'unexpected dynamic libc++ dependency in %s\n' "$artifact" >&2
    exit 1
fi

printf '%s\n' "$artifact"
