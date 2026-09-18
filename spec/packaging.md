# packaging

`snolpkg` installs immutable native module content from HTTPS Git or an
absolute local Git path.

```text
snolpkg add -b <git-url> <module-name>
snolpkg add -s <git-url> <module-name>
snolpkg del <owner/name@version>
snolpkg template <owner/name@version> --role <role> --output <path>
```

Set `SNOLPKG_ROOT` to an absolute package directory. Copy
`config/packages/snolpkg.toml` and `config/packages/sources.toml` there before
the first install.

## publication

The installer reads `snolpkg/<module>.toml` and its detached `.toml.sig` from a
single pinned Git commit through gix object access. It does not check out the
publication tree or run Git filters.

The strict manifest names package, authors, license, package version,
`wire_version`, classes, family, roles, platform capabilities, role template
source paths, entry, exact dependencies, source revision, toolchain, Cargo
package, and artifacts.

Each template lists its artifact targets. Every platform target and role pair
maps to one template. The installed target selects the template, so adapter-tun
emits Linux native mode on Linux and Android fd mode on Android.

Each artifact declares target triple, minimum ISA, minimum glibc or Android
API, HTTPS URL, byte size, SHA-256, and source-build output. The detached
Ed25519 signature covers the source TOML bytes. `sources.toml` supplies the
trusted public key. A key inside the package has no authority.

## binary install

Binary mode performs these operations:

1. lock the package root;
2. read and verify the publication;
3. verify exact installed dependencies;
4. download into a fresh staging directory;
5. enforce response length, byte count, and SHA-256;
6. extract regular files within configured limits;
7. verify the library and declared templates;
8. move content into its content-addressed immutable store;
9. replace the package lock atomically.

Archives may contain regular files and directories. The extractor rejects
absolute paths, parent traversal, links, devices, duplicate paths, setuid or
setgid bits, too many files, and byte-limit overflow.

## source install

Source mode checks out the exact signed source revision with gix, then runs:

```text
cargo +<toolchain> build --release --locked --package <package> --target <target>
```

The process uses argument vectors, not a shell. It copies the declared output,
role templates, project license, and notices into staging. Missing Cargo,
toolchain, source path, build output, or template fails. Source mode does not
download a binary fallback. Building package source executes untrusted build
code and is not a sandbox.

## store and deletion

The store path contains source fingerprint, owner, name, version, target, and
library content hash. A lock records the exact canonical library and store
paths. The engine verifies package identity and content hash before loading.
It never resolves `latest` or accesses the network.

Deletion checks every lock for an exact reverse dependency. It moves the store
entry to staging before removing the lock and restores it if lock removal
fails. Deletion does not remove module state or user configuration.

## templates and updates

`template` copies `templates/<role>.toml` to a new path and refuses overwrite.
An update installs another immutable content hash and atomically changes the
lock. It leaves user configuration untouched. A running engine keeps its loaded
library until a managed restart.

## proxy and offline behavior

Git, artifact HTTP, and Cargo inherit uppercase and lowercase `HTTP_PROXY`,
`HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY`. An invalid explicit proxy returns an
error and does not attempt a direct connection.

Offline mode rejects any HTTPS Git or artifact access. An offline bundle must
contain the publication, signature, lock inputs, and artifacts or vendored
source needed by the selected mode.

## official packages

Ten signed manifests live under the repository-root `snolpkg/`. Version 0.0.1 manifests
publish Linux x86_64 and Android arm64/armv7 artifacts built from commit
`dc4432b62ced51953beb662d6879beec2128486d`. Each archive carries Unlicense and
third-party dependency notices. Release checks compare archive size and SHA-256
to every signed row before upload.

`tools/package-release.py` consumes a checkout at that revision and explicit
prebuilt target directories. It writes deterministic archives, updates signed
artifact rows, and signs each manifest with the release Ed25519 key. Run
`tools/verify-release.py <dist>` before upload. A second package run must produce
byte-identical archives.

## failure behavior

A signature, hash, size, target, dependency, path, extraction, build, or move
error leaves the previous lock and store content available. Staging cleanup
does not rewrite a loaded library. The installer never raises privileges.
