# profiles, URI, and subscriptions

A profile URI has this form:

```text
snolc://profile/<base64url-no-padding UTF-8 TOML>
```

The encoded data occupies the path after `profile/`. The URI has no host. The
decoded TOML is at most 65,536 bytes. The decoder rejects padding, non-ASCII
base64 input, invalid UTF-8, unknown fields, and oversized data before import.

## profile schema

A profile contains:

- `wire_version = 1`
- a unique `server_id`
- endpoint
- one or more client adapter module records
- one protection, one carrier, and one policy module record
- pinned server identity
- bearer credential

Each module record contains instance, exact `owner/name@version`, class, and
client-role options. A profile supports at most 16 module records and rejects
duplicate instance IDs.

Profile options cannot set local paths, files, directories, sockets, commands,
scripts, package root, state root, or log destination. The importer generates
those values under its client data directory. It does not interpret URI data as
a shell command or install script.

## trust and installation

Import lists native package identities and their source before installation.
snolcNG requires approval for every package outside its trusted bundled set.
It installs through signed `snolpkg` sources. A profile cannot add a signing key
or weaken source trust.

Changing a package identity or server pin requires a new approved profile.
Subscription refresh does not inherit new package or filesystem privileges.

The profile URI is a bearer secret. Do not pass it on a process command line,
store it in logs, include it in crash reports, or publish it in shell history.
Provisioning prints one URI once. If it is lost, revoke that credential and
issue another.

## local persistence

Desktop config generation writes private files atomically. Secret module files
use mode 0600 and the containing directory uses mode 0700. snolcNG removes
temporary plaintext secret files after `Engine::build`, before reporting build
failure or starting the engine.

Android stores credentials encrypted with an AES-256-GCM key held by
AndroidKeyStore. Profile metadata stored under app-private storage excludes the
credential. Rust requests the credential through JNI for connection setup and
does not persist plaintext. Losing or invalidating the Keystore key makes the
profile unusable until reimport.

## subscriptions

A subscription is an HTTPS TOML document containing an array of profile URI
strings. The client bounds response bytes and profile count, then sends each URI
through the same parser as manual import. A bearer subscription token stays in
platform secret storage and does not enter logs.

Each `server_id` retains its own policy-local balance and status. The UI does
not sum independent server quotas into a global quota. A missing update marks
the previous status stale.

HTTP redirects are bounded. TLS, HTTP, decode, duplicate server, package trust,
pin change, and size failures leave the previous imported profile active.

## policy status

The protected POLICY stream supplies `used_bytes`, `limit_bytes`, upload and
download rates, expiration, revision, and reason. snolcNG handles known
policy-local fields. For another policy family, it keeps opaque data with the
family and schema identity. It reports an unsupported display instead of zero
usage.
