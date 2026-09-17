# policy-local

`policy-local` owns users, credentials, quota, rates, rules, administrative
idempotency, and user status. These values do not enter the common ABI.

## identity and authorization

A user ID is 16 random bytes rendered as 32 lowercase hex characters. A bearer
credential is 32 random bytes. Provisioning returns the credential once and
sends only its SHA-256 digest to `credential.add`. redb stores the digest and
user reference.

One yamux session binds to one user after AUTH on its POLICY stream. The client
cannot name another user in a flow OPEN. Credential mode `protected` requires
confidentiality on both ends and authenticated server identity on the client.
Policy reads those claims from `snolc.channel.security`. Core does not infer
them from a module name.

## storage

One storage worker owns `state/policy.redb`. It uses redb 4.3.0,
`Durability::Immediate`, one KV table, a 4 MiB low-memory cache, and a queue of
64 commands. Keys use `meta/`, `user/`, `credential/`, and `client/` prefixes.
Values use postcard.

The state directory has mode 0700 and the database file has mode 0600.
`LockedFileBackend` holds one whole-file exclusive lock, uses positional file
I/O, retries interrupted short operations, syncs durable commits, and refuses
growth beyond `max_database_bytes`. Failure to lock or sync stops the policy
instance.

Active users live in a bounded RAM cache. Packet forwarding does not read redb.

## administrative control

The local control socket accepts these methods:

- `user.create`, `user.update`, `user.disable`, `user.delete`
- `credential.add`, `credential.revoke`
- `quota.add`, `quota.new_period`
- `usage.get`
- `sessions.list`, `sessions.disconnect`
- `rules.replace`
- maintenance backup and restore operations

A mutation carries `client_id`, monotonic `seq`, and required revision where
the method changes an existing record. For one client, `last + 1` executes in
the same transaction as the data change. A repeat of `last` with the same
request hash returns the stored nonsecret response. A changed repeat, old
sequence, or sequence gap fails. `max_admin_clients` bounds receipt state.

The response reports success after Immediate commit and runtime application.
Disable and revoke stop new work first, commit, then close affected flows.
Other users continue.

## quota

Server policy charges payload accepted at the StackSocket to MuxStream boundary.
It charges upload plus download. TCP charges the accepted byte count. UDP
charges a full accepted datagram. Wire, policy, Noise, SSH, and carrier retry
bytes do not count.

Each active user owns at most one precharged block. With no RAM credit, policy
stops that user and asks storage to add the smaller of
`accounting_block_bytes` and unallocated quota to durable charged bytes. Policy
spends RAM credit only after an Immediate commit. It never prefetches a second
block.

Normal checkpoint and shutdown pause the user, refund unused credit with an
Immediate commit, then clear RAM credit. A crash can charge at most one unused
block per active user. An ambiguous storage result stops issuance and reloads
durable state before recovery. Policy does not retry a debit or refund blind.

Quota exhaustion closes that user's flows. The POLICY stream stays for
`control_grace_ms` so the client receives status. Refill does not reset usage;
`quota.new_period` starts a new period after invalidating old credit.

## scheduling and rates

Upload and download use integer token buckets with monotonic nanosecond time.
An optional combined bucket limits their sum. UDP requires burst large enough
for the largest allowed datagram. Checked arithmetic rejects overflow.

Weighted deficit round robin schedules active users. Round robin schedules
flows within one user. More sessions or flows do not increase a user's weight.
The policy sets one timer for the next token or deadline and never spins.

## access and filtering

User records contain enabled status, expiration or unlimited, total quota or
unlimited, directional rate modes, burst, session and flow limits, weight,
groups, weekly UTC windows, and ordered rules. The first matching rule decides;
a terminal action is required.

Rules match direction, IP or CIDR, port, exact or suffix domain, TLS SNI, HTTP
Host, protocol class, and user group. Protocol classes are TLS, HTTP, SSH, QUIC,
and unknown. A rule defines behavior when a requested observed value is absent.

Sniffing reads at most 16,384 bytes for 2,000 ms in the low-memory template.
That prefix counts against the flow memory budget. HTTPS content stays
encrypted. QUIC and ECH do not promise a visible destination name.

Clock rollback cannot extend an access period. Runtime derives monotonic
deadlines and persists the maximum observed UTC. Restart compares wall time to
that maximum.

## policy stream

Messages use `u32_be length` plus UTF-8 TOML, capped at 16,384 bytes. Client
methods are AUTH, status, subscribe, and disconnect self. Administrative method
names on this stream are denied.

After authorization, policy sends status no faster than
`status_interval_ms`. A one-entry snapshot queue replaces stale status. Errors
and command responses use a separate bounded queue and are not replaced.

## maintenance and failure

Backup pauses new policy work, drains and closes redb, copies the stable file,
opens the copy for verification, reopens the live database, then resumes.
Restore requires a stopped policy. The module never restores an older quota
database after an error.

Storage error, corrupted data, full disk, failed lock, policy protocol error,
or queue exhaustion stops the affected operation or instance. None selects
policy-dummy or a direct network path.
