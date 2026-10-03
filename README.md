# xmip-core-transport-sftp

SFTP transport: the SSH file transfer protocol over an SSH session; a Receive Location lists and reads, a Send Location writes. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

One file is one Stream, carried over a real SSH handshake — Curve25519 key
exchange, an Ed25519 host key, `aes256-ctr` with `hmac-sha2-256`, then password
or public-key authentication and the `sftp` subsystem over one channel. The
transport brings its own far end (ADR-0051): an in-process SSH server serves a
directory held in memory, so one exchange runs both ways on this machine, and
a public-key login is promoted onto the arrival as `ssh.key`, `ssh.user`,
`ssh.signature` and `ssh.session` for the identity gate, names declared once
in `xmip-core-context` (`context::property`) for this transport and the gates.

SSH itself — the wire types, the binary packet protocol, the key exchange,
the cipher, user authentication and the session channel — is
`xmip-core-library-ssh`'s, which the ssh-key gate and identifier read keys,
signatures and fingerprints with too; what is this crate's is the SFTP
protocol over the channel, its client and its in-process far end. Until
2026-09-28 the SSH transport layer sat here, and verified an Ed25519
signature less strictly than the gate (ADR-0050, amendments 2026-09-25 and
2026-09-28).

A Send Location puts on an SSH connection whose keys are exchanged and whose user is authenticated once per server and kept (`transport::Pool`), a channel per file, each closed from both ends; the far end serves channel after channel until the client hangs up. Until 2026-09-27 every put exchanged keys and authenticated.

A Receive Location harvests on the same kept connection, a channel per harvest. Until 2026-09-28 every receive exchanged keys and authenticated.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists the directory over one channel and hands each file back unread; its body is read a `READ` request (32 KiB) at a time as the runtime asks, never whole in memory. `Accepted` removes the file (`SSH_FXP_REMOVE`). `Refused` removes it too: a directory has no place for a refused file, the runtime audited the refusal, and from Message creation on the Stream is kept in Xmip (ADR-0013); left, it would be listed and refused again on every receive. `Failed` leaves it, and the next receive lists it again. The channel stays open, held by one thread for the receive, until every arrival of it has its verdict (`transport::together`), so the reads and removes cost the round trips they did when a receive took and removed every file itself; the connection then goes back to the pool. A send that finds it lent to a receive opens a connection of its own. Until 2026-10-02 a receive read and removed every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
