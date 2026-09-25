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

Every message is built and read with `xmip-core-library-ssh`, the one home of
SSH's wire types — `boolean`, `string`, `mpint`, `name-list` — which the
ssh-key gate reads its blobs with too; the binary packet framing of RFC 4253
section 6 is this transport's own (ADR-0050, amendment 2026-09-25).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
