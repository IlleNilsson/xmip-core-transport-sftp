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

The far end serves channel after channel per connection, and `serving` serves every client a listener accepts at once over one shared directory (`transport::concurrent`): what several receiving nodes race at, as the Playground's drop box does. It keeps what the claim leans on: an open with `EXCL` of an existing name, and a rename onto one, are refused, and a rename keeps the file's modification time.

A Send Location puts on an SSH connection whose keys are exchanged and whose user is authenticated once per server and kept (`transport::Pool`), a channel per file, each closed from both ends; the far end serves channel after channel until the client hangs up. Until 2026-09-27 every put exchanged keys and authenticated. A put sends the Message a `WRITE` request (32 KiB) at a time as it is read from the Ledger, never whole in memory (`Sending::Streamed`, 2026-10-19), and a receive claims no more files of a listing than the runtime has room for, the rest left for the next harvest.

A Receive Location harvests on the same kept connection, a channel per harvest. Until 2026-09-28 every receive exchanged keys and authenticated.

## Names, and a directory to a user

A file keeps its name both ways (ADR-0024, amendment 2026-10-20): an arrival carries the name it was dropped under as `file.name`, which the Message Context keeps, and a send names its file as the file family does — the name the Message was received under, else its identifier, or the target's own name where a test or a tool sends bytes it holds — the one naming in the transport capability (`transport::file_name`). Until 2026-10-22 a send named its file by its target's last segment, so a Send Location whose address named the server alone wrote every file under one empty name.

The far end serves one directory to everyone (`serving`) or one to each user (`serving_each`), and tells its owner of every file a client finished writing as it closes it (`Directory::telling`): the Parties' far end the Playground serves the nodes on machines of their own, each Location a user of its own there (ADR-0028, amendment 2026-10-22). The client still lists and names files in the directory its login lands in; a path in its address is not yet followed.

## The claim

A file is taken once it is finished, and by one node (ADR-0024, amendment 2026-10-13): several receiving nodes may poll one directory, and whichever claims a file has it. The claim is the file family's, written once in the transport capability (`transport::claim`), in SFTP's words (`src/site.rs`): a file is taken by the listing after the one whose `READDIR` entry gave it the same length and modification time — the stability check, checked again by `SSH_FXP_STAT` once its turn is held; its turn is `<name>.xmip-claim`, opened with `SSH_FXF_CREAT` and `SSH_FXF_EXCL`, which the server refuses where it exists, holding the node's name; the claim is `SSH_FXP_RENAME` to `<name>.xmip-claim.<node location, percent-encoded>.<nanoseconds>`. A node built by the runtime (`Configured::on_node`) returns every claim its name still holds, and removes its turns, at its first receive that reaches the server. Until 2026-10-13 a receive claimed nothing, and two nodes on one directory could both take a file.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists and claims over one channel and hands each claimed file back unread; its body is read a `READ` request (32 KiB) at a time as the runtime asks, never whole in memory. `Accepted` removes the claimed file (`SSH_FXP_REMOVE`). `Refused` renames it back under its dropped name: a refusal at a transport gate keeps nothing in Xmip, so the file is the only copy. This Location does not receive it again while it is unchanged — the length and modification time its `READDIR` entry carries (`SSH_FILEXFER_ATTR_SIZE` and `ACMODTIME`, whole seconds in version 3); written again, it is a new arrival. Version 3 times are whole seconds, so a file written again within the same second at the same length looks unchanged until it changes again. What is remembered as refused is the node process's: a node started again receives a refused file once more, and refuses it again. `Failed`, or an arrival let go without a verdict, renames it back, and a later receive lists it again. A return is a rename, which version 3 refuses onto an existing name, so a file dropped under the dropped name since is never replaced: the claimed one is held, with why (`SftpTransport::held`), and goes back once the name is free. The channel stays open, held by one thread for the receive, until every arrival of it has its verdict (`transport::together`), so the reads and removes cost the round trips they did when a receive took and removed every file itself; the connection then goes back to the pool. A send that finds it lent to a receive opens a connection of its own. Until 2026-10-02 a receive read and removed every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

## The address alone

A Location is entered by its address (ADR-0064, amendment 2026-10-28): `sftp://user@host:22/dir`, the user it logs in as in the address's user part — `xmip` where it names none — its password or key the secret the Location names (`secret = "<name>"`, set with `Set-XmipSecret`), never a setting. The `user` setting is deleted; `timeout` remains.
