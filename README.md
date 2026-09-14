# xmip-core-transport-sftp

SFTP transport: the SSH file transfer protocol over an SSH session; a Receive Location lists and reads, a Send Location writes. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

Declared and not yet written; `architecture.toml` carries the maturity. When
it is written it implements `Transport`, one mechanism at one gate (ADR-0050).
What it may depend on is `repository-model.md` section 4 and ADR-0044: its
capability, and no sibling.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
