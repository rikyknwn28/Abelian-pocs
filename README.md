# Abelian — PoC repository

Runnable Go proof-of-concept tests for the Abelian Round 1 findings
reported privately to the Abelian Foundation (GitHub private Security
Advisory + security@pqabelian.io).

## Layout

- `abec-needset-dos/` — Finding 1 (Medium): unmetered `needset` /
  `getblocktx` serving lets an unauthenticated remote peer force
  full-block DB loads. Test file: `p2p_needset_metering_poc_test.go`
  (package `main`, drop into the `abec` repo root).
- `abec-abedecode/` — Finding 2 (Low): `MsgSimplifiedBlock.AbeDecode`
  allocates unbounded memory from an untrusted tx-count varint.
  Test file: `abedecode_poc_test.go` (package `wire`, drop into
  `abec/wire/`).
- `pqringct/` — Finding 3 (Low, pqringct layer): key-image malleability
  via caller-supplied ledger id (`TestHunt01_*`); and Finding 4 (Low):
  `TransferTxVerify` panics on malformed deserialized txs
  (`TestHunt02`–`TestHunt06`). Test file: `hunt_poc_test.go`
  (package `pqringct`, drop into the `pqringct` repo root).
- `pqringctx/` — Finding 3 (Low, pqringctx/MLP layer): same key-image
  malleability (`TestHunt01MLP_*`). Also contains N3 verification tests
  proving the duplicate-SN check works for a fixed SN (which is why
  Finding 3 is Low, not Critical). Test file: `hunt_poc_test.go`
  (package `pqringctx`, drop into the `pqringctx` repo root).

## How to run

All tests run locally only — no network, no mainnet, no live funds.

Target HEADs (2026-11-20):
- abec `35799bed12f326b10df8227aa93646c563d79cb7` (main)
- pqringct `a249e5320cbc2ede1d0b424726b1129997fc3072` (main)
- pqringctx `a5290eb8e5b8e6f9e58e53042d63df65874a080e` (main)

Environment (Go + liboqs, as used by the node build):

```sh
export PATH="$HOME/.local/go/bin:$PATH"
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig"
export LD_LIBRARY_PATH="$HOME/.local/lib"
export CGO_ENABLED=1
```

Commands (single package, `-p 1`):

```sh
# Finding 1 — from the abec repo root (test file in repo root):
go test -p 1 -run 'TestPOCNeedSetGetBlockTxUnmetered' -v -count=1 .

# Finding 2 — from the abec repo root (test file in wire/):
go test -p 1 -run 'TestPOCSimplifiedBlock' -v -count=1 ./wire/

# Finding 3 (pqringct layer) — from the pqringct repo root:
go test -p 1 -run 'TestHunt01_' -v -count=1 .

# Finding 3 (pqringctx/MLP layer) — from the pqringctx repo root:
go test -p 1 -run 'TestHunt01MLP' -v -count=1 .

# Finding 4 — from the pqringct repo root:
go test -p 1 -run 'TestHunt0[2-6]' -v -count=1 .
```

## Expected results (verified 2026-11-20)

- Finding 1: banScore stays **0** after 200× OnNeedSet + 50×
  pushNeedSetResultMsg + 50× pushBlockTxMsg; control OnGetData
  (2000 invs) raises it to **3**.
- Finding 2: `AbeDecode(txCount=5000000)` grows the heap 3 MB → 155 MB
  (+152 MB); control `BtcDecode` rejects with +0 MB;
  `AbeDecode(txCount=2^44)` panics (`makeslice: len out of range`).
- Finding 3: the same 500-coin verifies twice (two txs, 980 total
  outputs; one tx, 990 outputs) with **different** serial numbers,
  in both the pqringct and the pqringctx (MLP) layer.
- Finding 4: all five malformed txs panic `TransferTxVerify`
  (index out of range / nil pointer dereference) instead of
  returning an error.
