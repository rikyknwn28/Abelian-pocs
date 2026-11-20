// PoC for Abelian hunt area (b) abec-p2p-rpc — CANDIDATE 1.
//
// Claim: the Abelian-specific P2P data-serving handlers OnNeedSet and
// OnGetBlockTx perform a full-block database load per request
// (chain.BlockByHashAbe + a full tx-hash map build in pushNeedSetResultMsg /
// pushBlockTxMsg) yet carry NO ban-score / rate-limit accounting, unlike
// OnGetData which scores every request (server.go addBanScore(0,
// len*99/MaxInvPerMsg, "getdata")). A remote peer can therefore force
// repeated full-block loads with tiny requests and never be banned.
//
// This test proves the accounting gap on a live local server (temp fflib DB,
// real chain, real inbound peer):
//   - 200x OnNeedSet for a known block + 50x pushNeedSetResultMsg /
//     pushBlockTxMsg (each performs the full DB-backed block load and reaches
//     the send path) leave the peer's ban score at 0 and the peer connected.
//   - A single OnGetData with 2000 unknown block invs raises the score to 3.
package main

import (
	"path/filepath"
	"testing"

	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/database"
	_ "github.com/pqabelian/abec/database/ffldb"
	"github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/wire"
)

func TestPOCNeedSetGetBlockTxUnmetered(t *testing.T) {
	quietP2PTestLogs(t)
	previousConfig := cfg
	cfg = &config{DisableBanning: false, BanThreshold: 100}
	t.Cleanup(func() { cfg = previousConfig })

	dir := t.TempDir()
	db, err := database.Create("ffldb", filepath.Join(dir, "blocks"), wire.MainNet, wire.FullNode, filepath.Join(dir, "temporary.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	chain, err := blockchain.New(&blockchain.Config{DB: db, ChainParams: &chaincfg.MainNetParams, NodeType: wire.FullNode, TimeSource: blockchain.NewMedianTime()})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{chain: chain, db: db}
	p := peer.NewInboundPeer(&peer.Config{CommunicationCache: &s.communicationCache})
	defer p.Disconnect()
	sp := &serverPeer{Peer: p, server: s}

	genesis := chaincfg.MainNetParams.GenesisBlock
	genesisHash := genesis.BlockHash()

	// Phase A: 200 unsolicited needset requests for a known block. Each one
	// performs a full BlockByHashAbe load + tx-hash map build and queues a
	// response, yet must not raise the ban score at all.
	for i := 0; i < 200; i++ {
		sp.OnNeedSet(p, wire.NewMsgNeedSet(genesisHash, nil), nil)
	}
	// Directly exercise the serving path as well: every call loads the whole
	// block from the DB and reaches the send path.
	for i := 0; i < 50; i++ {
		if err := sp.server.pushNeedSetResultMsg(sp, genesisHash, nil, wire.WitnessEncoding); err != nil {
			t.Fatalf("pushNeedSetResultMsg #%d failed (expected full-block load to succeed): %v", i, err)
		}
		if err := sp.server.pushBlockTxMsg(sp, genesisHash, genesis.Transactions[0].TxHash(), wire.WitnessEncoding); err != nil {
			t.Fatalf("pushBlockTxMsg #%d failed (expected full-block load to succeed): %v", i, err)
		}
	}
	if score := sp.banScore.Int(); score != 0 {
		t.Fatalf("ban score after 200 needset + 100 full-block serves = %d, want 0 (no metering)", score)
	}
	// The peer was never banned: serving still works after the 300 requests.
	if err := sp.server.pushNeedSetResultMsg(sp, genesisHash, nil, wire.WitnessEncoding); err != nil {
		t.Fatalf("serving stopped after 300 unmetered requests: %v", err)
	}
	t.Logf("after 200 OnNeedSet + 50 pushNeedSetResultMsg + 50 pushBlockTxMsg: banScore=%d (peer never banned)", sp.banScore.Int())

	// Phase B (control): the equivalent getdata path IS metered. 2000 invs
	// add 2000*99/50000 = 3 to the transient ban score.
	msg := wire.NewMsgGetData()
	for i := 0; i < 2000; i++ {
		h := chainhash.Hash{byte(i), byte(i >> 8)}
		if err := msg.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &h)); err != nil {
			t.Fatal(err)
		}
	}
	sp.OnGetData(p, msg)
	if score := sp.banScore.Int(); score == 0 {
		t.Fatal("control failed: OnGetData did not raise the ban score")
	} else {
		t.Logf("after 1 OnGetData with 2000 invs: banScore=%d (metered, as expected)", score)
	}
}
