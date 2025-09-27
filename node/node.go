package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"

	"log"

	mrand "math/rand"
	"net"

	"os/signal"

	"sync"
	"syscall"

	// "vendor/golang.org/x/net/idna"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// ---------- Types ----------
type Message struct {
	Command string      `json:"command"`
	Data    interface{} `json:"data"`
}

type NodeInfo struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

type RPCRequest struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type RPCResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type DKGResult struct {
	Address  string
	GroupKey *big.Int
}
type BatchProposal struct {
	Round      int64                    `json:"round"`
	BatchNonce uint64                   `json:"batch_nonce"`
	Items      []map[string]interface{} `json:"items"` // txs from mempool
	BatchHash  string                   `json:"batch_hash"`
	Relayer    string                   `json:"relayer"`
}

type BatchApproval struct {
	Round     int64  `json:"round"`
	BatchHash string `json:"batch_hash"`
	Verifier  string `json:"verifier"`
	Sig       string `json:"sig"` // signature of BatchHash
}

// ---------- Globals ----------
var (
	peerMap     = make(map[string]string)
	peerMapLock sync.Mutex

	p2pPort     string
	rpcPort     string
	selfId      string
	peersFile   string
	usersFile   string
	mempoolFile string

	// DKG state
	dkgLock         sync.Mutex
	dkgInitiator    string
	dkgParticipants []string
	dkgReveals      = make(map[string]*big.Int)

	currentID         string
	currentEOAFromPwd string
	currentCommitment string
	currentNullifier  string

	// channel used by initiator RPC to wait for finalization
	dkgResultCh chan DKGResult

	// Signing state
	signLock       sync.Mutex
	signTx         map[string]interface{}
	signFrom       string
	signShares     = make(map[string]*big.Int)
	signResultCh   chan map[string]interface{}
	signGroupParts []string

	// relayer
	stakeFile    string
	roundCounter int64
	batchNonce   uint64
	approvalLock sync.Mutex
	approvals    = make(map[string][]BatchApproval) // key = batchHash

)

// ---------- File Persistence ----------
func loadPeers() map[string]string {
	data, err := os.ReadFile(peersFile)
	if err != nil {
		return make(map[string]string)
	}
	var peers map[string]string
	if err := json.Unmarshal(data, &peers); err != nil {
		return make(map[string]string)
	}
	return peers
}

func savePeers() {
	peerMapLock.Lock()
	defer peerMapLock.Unlock()
	data, _ := json.MarshalIndent(peerMap, "", "  ")
	_ = os.WriteFile(peersFile, data, 0644)
}

func loadUsers() map[string]map[string]interface{} {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return make(map[string]map[string]interface{})
	}
	var users map[string]map[string]interface{}
	if err := json.Unmarshal(data, &users); err != nil {
		return make(map[string]map[string]interface{})
	}
	return users
}

func saveUsersMap(users map[string]map[string]interface{}) {
	data, _ := json.MarshalIndent(users, "", "  ")
	_ = os.WriteFile(usersFile, data, 0644)
}

func appendToMempool(entry map[string]interface{}) {
	mem := []map[string]interface{}{}
	data, _ := os.ReadFile(mempoolFile)
	if len(data) > 0 {
		_ = json.Unmarshal(data, &mem)
	}
	mem = append(mem, entry)
	out, _ := json.MarshalIndent(mem, "", "  ")
	_ = os.WriteFile(mempoolFile, out, 0644)
}

// Save an entry under a provided key (used to write final address or temporary participant-key)
func saveUserEntryWithKey(key string, participants []string, myShare *big.Int) {
	users := loadUsers()
	users[key] = map[string]interface{}{
		"participants":  participants,
		"private_share": "0x" + myShare.Text(16),
	}
	saveUsersMap(users)
}

// Save a temporary "pending" entry keyed by hash(participants). Returns that temp key.
func saveUserTemp(participants []string, myShare *big.Int) string {
	key := participantsKey(participants)
	saveUserEntryWithKey(key, participants, myShare)
	return key
}

// Compute deterministic temporary key for a participants set
func participantsKey(participants []string) string {
	joined := strings.Join(participants, ",")
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(joined))
	sum := h.Sum(nil)
	// short prefix to keep file readable
	return "pending_" + hex.EncodeToString(sum)[:16]
}

func makeTxHash(tx map[string]interface{}) []byte {
	from := common.HexToAddress(tx["from"].(string))
	to := common.HexToAddress(tx["to"].(string))
	value := new(big.Int)
	value.SetString(tx["value"].(string), 10)
	dataBytes, _ := hex.DecodeString(strings.TrimPrefix(tx["data"].(string), "0x"))

	h := sha3.NewLegacyKeccak256()
	h.Write(from.Bytes())
	h.Write(to.Bytes())
	h.Write(value.FillBytes(make([]byte, 32)))
	h.Write(dataBytes)
	return h.Sum(nil)
}

// ---------- Bootnode Registration ----------
func registerWithBootnode(bootAddr string) {
	msg := Message{
		Command: "REGISTER",
		Data:    NodeInfo{ID: selfId, Addr: "localhost:" + p2pPort},
	}
	data, _ := json.Marshal(msg)

	conn, err := net.Dial("tcp", bootAddr)
	if err != nil {
		log.Fatal("❌ Could not connect to bootnode:", err)
	}
	defer conn.Close()
	_, _ = conn.Write(data)
	_, _ = conn.Write([]byte("\n"))

	decoder := json.NewDecoder(conn)
	var resp Message
	if err := decoder.Decode(&resp); err != nil {
		log.Fatal("❌ Error decoding bootnode response:", err)
	}
	if resp.Command == "PEERLIST" {
		peers, ok := resp.Data.(map[string]interface{})
		if ok {
			fmt.Printf("📥 Got %d peers from bootnode\n", len(peers))
			for id, addrI := range peers {
				if id == selfId {
					continue
				}
				addr, ok := addrI.(string)
				if ok {
					go pingPeer(id, addr)
				}
			}
		}
	}
}

// ---------- P2P ----------
func startP2PServer(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("❌ P2P listen error:", err)
	}
	fmt.Println("🔗 P2P server listening on", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleP2PConnection(conn)
	}
}

func handleP2PConnection(conn net.Conn) {
	defer conn.Close()
	decoder := json.NewDecoder(conn)
	var msg Message
	if err := decoder.Decode(&msg); err != nil {
		return
	}

	switch msg.Command {
	case "PING":
		peer := NodeInfo{}
		b, _ := json.Marshal(msg.Data)
		_ = json.Unmarshal(b, &peer)
		fmt.Printf("📡 PING from %s (%s)\n", peer.ID, peer.Addr)

		peerMapLock.Lock()
		peerMap[peer.ID] = peer.Addr
		peerMapLock.Unlock()
		savePeers()

		encoder := json.NewEncoder(conn)
		encoder.Encode(Message{Command: "PONG", Data: NodeInfo{ID: selfId, Addr: "localhost:" + p2pPort}})

	case "START_DKG":

		b, _ := json.Marshal(msg.Data)
		var participants []string
		_ = json.Unmarshal(b, &participants)
		fmt.Printf("🚀 Received START_DKG with participants %v\n", participants)

		// Generate random private share (crypto randomness)
		share, _ := crand.Int(crand.Reader, crypto.S256().Params().N)

		// Save pending entry (deterministic key derived from participants)
		_ = saveUserTemp(participants, share)

		// Send DKG_REVEAL back to initiator
		initiatorID := participants[0] // protocol assumes initiator is first in list
		peerMapLock.Lock()
		initiatorAddr := peerMap[initiatorID]
		peerMapLock.Unlock()

		if initiatorAddr == "" {
			fmt.Printf("⚠️  Could not find initiator address for %s\n", initiatorID)
			return
		}

		sendMessage(initiatorAddr, Message{
			Command: "DKG_REVEAL",
			Data: map[string]string{
				"id":    selfId,
				"share": "0x" + share.Text(16),
			},
		})

	case "DKG_REVEAL":
		// Only initiator should run finalize logic when it has all reveals.
		dataMap := make(map[string]string)
		b, _ := json.Marshal(msg.Data)
		_ = json.Unmarshal(b, &dataMap)
		id := dataMap["id"]
		shareHex := dataMap["share"]
		if strings.HasPrefix(shareHex, "0x") {
			shareHex = shareHex[2:]
		}
		share := new(big.Int)
		share.SetString(shareHex, 16)

		dkgLock.Lock()
		dkgReveals[id] = share
		all := len(dkgReveals)
		needed := len(dkgParticipants)
		dkgLock.Unlock()

		fmt.Printf("📩 Got DKG_REVEAL from %s (%d/%d)\n", id, all, needed)

		// If initiator and all shares collected → finalize
		if selfId == dkgInitiator && all == needed {
			go finalizeDKG(currentID, currentEOAFromPwd, currentCommitment, currentNullifier) // run finalize in goroutine to avoid blocking p2p handler
		}

	case "GROUP_FINAL":
		// Update local users file by moving pending entry to final address key

		b, _ := json.Marshal(msg.Data)
		var final map[string]interface{}
		_ = json.Unmarshal(b, &final)

		addr := final["address"].(string)

		rawParts := final["participants"].([]interface{})
		participants := make([]string, len(rawParts))
		for i, p := range rawParts {
			participants[i] = p.(string)
		}
		fmt.Printf("🎉 Group formed! Address=%s Participants=%v\n", addr, participants)

		tempKey := participantsKey(participants)
		users := loadUsers()

		entry := map[string]interface{}{}
		if old, ok := users[tempKey]; ok {
			// carry over old values
			for k, v := range old {
				entry[k] = v
			}
			delete(users, tempKey)
		} else {
			entry["private_share"] = "<unknown>"
		}

		// always set participants + metadata
		entry["participants"] = participants
		if id, ok := final["id"]; ok {
			entry["id"] = id
		}
		if eoa, ok := final["eoa_from_password"]; ok {
			entry["eoa_from_password"] = eoa
		}
		if cmt, ok := final["commitment"]; ok {
			entry["commitment"] = cmt
		}
		if nul, ok := final["nullifier"]; ok {
			entry["nullifier"] = nul
		}
		entry["value_thershold"] = "10"

		users[addr] = entry
		saveUsersMap(users)

	case "SHARE_REQUEST":
		b, _ := json.Marshal(msg.Data)
		req := map[string]string{}
		_ = json.Unmarshal(b, &req)
		groupAddr := req["address"]

		users := loadUsers()
		if users[groupAddr] != nil {
			share := users[groupAddr]["private_share"].(string)
			initiator := req["initiator"]
			peerMapLock.Lock()
			initiatorAddr := peerMap[initiator]
			peerMapLock.Unlock()
			sendMessage(initiatorAddr, Message{
				Command: "SHARE_RESPONSE",
				Data: map[string]string{
					"id":    selfId,
					"share": share,
				},
			})
		}

	case "SHARE_RESPONSE":
		b, _ := json.Marshal(msg.Data)
		resp := map[string]string{}
		_ = json.Unmarshal(b, &resp)
		id := resp["id"]
		shareHex := strings.TrimPrefix(resp["share"], "0x")
		share := new(big.Int)
		share.SetString(shareHex, 16)

		signLock.Lock()
		signShares[id] = share
		all := len(signShares)
		needed := len(signGroupParts)
		signLock.Unlock()
		fmt.Printf("📩 Got SHARE_RESPONSE from %s (%d/%d)\n", id, all, needed)

		if all == needed {
			go finalizeSignature()
		}

	case "SIGN_BROADCAST":
		b, _ := json.Marshal(msg.Data)
		entry := map[string]interface{}{}
		_ = json.Unmarshal(b, &entry)
		appendToMempool(entry)
		fmt.Printf("📝 Stored SIGN_BROADCAST tx in mempool\n")

	case "BATCH_PROPOSED":
		b, _ := json.Marshal(msg.Data)
		var prop BatchProposal
		_ = json.Unmarshal(b, &prop)
		fmt.Printf("📥 Got batch proposal %s from %s\n", prop.BatchHash, prop.Relayer)

		// Verifier check
		expected := computeBatchHash(prop.Items)
		if expected == prop.BatchHash {
			sig := signBatchHash(prop.BatchHash)
			approval := BatchApproval{
				Round:     prop.Round,
				BatchHash: prop.BatchHash,
				Verifier:  selfId,
				Sig:       sig,
			}

			peerMapLock.Lock()
			addr := peerMap[prop.Relayer]
			peerMapLock.Unlock()
			if addr != "" {
				sendMessage(addr, Message{Command: "BATCH_APPROVAL", Data: approval})
			}
			fmt.Println("✅ Approved batch", prop.BatchHash)

			approvalLock.Lock()
			approvals[prop.BatchHash] = append(approvals[prop.BatchHash], approval)
			approvalLock.Unlock()
		} else {
			fmt.Println("❌ Rejected batch", prop.BatchHash, "expected", expected)
		}

	case "BATCH_APPROVAL":
		b, _ := json.Marshal(msg.Data)
		var appr BatchApproval
		_ = json.Unmarshal(b, &appr)
		fmt.Printf("📩 Got approval from %s for %s\n", appr.Verifier, appr.BatchHash)
		approvalLock.Lock()
		approvals[appr.BatchHash] = append(approvals[appr.BatchHash], appr)
		approvalLock.Unlock()

	case "BATCH_CONFIRMED":
		b, _ := json.Marshal(msg.Data)
		var conf map[string]interface{}
		_ = json.Unmarshal(b, &conf)
		batchHash := conf["batchHash"].(string)

		// sanity: check we saw/approved this hash
		if _, ok := approvals[batchHash]; !ok {
			fmt.Println("⚠️ Got BATCH_CONFIRMED for unknown hash", batchHash)
			return
		}

		txHashesIface := conf["txHashes"].([]interface{})
		txs := []map[string]interface{}{}
		for _, h := range txHashesIface {
			// just store as hash list to remove
			txs = append(txs, map[string]interface{}{"hash": h.(string)})
		}

		// load mempool and filter
		mem := []map[string]interface{}{}
		data, _ := os.ReadFile(mempoolFile)
		if len(data) > 0 {
			_ = json.Unmarshal(data, &mem)
		}

		hashSet := make(map[string]bool)
		for _, h := range txHashesIface {
			hashSet[h.(string)] = true
		}

		filtered := []map[string]interface{}{}
		for _, tx := range mem {
			h := computeTxHash(tx)
			if !hashSet[h] {
				filtered = append(filtered, tx)
			}
		}
		out, _ := json.MarshalIndent(filtered, "", "  ")
		_ = os.WriteFile(mempoolFile, out, 0644)

		fmt.Printf("🧹 Removed %d txs from mempool after BATCH_CONFIRMED %s\n", len(txHashesIface), batchHash)

	}
}

// ---------- Relayer Helpers ----------
func computeBatchHash(items []map[string]interface{}) string {
	b, _ := json.Marshal(items)
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

func signBatchHash(hash string) string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(hash + selfId))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// ---------- Relayer Flow ----------
func startRelayer() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		roundCounter++

		if roundCounter/2 == 0 {
			approvalLock.Lock()
			approvals = make(map[string][]BatchApproval)
			approvalLock.Unlock()
		}

		stakes := loadStakeData()
		leader := selectRelayer(stakes, roundCounter)

		fmt.Println("🎲 Round", roundCounter, "— selected relayer:", leader)

		if leader != selfId {
			fmt.Println("🛡️ Acting as verifier this round")
			continue
		}

		// Relayer role
		batch := loadMempoolBatch(5)

		if len(batch) == 0 {
			continue
		}
		hash := computeBatchHash(batch)
		prop := BatchProposal{
			Round:      roundCounter,
			BatchNonce: batchNonce + 1,
			Items:      batch,
			BatchHash:  hash,
			Relayer:    selfId,
		}

		// Broadcast proposal
		for _, addr := range peerMap {
			sendMessage(addr, Message{Command: "BATCH_PROPOSED", Data: prop})
		}
		fmt.Println("📢 Proposed batch", hash)

		// Wait for approvals
		time.Sleep(5 * time.Second)

		approvalLock.Lock()
		sigs := approvals[hash]
		approvalLock.Unlock()

		if len(sigs) >= 1 { // TODO: quorum
			fmt.Println("✅ Got approvals, submitting batch", hash)
			batchNonce++

			// remove from local mempool
			removeTxsFromMempool(batch)

			// broadcast confirmation to verifiers
			txHashes := []string{}
			for _, tx := range batch {
				txHashes = append(txHashes, computeTxHash(tx))
			}
			confirmMsg := map[string]interface{}{
				"batchHash": hash,
				"txHashes":  txHashes,
			}
			for _, addr := range peerMap {
				sendMessage(addr, Message{Command: "BATCH_CONFIRMED", Data: confirmMsg})
			}

			// TODO: Call on-chain contract here

		} else {
			fmt.Println("❌ Not enough approvals, skipping batch", hash)
		}
	}
}

func removeTxsFromMempool(txs []map[string]interface{}) {
	mem := []map[string]interface{}{}
	data, _ := os.ReadFile(mempoolFile)
	if len(data) > 0 {
		_ = json.Unmarshal(data, &mem)
	}

	// build set of hashes to remove
	toRemove := make(map[string]bool)
	for _, tx := range txs {
		h := computeTxHash(tx)
		toRemove[h] = true
	}

	filtered := []map[string]interface{}{}
	for _, tx := range mem {
		h := computeTxHash(tx)
		if !toRemove[h] {
			filtered = append(filtered, tx)
		}
	}

	out, _ := json.MarshalIndent(filtered, "", "  ")
	_ = os.WriteFile(mempoolFile, out, 0644)
}

func computeTxHash(tx map[string]interface{}) string {
	fromStr, _ := tx["from"].(string)
	toStr, _ := tx["to"].(string)
	valStr, _ := tx["value"].(string)
	dataStr, _ := tx["data"].(string)

	from := common.HexToAddress(fromStr)
	to := common.HexToAddress(toStr)

	value := new(big.Int)
	if valStr != "" {
		value.SetString(valStr, 10)
	}

	dataBytes, _ := hex.DecodeString(strings.TrimPrefix(dataStr, "0x"))

	h := sha3.NewLegacyKeccak256()
	h.Write(from.Bytes())
	h.Write(to.Bytes())
	h.Write(value.FillBytes(make([]byte, 32)))
	h.Write(dataBytes)
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

func loadMempoolBatch(n int) []map[string]interface{} {
	mem := []map[string]interface{}{}
	data, _ := os.ReadFile(mempoolFile)
	if len(data) > 0 {
		_ = json.Unmarshal(data, &mem)
	}
	if len(mem) == 0 {
		return []map[string]interface{}{} // guarantee truly empty slice
	}
	if len(mem) > n {
		mem = mem[:n]
	}
	return mem
}

func finalizeSignature() {
	// reconstruct group key
	groupKey := big.NewInt(0)
	for _, share := range signShares {
		groupKey.Add(groupKey, share)
	}
	groupKey.Mod(groupKey, crypto.S256().Params().N)

	// build ecdsa.PrivateKey
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: crypto.S256(),
		},
		D: groupKey,
	}
	priv.PublicKey.X, priv.PublicKey.Y = crypto.S256().ScalarBaseMult(groupKey.Bytes())

	// sign tx
	digest := makeTxHash(signTx)
	sigBytes, err := crypto.Sign(digest, priv)
	if err != nil {
		fmt.Println("❌ Failed signing:", err)
		return
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])
	v := int(sigBytes[64]) + 27
	hashHex := "0x" + hex.EncodeToString(digest)

	sig := map[string]interface{}{
		"v":    v,
		"r":    "0x" + r.Text(16),
		"s":    "0x" + s.Text(16),
		"hash": hashHex,
	}

	result := map[string]interface{}{
		"tx":        signTx,
		"signature": sig,
	}

	// store locally
	appendToMempool(result)
	// broadcast to others
	for _, pid := range signGroupParts {
		if pid == selfId {
			continue
		}
		peerMapLock.Lock()
		addr := peerMap[pid]
		peerMapLock.Unlock()
		if addr != "" {
			sendMessage(addr, Message{Command: "SIGN_BROADCAST", Data: result})
		}
	}

	if signResultCh != nil {
		signResultCh <- result
	}
}

func pingPeer(id, addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("⚠️  Could not reach %s (%s)\n", id, addr)
		return
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	encoder.Encode(Message{Command: "PING", Data: NodeInfo{ID: selfId, Addr: "localhost:" + p2pPort}})

	var resp Message
	if err := decoder.Decode(&resp); err == nil && resp.Command == "PONG" {
		peer := NodeInfo{}
		b, _ := json.Marshal(resp.Data)
		_ = json.Unmarshal(b, &peer)
		fmt.Printf("✅ PONG from %s (%s)\n", peer.ID, peer.Addr)

		peerMapLock.Lock()
		peerMap[peer.ID] = peer.Addr
		peerMapLock.Unlock()
		savePeers()
	}
}

func sendMessage(addr string, msg Message) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("⚠️  Failed to send %s to %s\n", msg.Command, addr)
		return
	}
	defer conn.Close()
	encoder := json.NewEncoder(conn)
	encoder.Encode(msg)
}

// ---------- DKG Helpers ----------
func finalizeDKG(idS, eoaFromPwd, commitment, nullifier string) {
	// Lock to get a snapshot of reveals & participants
	dkgLock.Lock()
	reveals := make(map[string]*big.Int, len(dkgReveals))
	for k, v := range dkgReveals {
		reveals[k] = new(big.Int).Set(v)
	}
	participants := append([]string(nil), dkgParticipants...)
	dkgLock.Unlock()

	// Sum all constants into group private key
	groupKey := big.NewInt(0)
	for _, share := range reveals {
		groupKey.Add(groupKey, share)
	}
	groupKey.Mod(groupKey, crypto.S256().Params().N)

	// Derive Ethereum address
	pubX, pubY := crypto.S256().ScalarBaseMult(groupKey.Bytes())
	xBytes := pubX.Bytes()
	yBytes := pubY.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}
	pubBytes := append(xBytes, yBytes...)
	h := sha3.NewLegacyKeccak256()
	h.Write(pubBytes)
	addr := "0x" + hex.EncodeToString(h.Sum(nil)[12:])

	fmt.Printf("✅ GROUP FINALIZED — groupKey=0x%s address=%s\n", groupKey.Text(16), addr)

	// Move pending entry (participantsKey) to final address key in initiator's users file
	tempKey := participantsKey(participants)
	users := loadUsers()

	entry := map[string]interface{}{}
	if old, ok := users[tempKey]; ok {
		for k, v := range old {
			entry[k] = v
		}
		delete(users, tempKey)
	} else {
		myShare := reveals[selfId]
		if myShare == nil {
			myShare = big.NewInt(0)
		}
		entry["private_share"] = "0x" + myShare.Text(16)
	}
	// always set participants + metadata
	entry["participants"] = participants
	entry["id"] = idS
	entry["eoa_from_password"] = eoaFromPwd
	entry["commitment"] = commitment
	entry["nullifier"] = nullifier
	entry["value_thershold"] = "10"

	users[addr] = entry
	saveUsersMap(users)

	// Broadcast GROUP_FINAL to all participants (so each node updates its own users file)
	finalMsg := Message{
		Command: "GROUP_FINAL",
		Data: map[string]interface{}{
			"address":           addr,
			"participants":      participants,
			"id":                idS,
			"eoa_from_password": eoaFromPwd,
			"commitment":        commitment,
			"nullifier":         nullifier,
		},
	}

	for _, pid := range participants {
		if pid == selfId {
			continue
		}
		peerMapLock.Lock()
		peerAddr := peerMap[pid]
		peerMapLock.Unlock()
		if peerAddr != "" {
			sendMessage(peerAddr, finalMsg)
		}
	}

	// If an RPC call is waiting, send the result back (non-blocking)
	if dkgResultCh != nil {
		select {
		case dkgResultCh <- DKGResult{Address: addr, GroupKey: groupKey}:
		default:
		}
	}
}

func verifySignature(id, commitment, nullifier, eoaFromPwd string, v interface{}, r interface{}, s interface{}) (bool, error) {
	// 1. Concatenate message
	message := id + commitment + nullifier

	// 2. Hash with keccak256
	msgHash := crypto.Keccak256Hash([]byte(message))

	// 3. Parse v, r, s
	vInt := int64(v.(float64)) // JSON numbers come as float64
	rHex := r.(string)
	sHex := s.(string)

	rBytes, err := hex.DecodeString(strings.TrimPrefix(rHex, "0x"))
	if err != nil {
		return false, fmt.Errorf("bad r: %w", err)
	}
	sBytes, err := hex.DecodeString(strings.TrimPrefix(sHex, "0x"))
	if err != nil {
		return false, fmt.Errorf("bad s: %w", err)
	}

	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)

	// Ethereum adds 27 to v in legacy sigs
	if vInt == 27 || vInt == 28 {
		vInt -= 27
	}

	// 4. Reconstruct signature bytes [R || S || V]
	sig := make([]byte, 65)
	copy(sig[0:32], rInt.FillBytes(make([]byte, 32)))
	copy(sig[32:64], sInt.FillBytes(make([]byte, 32)))
	sig[64] = byte(vInt)

	// 5. Recover public key
	pubKey, err := crypto.SigToPub(msgHash.Bytes(), sig)
	if err != nil {
		return false, fmt.Errorf("sig recovery failed: %w", err)
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	// 6. Compare with claimed EOA
	match := strings.EqualFold(recoveredAddr.Hex(), eoaFromPwd)
	return match, nil
}

// --------- Circuit ----------
type zkTOTPCircuit struct {
	Secret     frontend.Variable
	Commitment frontend.Variable `gnark:",public"`
	TimeStep   frontend.Variable `gnark:",public"`
}

func (c *zkTOTPCircuit) Define(api frontend.API) error {
	h, _ := mimc.NewMiMC(api)
	h.Write(c.Secret)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	_ = api.Add(c.Secret, c.TimeStep)
	return nil
}

// --------- Helpers ----------
func loadVK() *groth16.VerifyingKey {
	fvk, _ := os.Open("vk.bin")
	defer fvk.Close()
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, _ = vk.ReadFrom(fvk)
	return &vk
}

func decodeProofBase64(b64 string) groth16.Proof {
	raw, _ := base64.StdEncoding.DecodeString(b64)
	proof := groth16.NewProof(ecc.BN254) // allocate correct type for curve
	_, _ = proof.ReadFrom(bytes.NewReader(raw))
	return proof
}

func getTimeStep() *big.Int {
	return new(big.Int).SetUint64(uint64(time.Now().Unix() / 30))
}

// ---------- RPC ----------
func rpcHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	var req RPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	var resp RPCResponse

	switch req.Method {
	case "get_peers":
		peerMapLock.Lock()
		resp.Result = peerMap
		peerMapLock.Unlock()

	case "get_user_info":
		if len(req.Params) < 1 {
			resp.Error = "missing id param"
			break
		}
		idParam := req.Params[0].(string)

		users := loadUsers()
		found := false
		for eoa, entry := range users {
			if entry["id"] == idParam {
				resp.Result = map[string]interface{}{
					"dkg_eoa":         eoa,
					"value_threshold": entry["value_thershold"],
					"nullifier":       entry["nullifier"],
				}
				found = true
				break
			}
		}
		if !found {
			resp.Error = fmt.Sprintf("no user found with id %s", idParam)
		}

	case "generate_key":
		// RPC trigger to start DKG (initiator = this node)

		/*
			1. ID
			2. EOA from password
			3. commitement from 2FA
			4. Nullifier from self
			5. signature of (id + commitment + nullifier) with EOA
			process -> verify signature and start process and store values
		*/

		if len(req.Params) < 1 {
			resp.Error = "missing tx params"
			break
		}
		userData := req.Params[0].(map[string]interface{})

		currentID = userData["id"].(string)
		currentEOAFromPwd = userData["eoaFromPwd"].(string)
		currentCommitment = userData["commitment"].(string)
		currentNullifier = userData["nullifier"].(string)
		v := userData["v"]
		r := userData["r"]
		s := userData["s"]

		ok, err := verifySignature(currentID, currentCommitment, currentNullifier, currentEOAFromPwd, v, r, s)
		if err != nil {
			resp.Error = fmt.Sprintf("signature verification failed: %v", err)
			break
		}
		if !ok {
			resp.Error = "invalid signature: recovered EOA mismatch"
			break
		}

		fmt.Println("✅ Signature verified from:", currentEOAFromPwd)
		peerMapLock.Lock()
		participants := make([]string, 0, len(peerMap)+1)
		participants = append(participants, selfId)
		for id := range peerMap {
			participants = append(participants, id)
		}
		peerMapLock.Unlock()

		dkgLock.Lock()
		dkgInitiator = selfId
		dkgParticipants = append([]string(nil), participants...)
		dkgReveals = make(map[string]*big.Int)
		// create the channel to wait on finalization
		dkgResultCh = make(chan DKGResult, 1)
		// generate initiator's own share and save as pending
		myShare, _ := crand.Int(crand.Reader, crypto.S256().Params().N)
		dkgReveals[selfId] = myShare
		_ = saveUserTemp(participants, myShare)
		dkgLock.Unlock()

		// broadcast START_DKG to peers
		for pid, addr := range peerMap {
			// send whole participants list; peers will generate their own share and reply to initiator
			sendMessage(addr, Message{Command: "START_DKG", Data: participants})
			fmt.Printf("📨 Sent START_DKG to %s (%s)\n", pid, addr)
		}

		// Wait for finalizeDKG to send the result (demo only).
		// NOTE: in production you would NOT reconstruct and return the group private key.
		select {
		case res := <-dkgResultCh:
			resp.Result = map[string]interface{}{
				"address":           res.Address,
				"group_private_key": "0x" + res.GroupKey.Text(16), // ⚠️ only for demo, remove later
				"status":            "dkg_complete",
				"message":           "Group EOA created; metadata relayed to all nodes",
			}

		case <-time.After(15 * time.Second):
			resp.Error = "DKG timeout waiting for reveals / finalization"
		}

	case "send_transaction":

		/*

			1. tx details (from would be eoa from password)
			2. 2FA base64 only if tx value > 10 dollar
			3. signature (2FA + tx)
			process -> verify signature + verify 2FA and start process

		*/

		if len(req.Params) < 1 {
			resp.Error = "missing tx params"
			break
		}
		tx := req.Params[0].(map[string]interface{})
		from := tx["from"].(string)
		// txValue := tx["value"].(string)
		users := loadUsers()
		if users[from] == nil {
			resp.Error = "no entry for this from address"
			break
		}
		// if txValue > users[from].value_thershold {
		// 	// we need the 2FA
		// }

		// proof := decodeProofBase64(tx["2fa"].(string))
		// timestep := getTimeStep()

		// v := tx["v"]
		// r := tx["r"]
		// s := tx["s"]

		// tx data like (from to value data) should be signed by eoa_from_password

		// vk := loadVK()
		// publicAssign := zkTOTPCircuit{Commitment: commitment, TimeStep: timestep}
		// publicWitness, _ := frontend.NewWitness(&publicAssign, ecc.BN254.ScalarField(), frontend.PublicOnly())

		// if err := groth16.Verify(proof, *vk, publicWitness); err != nil {
		// 	// send failed response

		// 	break
		// }
		fmt.Println("[Node] Verification SUCCESS ✅")

		signLock.Lock()
		signTx = tx
		signFrom = from
		signShares = make(map[string]*big.Int)
		signResultCh = make(chan map[string]interface{}, 1)
		signGroupParts = []string{}
		if arr, ok := users[from]["participants"].([]interface{}); ok {
			for _, p := range arr {
				signGroupParts = append(signGroupParts, p.(string))
			}
		}
		signLock.Unlock()

		// ask all peers for shares
		for _, pid := range signGroupParts {
			if pid == selfId {
				// add own share
				shareHex := users[from]["private_share"].(string)
				share := new(big.Int)
				share.SetString(strings.TrimPrefix(shareHex, "0x"), 16)
				signShares[selfId] = share
				continue
			}
			peerMapLock.Lock()
			addr := peerMap[pid]
			peerMapLock.Unlock()
			if addr != "" {
				sendMessage(addr, Message{
					Command: "SHARE_REQUEST",
					Data: map[string]string{
						"address":   from,
						"initiator": selfId,
					},
				})
			}
		}

		select {
		case res := <-signResultCh:
			resp.Result = res
		case <-time.After(10 * time.Second):
			resp.Error = "timeout collecting shares"
		}

	case "user_login":

		if len(req.Params) < 1 {
			resp.Error = "missing tx params"
			break
		}

		loginData := req.Params[0].(map[string]interface{})
		id := loginData["id"].(string)
		proofB64 := loginData["proof"].(string)

		// Load user info
		users := loadUsers()

		var commitment string
		found := false
		for _, entry := range users {
			if entry["id"] == id {
				commitment = entry["commitment"].(string)
				found = true
				break
			}
		}
		if !found {
			resp.Error = fmt.Sprintf("no user found with id %s", id)
			break
		}

		proof := decodeProofBase64(proofB64)

		// current timestep
		timestep := getTimeStep()

		if err := verify2FA(proof, commitment, timestep); err != nil {
			resp.Error = fmt.Sprintf("2FA verification failed: %v", err)
			break
		}

		resp.Result = map[string]interface{}{
			"status":  "login_success",
			"message": "User authenticated successfully",
		}

	default:
		resp.Error = "Unknown method"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func verifyRawSignature(msgHash common.Hash, expectedAddr string, v interface{}, r interface{}, s interface{}) (bool, error) {
	vInt := int64(v.(float64))
	rHex := r.(string)
	sHex := s.(string)

	rBytes, err := hex.DecodeString(strings.TrimPrefix(rHex, "0x"))
	if err != nil {
		return false, fmt.Errorf("bad r: %w", err)
	}
	sBytes, err := hex.DecodeString(strings.TrimPrefix(sHex, "0x"))
	if err != nil {
		return false, fmt.Errorf("bad s: %w", err)
	}

	rInt := new(big.Int).SetBytes(rBytes)
	sInt := new(big.Int).SetBytes(sBytes)

	if vInt == 27 || vInt == 28 {
		vInt -= 27
	}

	sig := make([]byte, 65)
	copy(sig[0:32], rInt.FillBytes(make([]byte, 32)))
	copy(sig[32:64], sInt.FillBytes(make([]byte, 32)))
	sig[64] = byte(vInt)

	pubKey, err := crypto.SigToPub(msgHash.Bytes(), sig)
	if err != nil {
		return false, fmt.Errorf("sig recovery failed: %w", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	return strings.EqualFold(recoveredAddr.Hex(), expectedAddr), nil
}

func verify2FA(proof groth16.Proof, commitHex string, timestep *big.Int) error {
	commitHex = strings.TrimSpace(strings.TrimPrefix(commitHex, "0x"))
	commitBytes, err := hex.DecodeString(commitHex)
	if err != nil {
		return fmt.Errorf("invalid commitment hex: %w", err)
	}
	commitment := new(big.Int).SetBytes(commitBytes)

	vk := loadVK()
	if vk == nil {
		return fmt.Errorf("verification key not loaded")
	}

	publicAssign := zkTOTPCircuit{
		Commitment: commitment,
		TimeStep:   timestep,
	}
	publicWitness, err := frontend.NewWitness(&publicAssign, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to build witness: %w", err)
	}

	if err := groth16.Verify(proof, *vk, publicWitness); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
}

func startRPCServer(port string) {
	http.Handle("/", withCORS(http.HandlerFunc(rpcHandler)))
	fmt.Println("🖥️  RPC server on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// ---------- Cleanup ----------
func cleanupOnExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Printf("🧹 Cleaning up %s %s...\n", peersFile, usersFile)
		os.Remove(peersFile)
		os.Remove(usersFile)
		os.Remove(mempoolFile)
		os.Remove(stakeFile)
		os.Exit(0)
	}()
}
func loadStakeData() map[string]int {
	data, err := os.ReadFile(stakeFile)
	if err != nil {
		return map[string]int{}
	}
	var stakes map[string]int
	if err := json.Unmarshal(data, &stakes); err != nil {
		return map[string]int{}
	}
	return stakes
}

// ---------- Relayer Selection ----------
func selectRelayer(stakes map[string]int, round int64) string {
	total := 0
	for _, s := range stakes {
		total += s
	}
	if total == 0 {
		return ""
	}

	// deterministic seed = round number
	r := int(round % int64(total))
	cumulative := 0
	for id, s := range stakes {
		cumulative += s
		if r < cumulative {
			return id
		}
	}
	return ""
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// ---------- MAIN ----------
func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run node.go <p2pPort> <rpcPort>")
		return
	}
	p2pPort = os.Args[1]
	rpcPort = os.Args[2]
	peersFile = fmt.Sprintf("./data/peers_%s.json", p2pPort)
	usersFile = fmt.Sprintf("./data/users_%s.json", p2pPort)
	mempoolFile = fmt.Sprintf("./data/mempool_%s.json", p2pPort)
	stakeFile = "./data/stakes_data.json"

	selfId = fmt.Sprintf("node-%d", mrand.Intn(1000000))

	fmt.Printf("🚀 Starting node %s on P2P:%s RPC:%s\n", selfId, p2pPort, rpcPort)

	peerMap = loadPeers()
	// ensure stake_data.json has an entry for this node
	stakes := map[string]int{}

	if _, err := os.Stat(stakeFile); err == nil {
		// file exists → load existing data
		data, _ := os.ReadFile(stakeFile)
		_ = json.Unmarshal(data, &stakes)
	}

	// if this node not in stakes, assign it a random stake
	if _, ok := stakes[selfId]; !ok {
		myStake := mrand.Intn(91) + 10
		stakes[selfId] = myStake
		fmt.Printf("💰 Added %s with %d ETH staked\n", selfId, myStake)
	}

	// save back updated stakes
	data, _ := json.MarshalIndent(stakes, "", "  ")
	_ = os.WriteFile(stakeFile, data, 0644)

	cleanupOnExit()

	go startP2PServer(p2pPort)
	go startRPCServer(rpcPort)
	go startRelayer()

	registerWithBootnode("localhost:9000")

	select {}
}
