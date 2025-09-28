
# 🚀 Zeno Project Node

This project implements a **decentralized MPC-TSS relayer network** with:

- **P2P communication** between nodes.
- **Distributed Key Generation (DKG)** for group Ethereum addresses.
- **Threshold Signing (TSS)** for transactions.
- **zk-TOTP (zk-SNARK-based 2FA)** for secure, privacy-preserving login and transaction approvals.
- **On-chain batch relay contract** for efficient Ethereum submissions.
- **JSON-RPC interface** for frontend integration.

Users don’t manage private keys directly. Instead, the network collaboratively generates and reconstructs them using **threshold cryptography**, adding **2FA verification** for high-value operations.

---

## ⚡ System Components

### 👤 User & Frontend

- Users interact via a **React frontend**.
- Provides **ID, password-derived EOA, and zk-TOTP proofs**.
- Calls backend via **JSON-RPC HTTP API**.

### 🌐 P2P Network

- Nodes discover each other through a **bootnode**.
- Exchange JSON-encoded messages over TCP:

  - `PING` / `PONG` → liveness checks.
  - `START_DKG`, `DKG_REVEAL`, `GROUP_FINAL` → distributed key generation.
  - `SHARE_REQUEST`, `SHARE_RESPONSE` → collect shares for threshold signatures.
  - `SIGN_BROADCAST` → share signed txs.
  - `BATCH_PROPOSED`, `BATCH_APPROVAL`, `BATCH_CONFIRMED` → batch consensus & confirmation.
  - `PASSWORD_RECOVERY` → issuer-authorized recovery across nodes.

### 🔑 DKG / Threshold Signing

- Each node generates a **random private share**.
- Shares are combined → **group private key** → corresponding **Ethereum address**.
- For signing:

  - Each peer provides its share.
  - Shares are aggregated → group key reconstructs temporarily → used for **ECDSA signing**.
  - Signed txs are broadcasted back into the P2P mempool.

### 📦 Mempool

- Local JSON file acts as mempool for pending txs.
- Stores both **signed txs** and **signatures**.
- Pruned on `BATCH_CONFIRMED`.

### ⛓️ Relayer Module

- Every round, one leader is chosen deterministically (using **block hash + round index**).
- Leader collects up to **N txs** from mempool, builds a **batch**, and submits via:

  ```solidity
  sendBatch(Tx[] batch)
  ```

- Batch hash + tx hashes are broadcasted across P2P.

### 🔐 zk-TOTP 2FA

- Uses **MiMC commitment** scheme inside zk-SNARK circuit.
- Users prove they know a secret TOTP without revealing it.
- Verified using gnark’s **Groth16 verifier** with BN254 curve.
- Enforced condition:

  - Tx value > threshold → **zk proof required**.
  - Otherwise → password signature is enough.

### 🖥️ RPC Server

Exposes JSON-RPC methods over HTTP:

- `get_peers` → return peer map.
- `get_user_info(id)` → return user metadata.
- `generate_key(userData)` → starts DKG, forms group address.
- `send_transaction(tx)` → verifies sig + 2FA, requests shares, signs, broadcasts.
- `user_login(proof)` → zk-TOTP login verification.
- `recover_password(id, newEOA, sig)` → issuer-signed recovery flow.

Includes **CORS support** → allows browser frontend to connect.

---

## 🔄 Data Flow (Example: Send Transaction)

1. User signs tx with their **password-derived EOA**.
2. If value > threshold:

   - User generates zk-TOTP proof → sent to backend.

3. RPC verifies:

   - Signature matches claimed EOA.
   - zk proof validates 2FA.

4. Backend requests **shares** from peers.
5. Shares aggregated → tx signed with group key.
6. Signed tx stored in mempool + broadcasted.
7. Leader relayer eventually batches txs → submits on-chain.

---

## 🛠️ Tech Stack

- **Go**: Networking, cryptography, zk proof verification.
- **Gnark**: zk-SNARKs (Groth16, BN254).
- **go-ethereum**: ECDSA, ABI encoding, Ethereum client.
- **React**: Frontend interaction with RPC API.
- **Polygon Amoy Testnet**: On-chain deployment of relayer contract.

---

## 🔒 Security Model

- **Threshold cryptography**: No single node holds full key.
- **zk-TOTP**: Proof of valid OTP without revealing secret.
- **Issuer-based recovery**: Controlled password reset mechanism.
- **Batch relay**: Reduces on-chain exposure and gas fees.
