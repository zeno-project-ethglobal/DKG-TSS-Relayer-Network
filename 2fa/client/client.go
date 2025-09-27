package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const bn254ModulusDec = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

type zkTOTPCircuit struct {
	Secret     frontend.Variable
	Commitment frontend.Variable `gnark:",public"`
	TimeStep   frontend.Variable `gnark:",public"`
}

func (c *zkTOTPCircuit) Define(api frontend.API) error {
	h, _ := mimc.NewMiMC(api)
	h.Write(c.Secret)
	hashOut := h.Sum()
	api.AssertIsEqual(hashOut, c.Commitment)
	_ = api.Add(c.Secret, c.TimeStep)
	return nil
}

// Helpers
func genSecret() *big.Int {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := new(big.Int).SetBytes(b)
	r := new(big.Int)
	r.SetString(bn254ModulusDec, 10)
	return secret.Mod(secret, r)
}
func computeCommitment(secret *big.Int) *big.Int {
	h := mimcNative.NewMiMC()
	input := make([]byte, 32)
	b := secret.Bytes()
	copy(input[32-len(b):], b)
	h.Write(input)
	return new(big.Int).SetBytes(h.Sum(nil))
}
func getTimeStep() *big.Int {
	return new(big.Int).SetUint64(uint64(time.Now().Unix() / 30))
}

// exportProofBase64: serialize proof using WriteTo, then base64
func exportProofBase64(proof groth16.Proof) string {
	var buf bytes.Buffer
	_, _ = proof.WriteTo(&buf)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func main() {
	fmt.Println("=== zk-TOTP Client ===")
	fmt.Println("Commands:")
	fmt.Println("  register  -> create secret + commitment, save secret locally")
	fmt.Println("  proof     -> generate zk proof for current timestep")
	fmt.Println("  exit      -> quit client")

	// Load pk once
	fpk, err := os.Open("pk.bin")
	if err != nil {
		fmt.Println("ERROR: pk.bin not found. Run setup first.")
		return
	}
	defer fpk.Close()
	pk := groth16.NewProvingKey(ecc.BN254)
	_, _ = pk.ReadFrom(fpk)

	// Load ccs once
	fccs, err := os.Open("ccs.bin")
	if err != nil {
		fmt.Println("ERROR: ccs.bin not found. Run setup first.")
		return
	}
	defer fccs.Close()
	ccs := groth16.NewCS(ecc.BN254)
	_, _ = ccs.ReadFrom(fccs)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("\n> ")
		if !scanner.Scan() {
			break
		}
		cmd := strings.TrimSpace(scanner.Text())
		switch cmd {
		case "register":
			secret := genSecret()
			commitment := computeCommitment(secret)
			// save secret
			_ = os.WriteFile("secret.hex", []byte(hex.EncodeToString(secret.Bytes())), 0600)
			fmt.Println("[REGISTER]")
			fmt.Println("  Commitment (hex):", hex.EncodeToString(commitment.Bytes()))
			fmt.Println("  Secret (private, saved to secret.hex):", secret.String())

		case "proof":
			secretHex, err := os.ReadFile("secret.hex")
			if err != nil {
				fmt.Println("ERROR: no secret found. Run register first.")
				continue
			}
			secretBytes, _ := hex.DecodeString(string(secretHex))
			secret := new(big.Int).SetBytes(secretBytes)
			commitment := computeCommitment(secret)
			timestep := getTimeStep()
			fmt.Println("timestamp : ", timestep)

			// build witness
			assign := zkTOTPCircuit{Secret: secret, Commitment: commitment, TimeStep: timestep}
			witness, _ := frontend.NewWitness(&assign, ecc.BN254.ScalarField())

			// generate proof with saved ccs + pk
			proof, _ := groth16.Prove(ccs, pk, witness)

			fmt.Println("[PROOF]")
			fmt.Println("  Commitment (hex):", hex.EncodeToString(commitment.Bytes()))
			fmt.Println("  Timestep:", timestep.String())
			fmt.Println("  Proof (base64):", exportProofBase64(proof))

		case "exit", "quit":
			fmt.Println("Exiting client.")
			return
		default:
			fmt.Println("Unknown command. Use register | proof | exit")
		}
	}
}
