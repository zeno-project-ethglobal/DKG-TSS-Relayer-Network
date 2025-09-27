// setup.go
package main

import (
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

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

func main() {

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zkTOTPCircuit{})
	pk, vk, _ := groth16.Setup(ccs)

	fpk, _ := os.Create("pk.bin")
	pk.WriteTo(fpk)
	fpk.Close()

	fvk, _ := os.Create("vk.bin")
	vk.WriteTo(fvk)
	fvk.Close()

	fccs, _ := os.Create("ccs.bin")
	ccs.WriteTo(fccs) // <-- save the circuit too
	fccs.Close()

}
