package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
)

// Address type for json encoding
type Address struct {
	Seed modules.Seed     `json:"seed"`
	Esk  crypto.SecretKey `json:"esk"`
	Epk  crypto.PublicKey `json:"epk"`
	Add  types.UnlockHash `json:"address"`
}

// TestVectors is the form of overall json output
type TestVectors struct {
	SeedStr         string       `json:"seedStr"`
	SeedBytes       []byte       `json:"seedBytes"`
	SeedEng         string       `json:"seedEng"`
	SeedHashed      modules.Seed `json:"seedHashed"`
	DerivedAdresses []Address    `json:"derivedAddresses"`
}

func getAddress(seed modules.Seed) (esk crypto.SecretKey, epk crypto.PublicKey, add types.UnlockHash) {
	esk, epk = crypto.GenerateKeyPairDeterministic(seed)
	add = types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{types.Ed25519PublicKey(epk)},
		SignaturesRequired: 1,
	}.UnlockHash()
	return
}

func main() {
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose?")
	flag.Parse()
	var testVectors TestVectors
	testVectors.SeedStr = "paper hard ripple dwarf wise ski salute middle crouch stuff broom"
	testVectors.SeedBytes = []byte(testVectors.SeedStr)
	testVectors.SeedHashed = modules.Seed(crypto.HashBytes(testVectors.SeedBytes))
	testVectors.SeedEng, _ = modules.SeedToString(testVectors.SeedHashed, "english")
	if verbose {
		fmt.Println("::: ::: Master seed")
		fmt.Println("::: String:", testVectors.SeedStr)
		fmt.Println("::: Bytes:", testVectors.SeedBytes)
		fmt.Println("::: Hashed:", testVectors.SeedHashed)
		fmt.Println("::: English:", testVectors.SeedEng)
		fmt.Println(":::")
		fmt.Println(":::")
	}
	var addresses []Address
	for i := uint64(0); i < 20; i++ {
		s := modules.Seed(crypto.HashAll(testVectors.SeedHashed, i))
		esk, epk, add := getAddress(s)
		addresses = append(addresses, Address{Seed: s, Esk: esk, Epk: epk, Add: add})
		if verbose {
			fmt.Println("::: ::: Address", i)
			fmt.Println("::: Hashed Seed:", s)
			fmt.Println("::: ESK:", esk)
			fmt.Println("::: EPK:", epk)
			fmt.Println("::: Address:", add)
			fmt.Println(":::")
			fmt.Println(":::")
		}
	}
	testVectors.DerivedAdresses = addresses
	j, err := json.Marshal(testVectors)
	if err != nil {
		fmt.Println(err)
	}
	if !verbose {
		fmt.Print(string(j))
	}
}
