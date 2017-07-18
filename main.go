package main

import (
	"fmt"

	"github.com/NebulousLabs/Sia/crypto"
	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/types"
)

func getAddress(seed modules.Seed) (esk crypto.SecretKey, epk crypto.PublicKey, add types.UnlockHash) {
	esk, epk = crypto.GenerateKeyPairDeterministic(seed)
	add = types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{types.Ed25519PublicKey(epk)},
		SignaturesRequired: 1,
	}.UnlockHash()
	return
}

func main() {
	var seed modules.Seed
	seedStr := "paper hard ripple dwarf wise ski salute middle crouch stuff broom paper"
	seedBytes := []byte(seedStr)
	seed = modules.Seed(crypto.HashBytes(seedBytes))
	esk, epk, add := getAddress(seed)
	finalSeedStr, _ := modules.SeedToString(seed, "english")
	fmt.Println("Raw Seed:", seed)
	fmt.Println("English Seed:", finalSeedStr)
	fmt.Println("ESK:", esk)
	fmt.Println("EPK:", epk)
	fmt.Println("Address:", add)
}
