package main

import (
	"flag"
	"fmt"

	"github.com/Zenoglyphs-VM/zvm-core/devnet"
)

func init() {
	register("sign", "sign a message with a dev Zenon key, the way the Syrius extension does", runSign)
}

// runSign answers with what `window.zenon.signMessage` answers with: the
// address, the public key and an Ed25519 signature over the raw message bytes.
// It exists so a test can stand in for the extension, which cannot be driven
// without a person typing a password into its own window.
func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	index := fs.Uint("index", devnet.DevOwner, "dev mnemonic index to sign with")
	message := fs.String("message", "", "the message, as UTF-8 text")
	fs.Parse(args)

	if *message == "" {
		return fmt.Errorf("-message is empty")
	}
	if len([]byte(*message)) == 32 {
		// The same refusal the extension makes: 32 bytes is the size of an
		// account block hash, so signing one could be signing a transaction.
		return fmt.Errorf("a 32-byte message is the size of an account block hash; Syrius refuses to sign one")
	}
	key := devnet.Key(uint32(*index))
	fmt.Printf("address     %s\n", key.Address)
	fmt.Printf("publicKey   %x\n", key.Public)
	fmt.Printf("signature   %x\n", key.Sign([]byte(*message)))
	return nil
}
