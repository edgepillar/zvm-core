package znn

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// The ten addresses go-zenon's devnet README derives from its committed
// mnemonic. Matching all of them checks the BIP-39 seed, SLIP-0010 and the
// address hash in one go.
func TestDevWalletMatchesDevnetREADME(t *testing.T) {
	want := []string{
		"z1qq9n7fpaqd8lpcljandzmx4xtku9w4ftwyg0mq",
		"z1qq6eg8n43g032hanpsfp02qcdmv7zfj3y2lt5d",
		"z1qzmzssx28dc0fmvlca05hyxk2kgkgu7n0cj8pl",
		"z1qp3yph55qgresyytz83anynr2f4z39x2z3ej3e",
		"z1qz9zr5c7a0p8qljvrwt2cy5j99w98c5myrn2un",
		"z1qqleq9qc2u3039fly4ld5qgngdeapa3yks0e3l",
		"z1qzedcjmds6cwuqu7wkrvl0dadwwauzaana6g8e",
		"z1qq8gll9ey70nym5cjxjqcegymw0g8a4je6kwes",
		"z1qpeet8dcjg0m6x6m3tg437wnc42aa2nez2fzth",
		"z1qqcam4ycu0ta8333hx38r5j2z3ry9jjfxkc7t5",
	}
	w := MustDevWallet()
	for i, s := range want {
		if got := w.Key(uint32(i)).Address.String(); got != s {
			t.Errorf("index %d: got %s, want %s", i, got, s)
		}
	}
}

func TestKnownEncodings(t *testing.T) {
	if got := ZeroAddress.String(); got != "z1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsggv2f" {
		t.Errorf("zero address: %s", got)
	}
	if got := ZeroTokenStandard.String(); got != "zts1qqqqqqqqqqqqqqqqtq587y" {
		t.Errorf("zero token standard: %s", got)
	}
	plasma := MustParseAddress("z1qxemdeddedxplasmaxxxxxxxxxxxxxxxxsctrp")
	if !plasma.IsEmbedded() || plasma.IsUser() {
		t.Errorf("plasma contract should be embedded")
	}
	for _, s := range []string{"zts1znnxxxxxxxxxxxxx9z4ulx", "zts1qsrxxxxxxxxxxxxxmrhjll"} {
		if MustParseZTS(s).String() != s {
			t.Errorf("round trip %s", s)
		}
	}
}

func TestChecksumIsChecked(t *testing.T) {
	good := "z1qq6eg8n43g032hanpsfp02qcdmv7zfj3y2lt5d"
	bad := strings.Replace(good, "qq6eg", "qq6ef", 1)
	if _, err := ParseAddress(bad); err == nil {
		t.Fatal("a mistyped address decoded")
	}
}

// A real user send off the go-zenon devnet (chain 69), read with
// ledger.getDetailedMomentumsByHeight on 2026-09-14: pillar 2's producer
// calling the accelerator contract.
const devnetSend = `{
  "version": 1, "chainIdentifier": 69, "blockType": 2,
  "hash": "b4c290f2e5e5678303d9528fcb3052572b7eccb9d53fe65982217cb4ead031bc",
  "previousHash": "dd4091a2872f48cc4a35b782995b5c1cd45838771e21106ed37dba6df170d0aa",
  "height": 414,
  "momentumAcknowledged": {"hash": "789fac148ccba814c061baa316273a00af850b9fd86b1e20d298334bab706521", "height": 81989},
  "address": "z1qz9zr5c7a0p8qljvrwt2cy5j99w98c5myrn2un",
  "toAddress": "z1qxemdeddedxaccelerat0rxxxxxxxxxxp4tk22",
  "amount": "0",
  "tokenStandard": "zts1qqqqqqqqqqqqqqqqtq587y",
  "fromBlockHash": "0000000000000000000000000000000000000000000000000000000000000000",
  "descendantBlocks": [],
  "data": "IAk+pg==",
  "fusedPlasma": 73500, "difficulty": 0, "nonce": "0000000000000000",
  "basePlasma": 73500, "usedPlasma": 73500,
  "changesHash": "7725fb05f8416761b28535f0abe3d6a25376f962274d369086314fa9b4f86e3e",
  "publicKey": "2GygalQtICU0kKLE/eZAwHbSSSBQ/o4NfZT/KjK6tG4=",
  "signature": "kvbDlo9kC7+RDux+cVL66KeK34opN0vTkz/ugMXy/YFSH6WvnO9FJATrDD9wT60UlUZ45DEYCc32WeYlmFVsDQ==",
  "token": null,
  "confirmationDetail": {"numConfirmations": 155, "momentumHeight": 81990, "momentumHash": "3526c20cfda56a5b84480d706e17217300099bf2ce08946a8fdd9505fffb7590", "momentumTimestamp": 1789438800},
  "pairedAccountBlock": null
}`

func TestDevnetBlockHashAndSignature(t *testing.T) {
	var b AccountBlock
	if err := json.Unmarshal([]byte(devnetSend), &b); err != nil {
		t.Fatal(err)
	}
	if got := b.ComputeHash(); got != b.Hash {
		t.Fatalf("hash: got %s, want %s", got, b.Hash)
	}
	if err := b.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSignRoundTrip(t *testing.T) {
	k := MustDevWallet().Key(100)
	b := &AccountBlock{
		Version: 1, ChainIdentifier: 70, BlockType: BlockTypeUserSend, Height: 1,
		Address: k.Address, ToAddress: MustDevWallet().Key(101).Address,
		Amount: BigIntFromUint64(12345), TokenStandard: ZNN, Data: []byte{1, 2, 3},
		FusedPlasma: BaseSendPlasma(3), DescendantBlocks: []*AccountBlock{},
	}
	b.Sign(k)
	if err := b.Verify(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var back AccountBlock
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ComputeHash() != b.Hash {
		t.Fatal("hash changed across a JSON round trip")
	}
}

func TestPoW(t *testing.T) {
	h := PoWDataHash(MustDevWallet().Key(1).Address, ZeroHash)
	const difficulty = 20_000
	n, err := GeneratePoW(context.Background(), difficulty, h)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPoW(difficulty, h, n) {
		t.Fatal("generated nonce does not check")
	}
}

func TestFusionPriceCoversBothRulesets(t *testing.T) {
	// A v1 momentum carries no price at all.
	var v1 Momentum
	if got := v1.FusionPrice(); got != PriceScaleFactor {
		t.Fatalf("a v1 momentum asks the minimum price, got %d", got)
	}
	// A v2 momentum never goes below the minimum either.
	low := uint64(500)
	if got := (&Momentum{Version: 2, NextFusionPrice: &low}).FusionPrice(); got != PriceScaleFactor {
		t.Fatalf("a price below the minimum reads as the minimum, got %d", got)
	}
	busy := uint64(2500)
	if got := (&Momentum{Version: 2, NextFusionPrice: &busy}).FusionPrice(); got != 2500 {
		t.Fatalf("a v2 price is used as given, got %d", got)
	}
}

func TestMaxFusedAmountFollowsTheRuleset(t *testing.T) {
	v1 := MaxFusedAmountForAccount(&Momentum{Version: 1})
	if want := new(big.Int).Mul(big.NewInt(5_000), OneQSR); v1.Cmp(want) != 0 {
		t.Fatalf("mainnet's rules cap an account at 5,000 QSR, got %s", v1)
	}
	// Dynamic plasma raises go-zenon's own constant by four orders of
	// magnitude, so the v1 figure is not a ceiling on such a network. Measured
	// on the shared devnet 2026-09-17: one account held 10,300 QSR fused, which
	// v1 would call twice over the limit.
	v2 := MaxFusedAmountForAccount(&Momentum{Version: 2})
	if v2.Cmp(v1) <= 0 {
		t.Fatalf("dynamic plasma raises the ceiling, got %s against %s", v2, v1)
	}
	if got := new(big.Int).Mul(big.NewInt(10_300), OneQSR); got.Cmp(v2) >= 0 {
		t.Fatalf("10,300 QSR fused is under the dynamic-plasma ceiling, got %s", v2)
	}
	// A nil momentum is the conservative answer, not a panic.
	if got := MaxFusedAmountForAccount(nil); got.Cmp(v1) != 0 {
		t.Fatalf("an unknown ruleset reads as v1, got %s", got)
	}
}

func TestRequiredFusedPlasmaRoundsUp(t *testing.T) {
	base := BaseSendPlasma(32) // 23,176
	if got := RequiredFusedPlasma(base, PriceScaleFactor); got != base {
		t.Fatalf("at the minimum price a block pays its base plasma, got %d", got)
	}
	if got := RequiredFusedPlasma(base, 2500); got != base*5/2 {
		t.Fatalf("at 2.5x a block pays 2.5x, got %d", got)
	}
	// Rounded up, because ValidPrice compares against the ceiling: paying one
	// unit less is what wedges an account.
	if got := RequiredFusedPlasma(1, 1001); got != 2 {
		t.Fatalf("the requirement rounds up, got %d", got)
	}
}
