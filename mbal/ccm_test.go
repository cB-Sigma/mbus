package mbal

import (
	"bytes"
	"testing"
)

// TestCCMReferenceValues pins ccmSeal and ccmOpen to values from an
// independent implementation (Python cryptography's AESCCM; the same
// values are in libs/iotcrypto/ccm/testdata/reference.json): NIST SP
// 800-38C example C.4 (65536 bytes of additional data), the
// AES-CCM-16-64 shape of COSE (13-byte nonce, 8-byte tag) with 128- and
// 256-bit keys, a 7-byte nonce with a 4-byte tag, and 0xFF00 bytes of
// additional data (the first length that takes the 0xFF 0xFE encoding).
func TestCCMReferenceValues(t *testing.T) {
	c4AAD := make([]byte, 65536)
	for i := range c4AAD {
		c4AAD[i] = byte(i)
	}
	longAAD := make([]byte, 0xFF00)
	for i := range longAAD {
		longAAD[i] = byte(i*7 + 3)
	}
	for _, v := range []struct {
		name, key, nonce, plain, sealed string
		aad                             []byte
		tag                             int
	}{
		{"SP 800-38C C.4", "404142434445464748494a4b4c4d4e4f", "101112131415161718191a1b1c",
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			"69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b", c4AAD, 14},
		{"13/8, AES-128, empty", "e7cb985487513dfeafb3e9b0968d92cc", "fc0cc6b119f89cb1c0537fac73", "",
			"e6a6a1636c8f2b34", nil, 8},
		{"13/8, AES-128", "620374ae68c0383fbda6451a4cbd4d0f", "f97b7a15293edc96b048eee0de",
			"55e4b10d4528918b1ed6ad9ed7866c860c778f70329df8dda33485e1d106efb1aa",
			"72a53bfc104ea6b675dda8ea9444add1c2e3f626922b7edd370fef278d4b3898f9bc87b0df6989c425",
			hx(t, "7a3f9048208945793a0c1b9833bc2ffa532beb19d923032e3ceb379369e33faf5664caa95f0ade96"), 8},
		{"13/8, AES-256", "6a8998cfeed4ba0428c85ef1edbb96beca94042bcade3d40403d6f752e2c802b", "986d2a54836eebae3100fde551",
			"3237af5db6e397e0c3ccded027ab42976c4feb2172d75f7daef32d75c8f478293e",
			"4245c296a61af40e157a9b555368e617b0a361a6ebe3e1e6f48f186acf501048ca5675e24646ad449e",
			hx(t, "ac4b41cdc4eeeec9f265260ed0d87c195d897d06e581ba214d2649a94072d9ad4a590fbb8fffdc00"), 8},
		{"7/4", "fa5df89acd10f3ef9d7ac2b27fe43882", "a3468e5f6f141c", "4ced2387c32cd1dd5881a193e3acddf5cf",
			"f6779d03670dfa4e903e4090e298f4b0eef0426332", nil, 4},
		{"0xFF00 bytes of additional data", "000102030405060708090a0b0c0d0e0f", "101112131415161718191a1b",
			"7369676d616d326d2063636d206c617267652061616420636865636b",
			"50dcdecd23991fdf2acf1cad5408baf41cd2f2d654232a489e8dc43baefac2fb52e3461ae026054be33a43f7", longAAD, 16},
	} {
		key, nonce, plain, want := hx(t, v.key), hx(t, v.nonce), hx(t, v.plain), hx(t, v.sealed)
		got, err := ccmSeal(key, nonce, plain, v.aad, v.tag)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: seal % x, %v", v.name, got, err)
		}
		back, err := ccmOpen(key, nonce, want, v.aad, v.tag)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("%s: open % x, %v", v.name, back, err)
		}
		bad := append([]byte(nil), want...)
		bad[len(bad)-1] ^= 0x80
		if _, err := ccmOpen(key, nonce, bad, v.aad, v.tag); err != errCCMAuth {
			t.Fatalf("%s: changed tag: %v", v.name, err)
		}
	}
}

// TestCCMErrorTexts pins the errors ccmSeal and ccmOpen return, and the
// order of the checks (a short ciphertext is refused before the key is
// looked at).
func TestCCMErrorTexts(t *testing.T) {
	key := make([]byte, 16)
	n13 := make([]byte, 13)
	for _, c := range []struct {
		name string
		err  func() error
		want string
	}{
		{"bad key, seal", func() error { _, err := ccmSeal(make([]byte, 15), n13, nil, nil, 8); return err },
			"crypto/aes: invalid key size 15"},
		{"bad key, open", func() error { _, err := ccmOpen(make([]byte, 15), n13, make([]byte, 8), nil, 8); return err },
			"crypto/aes: invalid key size 15"},
		{"short ciphertext before bad key", func() error { _, err := ccmOpen(make([]byte, 15), n13, make([]byte, 7), nil, 8); return err },
			"CCM ciphertext shorter than its tag"},
		{"short ciphertext", func() error { _, err := ccmOpen(key, n13, make([]byte, 7), nil, 8); return err },
			"CCM ciphertext shorter than its tag"},
		{"nonce 6", func() error { _, err := ccmSeal(key, make([]byte, 6), nil, nil, 8); return err },
			"CCM parameters are invalid"},
		{"nonce 14", func() error { _, err := ccmOpen(key, make([]byte, 14), make([]byte, 8), nil, 8); return err },
			"CCM parameters are invalid"},
		{"tag 3", func() error { _, err := ccmSeal(key, n13, nil, nil, 3); return err },
			"CCM parameters are invalid"},
		{"tag 5", func() error { _, err := ccmSeal(key, n13, nil, nil, 5); return err },
			"CCM parameters are invalid"},
		{"tag 18", func() error { _, err := ccmOpen(key, n13, make([]byte, 18), nil, 18); return err },
			"CCM parameters are invalid"},
		{"too long, seal", func() error { _, err := ccmSeal(key, n13, make([]byte, 1<<16), nil, 8); return err },
			"CCM message too long"},
		{"too long, open", func() error { _, err := ccmOpen(key, n13, make([]byte, 1<<16+8), nil, 8); return err },
			"CCM message too long"},
		{"wrong tag", func() error { _, err := ccmOpen(key, n13, make([]byte, 8), nil, 8); return err },
			"COSE content does not authenticate (wrong key or tampered)"},
	} {
		if err := c.err(); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// The longest payload a 13-byte nonce allows still seals.
	if _, err := ccmSeal(key, n13, make([]byte, 1<<16-1), nil, 8); err != nil {
		t.Errorf("65535-byte payload: %v", err)
	}
}
