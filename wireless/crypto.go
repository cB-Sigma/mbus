package wireless

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	ccmmode "github.com/cB-Sigma/iotcrypto/ccm"
)

// CMAC computes AES-CMAC (NIST SP 800-38B, RFC 4493) of msg with a 16-byte
// key.
func CMAC(key, msg []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var l, k1, k2 [16]byte
	blk.Encrypt(l[:], l[:])
	shift := func(dst, src *[16]byte) {
		var carry byte
		for i := 15; i >= 0; i-- {
			dst[i] = src[i]<<1 | carry
			carry = src[i] >> 7
		}
		if src[0]&0x80 != 0 {
			dst[15] ^= 0x87
		}
	}
	shift(&k1, &l)
	shift(&k2, &k1)
	n := (len(msg) + 15) / 16
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last [16]byte
	if complete {
		copy(last[:], msg[(n-1)*16:])
		subtle.XORBytes(last[:], last[:], k1[:])
	} else {
		rest := msg[(n-1)*16:]
		copy(last[:], rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last[:], last[:], k2[:])
	}
	var x [16]byte
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x[:], x[:], msg[i*16:(i+1)*16])
		blk.Encrypt(x[:], x[:])
	}
	subtle.XORBytes(x[:], x[:], last[:])
	blk.Encrypt(x[:], x[:])
	return x[:], nil
}

// Key derivation function A (EN 13757-7:2025 clause 9.6.2): the derivation
// constant says which key and which direction.
const (
	DCEncMeter byte = 0x00 // Kenc, meter to other
	DCMACMeter byte = 0x01 // Kmac, meter to other
	DCEncOther byte = 0x10 // Lenc, other to meter
	DCMACOther byte = 0x11 // Lmac, other to meter
)

// DeriveKey is KDF-A: CMAC under the master key of the derivation constant,
// the message counter and the meter ID (both as transmitted, least
// significant byte first), padded with 0x07 to one block.
func DeriveKey(master []byte, dc byte, counter uint32, id [4]byte) ([]byte, error) {
	in := make([]byte, 16)
	in[0] = dc
	binary.LittleEndian.PutUint32(in[1:5], counter)
	copy(in[5:9], id[:])
	for i := 9; i < 16; i++ {
		in[i] = 0x07
	}
	return CMAC(master, in)
}

var errShort = errors.New("the encrypted part is not a whole number of AES blocks")

func cbcDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errShort
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}

func cbcEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errShort
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}

func ctrXOR(key, iv, data []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	out := make([]byte, len(data))
	cipher.NewCTR(blk, iv).XORKeyStream(out, data)
	return out, nil
}

// ---- AES-CCM (NIST SP 800-38C) ---------------------------------------------

// ccm seals or opens with AES-CCM (libs/iotcrypto/ccm). The nonce length n gives
// q = 15-n bytes of payload length; tagLen is 4, 6, 8, 10, 12, 14 or 16.
// On open, data is the ciphertext followed by the tag.
func ccm(key, nonce, aad, data []byte, tagLen int, open bool) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	a, err := ccmmode.New(blk, len(nonce), tagLen)
	if err != nil {
		return nil, fmt.Errorf("CCM: nonce %d bytes, tag %d bytes not allowed", len(nonce), tagLen)
	}
	if open {
		p, err := a.Open(nil, nonce, data, aad)
		if err != nil {
			return nil, ErrMAC
		}
		return p, nil
	}
	if q := 15 - len(nonce); q < 8 && uint64(len(data)) >= 1<<(8*q) {
		return nil, errors.New("CCM: payload too long for the nonce size")
	}
	return a.Seal(nil, nonce, data, aad), nil
}

// ---- AES-GCM / GMAC (NIST SP 800-38D) --------------------------------------

// gcmSeal encrypts with AES-GCM and returns ciphertext and a tag of tagLen
// bytes (the leading bytes of the full tag). Nonces of any length are
// allowed (a 13-byte one is processed by GHASH, as SP 800-38D says).
func gcmSeal(key, nonce, aad, plain []byte, tagLen int) (ct, tag []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES key: %w", err)
	}
	g, err := cipher.NewGCMWithNonceSize(blk, len(nonce))
	if err != nil {
		return nil, nil, err
	}
	out := g.Seal(nil, nonce, plain, aad)
	return out[:len(plain)], out[len(plain) : len(plain)+tagLen], nil
}

// gcmOpen checks a (possibly truncated) GCM tag and decrypts.
func gcmOpen(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	g, err := cipher.NewGCMWithNonceSize(blk, len(nonce))
	if err != nil {
		return nil, err
	}
	// GCM encryption is CTR from inc32(J0): decrypt with that keystream,
	// then re-seal to compare the (possibly truncated) tag.
	plain := gcmCTR(g, nonce, ct)
	out := g.Seal(nil, nonce, plain, aad)
	if subtle.ConstantTimeCompare(out[len(plain):len(plain)+len(tag)], tag) != 1 {
		return nil, ErrMAC
	}
	return plain, nil
}

// gcmCTR applies GCM's keystream (starting at inc32(J0)) to data. For a
// 12-byte nonce J0 is nonce||00000001; for other lengths it is found by
// sealing zeros, whose ciphertext is the keystream itself.
func gcmCTR(g cipher.AEAD, nonce, data []byte) []byte {
	ks := g.Seal(nil, nonce, make([]byte, len(data)), nil)[:len(data)]
	out := make([]byte, len(data))
	subtle.XORBytes(out, data, ks)
	return out
}

// ---- AES key wrap with padding (NIST SP 800-38F KWP, RFC 5649) -------------

var errUnwrap = errors.New("key unwrap failed: integrity check value mismatch")

// KWPWrap wraps plain with kek: AES key wrap with padding (RFC 5649,
// alternative initial value A65959A6), as SITP wraps keys.
func KWPWrap(kek, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	if len(plain) == 0 {
		return nil, errors.New("key wrap: nothing to wrap")
	}
	aiv := binary.BigEndian.AppendUint32([]byte{0xA6, 0x59, 0x59, 0xA6}, uint32(len(plain)))
	p := append([]byte(nil), plain...)
	for len(p)%8 != 0 {
		p = append(p, 0)
	}
	if len(p) == 8 {
		out := make([]byte, 16)
		blk.Encrypt(out, append(aiv, p...))
		return out, nil
	}
	return kwW(blk, aiv, p), nil
}

// KWPUnwrap is KWPWrap's inverse; it checks the ICV, length and padding.
func KWPUnwrap(kek, wrapped []byte) ([]byte, error) {
	blk, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("AES key: %w", err)
	}
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, errUnwrap
	}
	var a, p []byte
	if len(wrapped) == 16 {
		out := make([]byte, 16)
		blk.Decrypt(out, wrapped)
		a, p = out[:8], out[8:]
	} else {
		a, p = kwWInv(blk, wrapped)
	}
	if !bytes.Equal(a[:4], []byte{0xA6, 0x59, 0x59, 0xA6}) {
		return nil, errUnwrap
	}
	mli := int(binary.BigEndian.Uint32(a[4:8]))
	if mli > len(p) || mli <= len(p)-8 {
		return nil, errUnwrap
	}
	for _, b := range p[mli:] {
		if b != 0 {
			return nil, errUnwrap
		}
	}
	return p[:mli], nil
}

// kwW is the wrapping function W of SP 800-38F (RFC 3394) with initial
// value iv over the semiblocks of p.
func kwW(blk cipher.Block, iv, p []byte) []byte {
	n := len(p) / 8
	a := append([]byte(nil), iv...)
	r := append([]byte(nil), p...)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[:8], a)
			copy(b[8:], r[i*8:i*8+8])
			blk.Encrypt(b[:], b[:])
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(b[:8])^t)
			copy(r[i*8:], b[8:])
		}
	}
	return append(a, r...)
}

// kwWInv is W's inverse; it returns the recovered initial value and data.
func kwWInv(blk cipher.Block, c []byte) (iv, p []byte) {
	n := len(c)/8 - 1
	a := append([]byte(nil), c[:8]...)
	r := append([]byte(nil), c[8:]...)
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a)^t)
			copy(b[8:], r[i*8:i*8+8])
			blk.Decrypt(b[:], b[:])
			copy(a, b[:8])
			copy(r[i*8:], b[8:])
		}
	}
	return a, r
}

// Other KDF-A derivation constants (EN 13757-7:2025 clause 9.6): the keys
// for the communication partner's direction (Lenc, Lmac) use DCEncOther
// and DCMACOther with the partner's counter.

// desCBCDecrypt is DES-CBC (security modes 2 and 3, deprecated).
func desCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("the DES-encrypted part is not a whole number of 8-byte blocks")
	}
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("DES key: %w", err)
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}

// desCBCEncrypt is desCBCDecrypt's inverse (simulators and tests).
func desCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	blk, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}
