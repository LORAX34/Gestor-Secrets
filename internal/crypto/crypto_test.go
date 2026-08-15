package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("sensitive value")
	enc, err := Seal(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	dec, err := Open(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("round trip mismatch")
	}
}

func TestOpenWrongKey(t *testing.T) {
	key, _ := RandomBytes(32)
	other, _ := RandomBytes(32)
	enc, _ := Seal([]byte("x"), key)
	if _, err := Open(enc, other); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestUnwrapKeyRoundTrip(t *testing.T) {
	vk, _ := NewVaultKey()
	kek, _ := RandomBytes(32)
	wrapped, err := WrapKey(vk, kek)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnwrapKey(wrapped, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, vk) {
		t.Fatal("vault key mismatch after unwrap")
	}
}

func TestArgon2ParamsJSON(t *testing.T) {
	p := DefaultParams()
	s, err := EncodeParams(p)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeParams(s)
	if err != nil {
		t.Fatal(err)
	}
	if out != p {
		t.Fatal("params mismatch")
	}
}

func TestTokenHash(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}
	if h1 == tok {
		t.Fatal("hash must differ from raw token")
	}
}
