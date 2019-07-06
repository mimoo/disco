package libdisco

import (
	"bytes"
	"testing"
)

func TestSignVerify(t *testing.T) {
	input := []byte("hi, how are you?")
	kp := GenerateSigningKeyPair()
	sig := kp.Sign(input)

	if kp.Verify(input, sig) != nil {
		t.Fatal("Schnorr doesn't work")
	}
}

func TestDeterministicSignatures(t *testing.T) {
	kp := GenerateSigningKeyPair()
	input := []byte("hi, how are you?")
	sig1 := kp.Sign(input)
	sig2 := kp.Sign(input)

	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Signatures are not deterministic doesn't work")
	}
}
