package libdisco

import (
	"bytes"
	"testing"
)

func TestSignVerify(t *testing.T) {
	input := []byte("hi, how are you?")
	kp, err := GenerateSigningKeypair()

	if err != nil {
		t.Fatal("failed to generate a signing keypair")
	}
	sig := kp.Sign(input)

	err = kp.Verify(input, sig)
	if err != nil {
		t.Fatal("failed to verify signature with error : ", err)
	}
}

func TestDeterministicSignatures(t *testing.T) {
	kp, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatal("failed to generate a signing keypair")
	}
	input := []byte("hi, how are you?")
	sig1 := kp.Sign(input)
	sig2 := kp.Sign(input)

	sig1Bytes := sig1.Encode()
	sig2Bytes := sig2.Encode()

	if !bytes.Equal(sig1Bytes[:], sig2Bytes[:]) {
		t.Fatal("signatures are not deterministic doesn't work")
	}
}

func BenchmarkSignVerify(b *testing.B) {
	kp, err := GenerateSigningKeypair()
	if err != nil {
		b.Fatal("failed to generate a signing keypair")
	}
	input := []byte("benchmark how fast do I get signed and it stays consistent")

	for n := 0; n < b.N; n++ {
		sig := kp.Sign(input)
		kp.Verify(input, sig)
	}
}
