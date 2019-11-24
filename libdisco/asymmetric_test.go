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

	if ok, err := kp.Verify(input, sig); !ok || err != nil {
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

func BenchmarkSign(b *testing.B) {
	input := []byte("benchmark how fast do I get signed")

	for n := 0; n < b.N; n++ {
		kp, err := GenerateSigningKeypair()

		if err != nil {
			b.Fatal("failed to generate signing keypair")
		}
		sig := kp.Sign(input)

		if ok, err := kp.Verify(input, sig); !ok || err != nil {
			b.Fatal("failed to verify signature with error : ", err)
		}

	}
}

func BenchmarkDeterministicSign(b *testing.B) {
	kp, err := GenerateSigningKeypair()
	if err != nil {
		b.Fatal("failed to generate a signing keypair")
	}
	input := []byte("benchmark how fast do I get signed and it stays consistent")
	signature := kp.Sign(input)
	sigBytes := signature.Encode()
	for n := 0; n < b.N; n++ {
		sigN := kp.Sign(input)

		sigNBytes := sigN.Encode()

		if !bytes.Equal(sigBytes[:], sigNBytes[:]) {
			b.Fatal("failed to generate deterministic signatures")
		}
	}
}
