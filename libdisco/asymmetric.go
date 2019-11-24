package libdisco

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"

	ristretto "github.com/gtank/ristretto255"
	"golang.org/x/crypto/curve25519"
)

//
// The following code defines the X25519, chacha20poly1305, SHA-256 suite.
//
// The following code implements the Schnorrkel variant of Schnorr signatures
// over ristretto255.
// This implementation was picked from https://github.com/w3f/schnorrkel

const (
	dhLen  = 32 // A constant specifying the size in bytes of public keys and DH outputs. For security reasons, dhLen must be 32 or greater.
	skSize = 32 // a secret key is encoded as a 32 byte array.
)

// 4.1. DH functions

// TODO: store the KeyPair's parts in *[32]byte or []byte ?

// KeyPair contains a private and a public part, both of 32-byte.
// It can be generated via the GenerateKeyPair() function.
// The public part can also be extracted via the String() function.
type KeyPair struct {
	PrivateKey [32]byte // must stay a [32]byte because of Serialize()
	PublicKey  [32]byte // must stay a [32]byte because of Serialize()
}

// GenerateKeypair creates a X25519 static keyPair out of a private key. If privateKey is nil the function generates a random key pair.
func GenerateKeypair(privateKey *[32]byte) *KeyPair {

	var keyPair KeyPair
	if privateKey != nil {
		copy(keyPair.PrivateKey[:], privateKey[:])
	} else {
		if _, err := rand.Read(keyPair.PrivateKey[:]); err != nil {
			panic(err)
		}
	}

	curve25519.ScalarBaseMult(&keyPair.PublicKey, &keyPair.PrivateKey)

	return &keyPair
}

// String returns the public part in hex format of a static key pair.
func (kp KeyPair) String() string {
	return hex.EncodeToString(kp.PublicKey[:])
}

func dh(keyPair KeyPair, publicKey [32]byte) (shared [32]byte) {

	curve25519.ScalarMult(&shared, &keyPair.PrivateKey, &publicKey)

	return
}

// SigningKeypair uses deterministic Schnorr with strobe
type SigningKeypair struct {
	SecretKey ristretto.Scalar
	PublicKey ristretto.Element
}

// Signature represents a schnorrkel signature
type Signature struct {
	R ristretto.Element
	S ristretto.Scalar
}

// Decode a schnorrkel signature from a bytearray.
// ref: https://github.com/w3f/schnorrkel/blob/master/src/sign.rs#L100
func (s *Signature) Decode(sigBytes [64]byte) error {
	err := s.R.Decode(sigBytes[:32])
	if err != nil {
		return err
	}
	sigBytes[63] &= 127
	err = s.S.Decode(sigBytes[32:])
	if err != nil {
		return err
	}
	return nil
}

// Encode a signature as a bytearray.
// see: https://github.com/w3f/schnorrkel/blob/master/src/sign.rs#L77
func (s *Signature) Encode() [64]byte {
	var sigBytes [64]byte

	rBytes := s.R.Encode(nil)
	copy(sigBytes[:32], rBytes)

	sBytes := s.S.Encode(nil)
	copy(sigBytes[32:], sBytes)

	sigBytes[63] |= 128

	return sigBytes
}

// GenerateSigningKeypair for schnorr signatures.
func GenerateSigningKeypair() (SigningKeypair, error) {

	var sigpair SigningKeypair
	// Generate a schnorr keypair
	var publicKey ristretto.Element

	secretKey, err := newRandomScalar()
	if err != nil {
		return sigpair, err
	}
	sigpair.PublicKey = *publicKey.ScalarBaseMult(&secretKey)
	sigpair.SecretKey = secretKey

	return sigpair, nil
}

// String returns a hexstring encoding of the signing keypair.
func (kp SigningKeypair) String() string {
	return hex.EncodeToString(kp.SecretKey.Encode(nil)) + hex.EncodeToString(kp.PublicKey.Encode(nil))
}

// Sign a message using a deterministic nonce
func (kp SigningKeypair) Sign(message []byte) Signature {

	// choose a deterministic nonce

	var kBytes [64]byte
	// preallocate and avoid append allocations
	var buf = make([]byte, 0, skSize+len(message))
	buf = append(buf, kp.SecretKey.Encode(nil)...)
	buf = append(buf, message...)
	// buf ownership passed to reusable buffer
	var reusableBuffer = bytes.NewBuffer(buf)
	// the output should be 64 byte per ristretto255 rfc
	// ref : https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-00
	copy(kBytes[:], Hash(reusableBuffer.Bytes(), 64))
	// cleanup
	reusableBuffer.Reset()
	var k ristretto.Scalar
	var R ristretto.Element

	k.FromUniformBytes(kBytes[:])
	R.ScalarBaseMult(&k)

	var e ristretto.Scalar
	var x ristretto.Scalar
	var s ristretto.Scalar

	// e = H(R||message)
	reusableBuffer.Write(R.Encode(nil))
	reusableBuffer.Write(message)

	h := Hash(reusableBuffer.Bytes(), 64)
	e.FromUniformBytes(h)

	reusableBuffer.Reset()
	// x = sk*e
	x.Multiply(&kp.SecretKey, &e)
	// s = k + x
	s.Add(&k, &x)

	sig := Signature{R, s}

	return sig

}

// Verify a signature
func (kp SigningKeypair) Verify(message []byte, signature Signature) (bool, error) {

	// Verifying a signature of the form R,s
	// Decoding the signature

	var R ristretto.Element
	var s ristretto.Scalar

	R = signature.R
	s = signature.S

	ev := Hash(append(R.Encode(nil), message...), 64)

	var k ristretto.Scalar
	k.FromUniformBytes(ev)

	var Rp ristretto.Element
	Rp.ScalarBaseMult(&s)

	var ky ristretto.Element
	ky.ScalarMult(&k, &kp.PublicKey)

	Rp.Subtract(&Rp, &ky)

	return Rp.Equal(&R) == 1, nil

}

// newRandomScalar generates a random ristretto scalar using crypto/rand.
func newRandomScalar() (ristretto.Scalar, error) {

	var buf [64]byte
	var s ristretto.Scalar

	n, err := rand.Read(buf[:])

	if n != 64 || err != nil {
		return s, err
	}

	s.FromUniformBytes(buf[:])
	return s, nil
}

// newRandomElement generates a random ristretto point using crypto/rand.
func newRandomElement() (ristretto.Element, error) {

	var buf [64]byte
	var P ristretto.Element

	n, err := rand.Read(buf[:])

	if n != 64 || err != nil {
		return P, err
	}
	P.FromUniformBytes(buf[:])
	return P, nil
}
