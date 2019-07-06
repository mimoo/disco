package libdisco

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	ristretto "github.com/bwesterb/go-ristretto"
	"golang.org/x/crypto/curve25519"
)

//
// The following code defines the X25519, chacha20poly1305, SHA-256 suite.
//

const (
	dhLen = 32 // A constant specifying the size in bytes of public keys and DH outputs. For security reasons, dhLen must be 32 or greater.
)

// 4.1. DH functions

// TODO: store the KeyPair's parts in *[32]byte or []byte ?

// KeyPair contains a private and a public part, both of 32-byte.
// It can be generated via the GenerateKeyPair() function.
// The public part can also be extracted via the ExportPublicKey() function.
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

// ExportPublicKey returns the public part in hex format of a static key pair.
func (kp KeyPair) ExportPublicKey() string {
	return hex.EncodeToString(kp.PublicKey[:])
}

func dh(keyPair KeyPair, publicKey [32]byte) (shared [32]byte) {

	curve25519.ScalarMult(&shared, &keyPair.PrivateKey, &publicKey)

	return
}

// uses deterministic Schnorr with strobe
type SigningKeyPair struct {
	SecretKey ristretto.Scalar
	PublicKey ristretto.Point
}

//
func GenerateSigningKeyPair() SigningKeyPair {
	// Generate an El'Gamal keypair
	var secretKey ristretto.Scalar
	var publicKey ristretto.Point

	secretKey.Rand()                     // generate a new secret key
	publicKey.ScalarMultBase(&secretKey) // compute public key

	return SigningKeyPair{secretKey, publicKey}
}

func (kp SigningKeyPair) ExportPublicKey() string {
	return hex.EncodeToString(kp.SecretKey.Bytes()) + hex.EncodeToString(kp.PublicKey.Bytes())
}

//
func (kp SigningKeyPair) Sign(message []byte) []byte {
	// 1. deterministic ephemeral k; r=g^k
	var kBytes [32]byte
	copy(kBytes[:], Hash(append(kp.SecretKey.Bytes(), message...), 32))
	var k ristretto.Scalar
	k.SetBytes(&kBytes)
	var r ristretto.Point
	r.ScalarMultBase(&k)

	// 2. e = H(r || M)
	e := Hash(append(r.Bytes(), message...), 32)
	var e32 [32]byte
	copy(e32[:], e)
	// 3. s = k - xe
	var xe ristretto.Scalar
	var eScal ristretto.Scalar
	eScal.SetBytes(&e32)
	xe.Mul(&kp.SecretKey, &eScal)
	var s ristretto.Scalar
	s.Sub(&k, &xe)

	// 4. return (s, e)
	return append(s.Bytes(), e...)
}

//
func (kp SigningKeyPair) Verify(message, signature []byte) error {
	// 0. (s, e) = sig
	if len(signature) != 64 {
		return fmt.Errorf("disco: signature length incorrect")
	}
	var s, e [32]byte
	copy(s[:], signature[:32])
	copy(e[:], signature[32:])

	// 1. rv = g^s y^e
	var gs ristretto.Point
	var sScal ristretto.Scalar
	sScal.SetBytes(&s)
	gs.ScalarMultBase(&sScal)
	var ye ristretto.Point
	var eScal ristretto.Scalar
	eScal.SetBytes(&e)
	ye.PublicScalarMult(&kp.PublicKey, &eScal)

	var rv ristretto.Point
	rv.Add(&gs, &ye)

	// 2. ev = H(rv || M)
	ev := Hash(append(rv.Bytes(), message...), 32)

	// 3. ev = e ?
	if !bytes.Equal(ev, e[:]) {
		return fmt.Errorf("disco: signature is invalid")
	}

	//
	return nil
}
