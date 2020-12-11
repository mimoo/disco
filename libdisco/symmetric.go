package libdisco

import (
	"crypto/rand"
	"errors"

	"github.com/mimoo/StrobeGo/strobe"
)

const (
	nonceSize             = 192 / 8
	tagSize               = 16
	minimumCiphertextSize = nonceSize + tagSize
)

// Hash allows you to hash an input of any length and obtain an output of length greater or equal to 256 bits (32 bytes).
func Hash(input []byte, outputLength int) []byte {
	if outputLength < 32 {
		panic("disco: an output length smaller than 256-bit (32 bytes) has security consequences")
	}
	hash := strobe.InitStrobe("DiscoHash", 128)
	hash.AD(false, input)
	return hash.PRF(outputLength)
}

// DiscoHash represents a strobe hash
type DiscoHash struct {
	strobeState  strobe.Strobe
	streaming    bool
	outputLength int
}

// NewHash creates a new hashing state, allowing you to absorb data to hash via Write or WriteTuple,
// and to create a digest via the Sum function.
func NewHash(outputLength int) DiscoHash {
	if outputLength < 32 {
		panic("disco: an output length smaller than 256-bit (32 bytes) has security consequences")
	}
	return DiscoHash{strobeState: strobe.InitStrobe("DiscoHash", 128), outputLength: outputLength}
}

// Write absorbs more data into the hash's state. This function is usually called to hash contigous chunks
// of data. For structured data please refer to WriteTuple
func (d *DiscoHash) Write(inputData []byte) (written int, err error) {
	d.strobeState.Operate(false, "AD", inputData, 0, d.streaming)
	d.streaming = true
	written = len(inputData)
	return
}

// WriteTuple absorbs more data to hash in a non-ambigious way. This means that data absorbed
// via this function is separated from the data surrounding it. Use this function instead of Write
// to hash structured data.
func (d *DiscoHash) WriteTuple(inputData []byte) (written int, err error) {
	d.strobeState.Operate(false, "AD", inputData, 0, false)
	written = len(inputData)
	return
}

// Sum reads more output from the hash; reading affects the hash's
// state. (DiscoHash.Read is thus very different from Hash.Sum)
// It never returns an error.
func (d *DiscoHash) Sum() []byte {
	reader := d.strobeState.Clone()
	return reader.Operate(false, "PRF", nil, d.outputLength, false)
}

// Clone returns a copy of the DiscoHash in its current state.
func (d *DiscoHash) Clone() DiscoHash {
	cloned := d.strobeState.Clone()
	return DiscoHash{strobeState: *cloned}
}

// DeriveKeys allows you to derive keys
func DeriveKeys(inputKey []byte, outputLength int) []byte {
	if len(inputKey) < 16 {
		panic("disco: deriving keys from a value smaller than 128-bit (16 bytes) has security consequences")
	}
	hash := strobe.InitStrobe("DiscoKDF", 128)
	hash.AD(false, inputKey)
	return hash.PRF(outputLength)
}

// ProtectIntegrity allows you to send a message in cleartext (not encrypted)
// You can later verify via the VerifyIntegrity function that the message has not been modified
func ProtectIntegrity(key, plaintext []byte) []byte {
	if len(key) < 16 {
		panic("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	hash := strobe.InitStrobe("DiscoMAC", 128)
	hash.AD(false, key)
	hash.AD(false, plaintext)
	return append(plaintext, hash.Send_MAC(false, tagSize)...)
}

// VerifyIntegrity allows you to retrieve a message created with the ProtectIntegrity function.
// if it returns an error, it means that the message was altered. Otherwise it returns the original message.
func VerifyIntegrity(key, plaintextAndTag []byte) ([]byte, error) {
	if len(key) < 16 {
		panic("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	if len(plaintextAndTag) < tagSize {
		return nil, errors.New("disco: plaintext does not contain an integrity tag")
	}
	offset := len(plaintextAndTag) - tagSize
	plaintext := plaintextAndTag[:offset]
	tag := plaintextAndTag[offset:]

	hash := strobe.InitStrobe("DiscoMAC", 128)
	hash.AD(false, key)
	hash.AD(false, plaintext)

	// verify tag
	if !hash.Recv_MAC(false, tag) {
		return nil, errors.New("disco: the plaintext has been modified")
	}

	return plaintext, nil
}

// Encrypt allows you to encrypt a plaintext message with a key of any size greater than 128 bits (16 bytes).
func Encrypt(key, plaintext []byte) []byte {
	if len(key) < 16 {
		panic("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	ae := strobe.InitStrobe("DiscoAE", 128)
	// absorb the key
	ae.AD(false, key)
	// generate 192-bit nonce
	var nonce [nonceSize]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		panic("disco: golang's random function is not working")
	}
	// absorb the nonce
	ae.AD(false, nonce[:])
	// nonce + send_ENC(plaintext) + send_MAC(16)
	ciphertext := append(nonce[:], ae.Send_ENC_unauthenticated(false, plaintext)...)
	ciphertext = append(ciphertext, ae.Send_MAC(false, tagSize)...)
	//
	return ciphertext
}

// Decrypt allows you to decrypt a message that was encrypted with the Encrypt function.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	if len(ciphertext) < minimumCiphertextSize {
		return nil, errors.New("disco: ciphertext is too small, it should contain at a minimum a 192-bit nonce and a 128-bit tag")
	}
	// instantiate
	ae := strobe.InitStrobe("DiscoAE", 128)
	// absorb the key
	ae.AD(false, key)
	// absorb the nonce
	ae.AD(false, ciphertext[:nonceSize])
	// decrypt
	plaintext := ae.Recv_ENC_unauthenticated(false, ciphertext[nonceSize:len(ciphertext)-tagSize])
	// verify tag
	ok := ae.Recv_MAC(false, ciphertext[len(ciphertext)-tagSize:])
	if !ok {
		return nil, errors.New("disco: cannot decrypt the payload")
	}
	return plaintext, nil
}

// EncryptAndAuthenticate allows you to encrypt a plaintext message with a key of any size greater than 128 bits (16 bytes).
func EncryptAndAuthenticate(key, plaintext, ad []byte) []byte {
	if len(key) < 16 {
		panic("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	ae := strobe.InitStrobe("DiscoAEAD", 128)
	// absorb the key
	ae.AD(false, key)
	// absorb the AD
	ae.AD(false, ad)
	// generate 192-bit nonce
	var nonce [nonceSize]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		panic("disco: golang's random function is not working")
	}
	// absorb the nonce
	ae.AD(false, nonce[:])
	// nonce + send_ENC(plaintext) + send_MAC(16)
	ciphertext := append(nonce[:], ae.Send_ENC_unauthenticated(false, plaintext)...)
	ciphertext = append(ciphertext, ae.Send_MAC(false, tagSize)...)
	//
	return ciphertext
}

// DecryptAndAuthenticate allows you to decrypt a message that was encrypted with the Encrypt function.
func DecryptAndAuthenticate(key, ciphertext, ad []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("disco: using a key smaller than 128-bit (16 bytes) has security consequences")
	}
	if len(ciphertext) < minimumCiphertextSize {
		return nil, errors.New("disco: ciphertext is too small, it should contain at a minimum a 192-bit nonce and a 128-bit tag")
	}
	// instantiate
	ae := strobe.InitStrobe("DiscoAEAD", 128)
	// absorb the key
	ae.AD(false, key)
	// absorb the AD
	ae.AD(false, ad)
	// absorb the nonce
	ae.AD(false, ciphertext[:nonceSize])
	// decrypt
	plaintext := ae.Recv_ENC_unauthenticated(false, ciphertext[nonceSize:len(ciphertext)-tagSize])
	// verify tag
	ok := ae.Recv_MAC(false, ciphertext[len(ciphertext)-tagSize:])
	if !ok {
		return nil, errors.New("disco: cannot decrypt the payload")
	}
	return plaintext, nil
}
