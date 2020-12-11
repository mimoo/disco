// Package libdisco partially implements the Disco extension of the Noise protocol framework
// as specified in www.discocrypto.com/disco.html
//
// More usage helpers are available on www.discocrypto.com
//
// Author: David Wong
//
package libdisco

import (
	"bytes"
	"encoding/gob"
	"errors"

	"github.com/mimoo/StrobeGo/strobe"
)

//
// SymmetricState object
//

type symmetricState struct {
	strobeState strobe.Strobe
	isKeyed     bool
}

func (s *symmetricState) initializeSymmetric(protocolName string) {
	// initializing the Strobe state
	s.strobeState = strobe.InitStrobe(protocolName, 128)
}

func (s *symmetricState) mixKey(inputKeyMaterial [32]byte) {
	s.strobeState.AD(false, inputKeyMaterial[:])
	s.isKeyed = true
}

func (s *symmetricState) mixHash(data []byte) {
	s.strobeState.AD(false, data)
}

func (s *symmetricState) mixKeyAndHash(inputKeyMaterial []byte) {
	s.strobeState.AD(false, inputKeyMaterial)
}

// TODO: documentation
// GetHandshakeHash
func (s *symmetricState) GetHandshakeHash() []byte {
	return s.strobeState.PRF(32)
}

// encrypts the plaintext and authenticates the hash
// then insert the ciphertext in the running hash
func (s *symmetricState) encryptAndHash(plaintext []byte) (ciphertext []byte, err error) {

	if s.isKeyed {
		ciphertext := s.strobeState.Send_ENC_unauthenticated(false, plaintext)
		ciphertext = append(ciphertext, s.strobeState.Send_MAC(false, 16)...)
		return ciphertext, nil
	}
	// no keys, so we don't encrypt
	return plaintext, nil
}

// decrypts the ciphertext and authenticates the hash
func (s *symmetricState) decryptAndHash(ciphertext []byte) (plaintext []byte, err error) {

	if s.isKeyed {
		if len(ciphertext) < 16 {
			return nil, errors.New("disco: the received payload is shorter 16 bytes")
		}

		plaintext := s.strobeState.Recv_ENC_unauthenticated(false, ciphertext[:len(ciphertext)-16])
		ok := s.strobeState.Recv_MAC(false, ciphertext[len(ciphertext)-16:])
		if !ok {
			return nil, errors.New("disco: cannot decrypt the payload")
		}
		return plaintext, nil
	}
	// no keys, so nothing to decrypt
	return ciphertext, nil
}

func (s symmetricState) Split() (s1, s2 *strobe.Strobe) {

	s1 = s.strobeState.Clone()
	s1.AD(true, []byte("initiator"))
	s1.RATCHET(32)

	s2 = &s.strobeState
	s2.AD(true, []byte("responder"))
	s2.RATCHET(32)
	return
}

//
// HandshakeState object
//

type handshakeState struct {
	// the symmetricState object
	symmetricState symmetricState
	/* Empty is a special value which indicates the variable has not yet been initialized.
	we'll use KeyPair.privateKey = 0 as Empty
	*/
	s  KeyPair // The local static key pair
	e  KeyPair // The local ephemeral key pair
	rs KeyPair // The remote party's static public key
	re KeyPair // The remote party's ephemeral public key

	// A boolean indicating the initiator or responder role.
	initiator bool
	// A sequence of message pattern. Each message pattern is a sequence
	// of tokens from the set ("e", "s", "ee", "es", "se", "ss")
	messagePatterns []messagePattern

	// A boolean indicating if the role of the peer is to WriteMessage
	// or ReadMessage
	shouldWrite bool

	// pre-shared key
	psk []byte

	// for test vectors
	debugEphemeral *KeyPair
}

// Serialize is a helper function to serialize a handshake state, later to be unserialized via
// the `RecoverState()` function.
// For security purposes, the long-term static keypair is not serialized. Same for the psk
func (hs *handshakeState) Serialize() []byte {
	// [s.pubkey(32), e(64), rs(32), re(32), initiator(1), messagePatterns(?), shouldWrite(1), symmetricState.isKeyed(1) , serializedStrobeState(?)]
	var serialized bytes.Buffer

	// s.pubkey (not the private key!)
	serialized.Write(hs.s.PublicKey[:])
	// e
	serialized.Write(hs.e.PrivateKey[:])
	serialized.Write(hs.e.PublicKey[:]) // TODO: we can re-compute this, do we serialize it?
	// rs.pubkey
	serialized.Write(hs.rs.PublicKey[:])
	// re.pubkey
	serialized.Write(hs.re.PublicKey[:])

	// initiator
	if hs.initiator {
		serialized.WriteByte(1)
	} else {
		serialized.WriteByte(0)
	}

	// we use gob to encode the messagePatterns
	encoder := gob.NewEncoder(&serialized)
	encoder.Encode(hs.messagePatterns)

	// shouldWrite
	if hs.shouldWrite {
		serialized.WriteByte(1)
	} else {
		serialized.WriteByte(0)
	}

	// symmetricState.isKeyed
	if hs.symmetricState.isKeyed {
		serialized.WriteByte(1)
	} else {
		serialized.WriteByte(0)
	}

	// symmetricState.strobeState
	serialized.Write(hs.symmetricState.strobeState.Serialize())

	//
	return serialized.Bytes()
}

// RecoverState is a helper function to unserialize a previously serialized handshake state
// (via the `Serialize()` function).
// For security purposes, the long-term static keypair needs to be passed as argument.
// RecoverState will crash if the passed serializedState is malformed
func RecoverState(serialized []byte, psk []byte, s *KeyPair) handshakeState {
	// [s.pubkey(32), e(64), rs(32), re(32), initiator(1), messagePatterns(?), shouldWrite(1), symmetricState.isKeyed(1) , serializedStrobeState(?)]
	bb := bytes.NewBuffer(serialized)
	hs := handshakeState{}

	//psk
	if psk != nil {
		hs.psk = make([]byte, len(psk))
		copy(hs.psk, psk)
	}

	// verify static keypair
	if !bytes.Equal(s.PublicKey[:], serialized[0:32]) {
		panic("wrong static keyPair passed")
	}
	// store static keypair
	hs.s = *s
	bb.Next(32)
	// e
	bb.Read(hs.e.PrivateKey[:])
	bb.Read(hs.e.PublicKey[:])
	// rs.pubkey
	bb.Read(hs.rs.PublicKey[:])
	// re.pubkey
	bb.Read(hs.re.PublicKey[:])

	// initiator
	if initiator, _ := bb.ReadByte(); initiator == 1 {
		hs.initiator = true
	}

	// we use gob to encode the messagePatterns
	decoder := gob.NewDecoder(bb)
	if err := decoder.Decode(&(hs.messagePatterns)); err != nil {
		panic(err)
	}

	// shouldWrite
	if shouldWrite, _ := bb.ReadByte(); shouldWrite == 1 {
		hs.shouldWrite = true
	}

	// symmetricState.isKeyed
	if isKeyed, _ := bb.ReadByte(); isKeyed == 1 {
		hs.symmetricState.isKeyed = true
	}

	// symmetricState.strobeState
	hs.symmetricState.strobeState = strobe.RecoverState(bb.Bytes())

	//
	return hs
}

// Initialize allows you to initialize a peer
// * see `patterns` for a list of available handshakePatterns
// * initiator = false means the instance is for a responder
// * prologue is a byte string record of anything that happened prior the Noise handshakeState
// * s, e, rs, re are the local and remote static/ephemeral key pairs to be set (if they exist)
// the function returns a handshakeState object.
func Initialize(handshakeType noiseHandshakeType, initiator bool, prologue []byte, s, e, rs, re *KeyPair) (hs handshakeState) {

	handshakePattern, ok := patterns[handshakeType]
	if !ok {
		panic("disco: the supplied handshakePattern does not exist")
	}

	hs.symmetricState.initializeSymmetric("Noise_" + handshakePattern.name + "_25519_STROBEv1.0.2")

	hs.symmetricState.mixHash(prologue)

	if s != nil {
		hs.s = *s
	}
	if e != nil {
		panic("disco: fallback patterns are not implemented")
	}
	if rs != nil {
		hs.rs = *rs
	}
	if re != nil {
		panic("disco: fallback patterns are not implemented")
	}

	hs.initiator = initiator
	hs.shouldWrite = initiator

	//Calls MixHash() once for each public key listed in the pre-messages from handshake_pattern, with the specified public key as input (see Section 7 for an explanation of pre-messages). If both initiator and responder have pre-messages, the initiator's public keys are hashed first.

	// initiator pre-message pattern
	for _, token := range handshakePattern.preMessagePatterns[0] {
		if token == token_s {
			if initiator {
				if s == nil {
					panic("disco: the static key of the client should be set")
				}
				hs.symmetricState.mixHash(s.PublicKey[:])
			} else {
				if rs == nil {
					panic("disco: the remote static key of the server should be set")
				}
				hs.symmetricState.mixHash(rs.PublicKey[:])
			}
		} else {
			panic("disco: token of pre-message not supported")
		}
	}

	// responder pre-message pattern
	for _, token := range handshakePattern.preMessagePatterns[1] {
		if token == token_s {
			if initiator {
				if rs == nil {
					panic("disco: the remote static key of the server should be set")
				}
				hs.symmetricState.mixHash(rs.PublicKey[:])
			} else {
				if s == nil {
					panic("disco: the static key of the client should be set")
				}
				hs.symmetricState.mixHash(s.PublicKey[:])
			}
		} else {
			panic("disco: token of pre-message not supported")
		}
	}

	hs.messagePatterns = handshakePattern.messagePatterns

	return
}

// WriteMessage takes a (nil) payload and a messageBuffer. It writes the next Noise message into
// the message buffer.
// messageBuffer cannot be nil
func (hs *handshakeState) WriteMessage(payload []byte, messageBuffer *[]byte) (c1, c2 *strobe.Strobe, err error) {
	// is it our turn to write?
	if !hs.shouldWrite {
		panic("disco: unexpected call to WriteMessage should be ReadMessage")
	}
	// do we have a token to process?
	if len(hs.messagePatterns) == 0 || len(hs.messagePatterns[0]) == 0 {
		panic("disco: no more tokens or message patterns to write")
	}

	// process the patterns
	for _, pattern := range hs.messagePatterns[0] {

		switch pattern {

		default:
			panic("Disco: token not recognized")

		case token_e:
			// debug
			if hs.debugEphemeral != nil {
				hs.e = *hs.debugEphemeral
			} else {
				hs.e = *GenerateKeypair(nil)
			}
			*messageBuffer = append(*messageBuffer, hs.e.PublicKey[:]...)
			hs.symmetricState.mixHash(hs.e.PublicKey[:])
			if len(hs.psk) > 0 {
				hs.symmetricState.mixKey(hs.e.PublicKey)
			}

		case token_s:
			var ciphertext []byte
			ciphertext, err = hs.symmetricState.encryptAndHash(hs.s.PublicKey[:])
			if err != nil {
				return
			}
			*messageBuffer = append(*messageBuffer, ciphertext...)

		case token_ee:
			hs.symmetricState.mixKey(dh(hs.e, hs.re.PublicKey))

		case token_es:
			if hs.initiator {
				hs.symmetricState.mixKey(dh(hs.e, hs.rs.PublicKey))
			} else {
				hs.symmetricState.mixKey(dh(hs.s, hs.re.PublicKey))
			}

		case token_se:
			if hs.initiator {
				hs.symmetricState.mixKey(dh(hs.s, hs.re.PublicKey))
			} else {
				hs.symmetricState.mixKey(dh(hs.e, hs.rs.PublicKey))
			}

		case token_ss:
			hs.symmetricState.mixKey(dh(hs.s, hs.rs.PublicKey))

		case token_psk:
			hs.symmetricState.mixKeyAndHash(hs.psk)
		}
	}

	// Appends EncryptAndHash(payload) to the buffer
	var ciphertext []byte
	ciphertext, err = hs.symmetricState.encryptAndHash(payload)
	if err != nil {
		return
	}
	*messageBuffer = append(*messageBuffer, ciphertext...)

	// are there more message patterns to process?
	if len(hs.messagePatterns) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		hs.messagePatterns = nil
		c1, c2 = hs.symmetricState.Split()
	} else {
		// remove the pattern from the messagePattern
		hs.messagePatterns = hs.messagePatterns[1:]
	}

	// change the direction
	hs.shouldWrite = false

	return
}

// ReadMessage takes a byte sequence containing a Noise handshake message,
// and a payload_buffer to write the message's plaintext payload into.
// payload_buffer cannot be nil
func (hs *handshakeState) ReadMessage(message []byte, payloadBuffer *[]byte) (c1, c2 *strobe.Strobe, err error) {
	// is it our turn to read?
	if hs.shouldWrite {
		panic("disco: unexpected call to ReadMessage should be WriteMessage")
	}
	// do we have a token to process?
	if len(hs.messagePatterns) == 0 || len(hs.messagePatterns[0]) == 0 {
		panic("disco: no more message pattern to read")
	}

	// process the patterns
	offset := 0

	for _, pattern := range hs.messagePatterns[0] {

		switch pattern {

		default:
			panic("disco: token not recognized")

		case token_e:
			if len(message[offset:]) < dhLen {
				return nil, nil, errors.New("disco: the received ephemeral key is to short")
			}
			copy(hs.re.PublicKey[:], message[offset:offset+dhLen])
			offset += dhLen
			hs.symmetricState.mixHash(hs.re.PublicKey[:])
			if len(hs.psk) > 0 {
				hs.symmetricState.mixKey(hs.re.PublicKey)
			}

		case token_s:
			tagLen := 0
			if hs.symmetricState.isKeyed {
				tagLen = 16
			}
			if len(message[offset:]) < dhLen+tagLen {
				return nil, nil, errors.New("disco: the received static key is to short")
			}
			var plaintext []byte
			plaintext, err = hs.symmetricState.decryptAndHash(message[offset : offset+dhLen+tagLen])
			if err != nil {
				return
			}
			copy(hs.rs.PublicKey[:], plaintext)
			offset += dhLen + tagLen

		case token_ee:
			hs.symmetricState.mixKey(dh(hs.e, hs.re.PublicKey))

		case token_es:
			if hs.initiator {
				hs.symmetricState.mixKey(dh(hs.e, hs.rs.PublicKey))
			} else {
				hs.symmetricState.mixKey(dh(hs.s, hs.re.PublicKey))
			}

		case token_se:
			if hs.initiator {
				hs.symmetricState.mixKey(dh(hs.s, hs.re.PublicKey))
			} else {
				hs.symmetricState.mixKey(dh(hs.e, hs.rs.PublicKey))
			}

		case token_ss:
			hs.symmetricState.mixKey(dh(hs.s, hs.rs.PublicKey))

		case token_psk:
			hs.symmetricState.mixKeyAndHash(hs.psk)
		}
	}

	// Appends decrpyAndHash(payload) to the buffer
	var plaintext []byte
	plaintext, err = hs.symmetricState.decryptAndHash(message[offset:])
	if err != nil {
		return
	}
	*payloadBuffer = append(*payloadBuffer, plaintext...)

	// remove the pattern from the messagePattern
	if len(hs.messagePatterns) == 1 {
		// If there are no more message patterns returns two new CipherState objects
		hs.messagePatterns = nil
		c1, c2 = hs.symmetricState.Split()
	} else {
		hs.messagePatterns = hs.messagePatterns[1:]
	}

	// change the direction
	hs.shouldWrite = true

	return
}

//
// Clearing stuff
//

// TODO: is there a better way to get rid of secrets in Go?
func (hs *handshakeState) clear() {
	hs.s.clear()
	hs.e.clear()
	hs.rs.clear()
	hs.re.clear()
}

// TODO: is there a better way to get rid of secrets in Go?
func (kp *KeyPair) clear() {
	for i := 0; i < len(kp.PrivateKey); i++ {
		kp.PrivateKey[i] = 0
	}
}
