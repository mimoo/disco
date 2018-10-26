package libdisco

import (
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {

	input := []byte("hi, how are you?")

	if hex.EncodeToString(Hash(input, 32)) != "eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75" {
		t.Fatal("Hash does not produce a correct output")
	}
}

func TestSum(t *testing.T) {
	message1 := "hello"
	message2 := "how are you good sir?"
	message3 := "sure thing"
	fullmessage := message1 + message2

	// trying with NewHash with streaming and without streaming
	h1 := NewHash(32)
	h1.Write([]byte(message1))
	h1.Write([]byte(message2))
	out1 := h1.Sum()

	h2 := NewHash(32)
	h2.Write([]byte(fullmessage))
	out2 := h2.Sum()

	for idx, _ := range out1 {
		if out1[idx] != out2[idx] {
			t.Fatal("Sum function does not work")
		}
	}

	// trying with Hash()
	out3 := Hash([]byte(fullmessage), 32)

	for idx, _ := range out1 {
		if out1[idx] != out3[idx] {
			t.Fatal("Sum function does not work")
		}
	}

	// trying the streaming even more
	h1.Write([]byte(message3))
	out1 = h1.Sum()
	h2.Write([]byte(message3))
	out2 = h2.Sum()

	for idx, _ := range out1 {
		if out1[idx] != out2[idx] {
			t.Fatal("Sum function does not work")
		}
	}

	// tring with Hash()
	out3 = Hash([]byte(fullmessage+message3), 32)

	for idx, _ := range out1 {
		if out1[idx] != out3[idx] {
			t.Fatal("Sum function does not work")
		}
	}
}

func TestHashOutputHashOutput(t *testing.T) {
	message1 := "hello"
	message2 := "how are you good sir?"
	message3 := "sure thing"

	h1 := NewHash(32)
	h1.Write([]byte(message1))
	h1.Write([]byte(message2))
	h1.Sum() // this should not affect the state
	h1.Write([]byte(message3))
	out1 := h1.Sum()

	h2 := NewHash(32)
	h2.Write([]byte(message1))
	h2.Write([]byte(message2))
	h2.Write([]byte(message3))
	out2 := h2.Sum()

	for idx, _ := range out1 {
		if out1[idx] != out2[idx] {
			t.Fatal("Sum function affects the hash state")
		}
	}
}

func TestTupleHash(t *testing.T) {
	message1 := "the plasma"
	message2 := "screen is broken, we need to do something about it!"
	message3 := "\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05\x00\x01\x02\x03\x04\x05"
	message4 := "HAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHAHA"

	// trying with NewHash with streaming and without streaming
	h1 := NewHash(32)
	h1.Write([]byte(message1))
	h1.Write([]byte(message2))
	h1.Write([]byte(message3))
	out1 := h1.Sum()

	h2 := NewHash(32)
	h2.WriteTuple([]byte(message1))
	h1.WriteTuple([]byte(message2))
	h1.WriteTuple([]byte(message3))
	out2 := h2.Sum()

	same := true
	for idx, _ := range out1 {
		if out1[idx] != out2[idx] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("Tuple hashing should be different from stream hashing")
	}

	// trying a hybrid with streaming
	h3 := NewHash(32)
	h3.WriteTuple([]byte(message1))
	h3.Write([]byte(message2))
	h3.Write([]byte(message3))
	h3.WriteTuple([]byte(message4))
	out3 := h3.Sum()

	h4 := NewHash(32)
	h4.WriteTuple([]byte(message1))
	h4.WriteTuple([]byte(message2 + message3))
	h4.WriteTuple([]byte(message4))
	out4 := h4.Sum()

	for idx, _ := range out3 {
		if out3[idx] != out4[idx] {
			t.Fatal("Tuple hashing doesn't work properly with streaming")
		}
	}
}

func TestDeriveKeys(t *testing.T) {

	input := []byte("hi, how are you?")

	if hex.EncodeToString(DeriveKeys(input, 64)) != "d6350bb9b83884774fb9b0881680fc656be1071fff75d3fa94519d50a10b92644e3cc1cae166a60167d7bf00137018345bb8057be4b09f937b0e12066d5dc3df" {
		t.Fatal("DeriveKeys does not produce a correct output")
	}
}

func TestProtectVerifyIntegrity(t *testing.T) {
	key, _ := hex.DecodeString("eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75")

	message := []byte("hoy, how are you?")

	plaintextAndTag := ProtectIntegrity(key, message)

	retrievedMessage, err := VerifyIntegrity(key, plaintextAndTag)

	if err != nil {
		t.Fatal("Protect/Verify did not work")
	}
	for idx, _ := range message {
		if message[idx] != retrievedMessage[idx] {
			t.Fatal("Verify did not work")
		}
	}

	// tamper
	plaintextAndTag[len(plaintextAndTag)-1] += 1

	_, err = VerifyIntegrity(key, plaintextAndTag)
	if err == nil {
		t.Fatal("Verify did not work")
	}

}

func TestNonceSize(t *testing.T) {
	key, _ := hex.DecodeString("eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75")
	plaintext := []byte("hello, how are you?")
	ciphertext := Encrypt(key, plaintext)
	if len(ciphertext) != 19+16+24 {
		t.Fatal("Length of this ciphertext should be 19B (PT) + 16B (TAG) + 24B (NONCE)")
	}
}

func TestEncryptDecrypt(t *testing.T) {

	key, _ := hex.DecodeString("eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75")
	plaintexts := []string{
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"short",
		"hello, how are you?",
		"this is very short",
		"this is very long though, like, very very long, should we test very very long things here?",
	}
	for _, plaintext := range plaintexts {
		plaintextBytes := []byte(plaintext)
		ciphertext := Encrypt(key, plaintextBytes)
		decrypted, err := Decrypt(key, ciphertext)
		if err != nil {
			t.Fatal("Encrypt/Decrypt did not work")
		}
		if len(plaintext) != len(decrypted) {
			t.Fatal("Decrypt did not work")
		}
		for idx, _ := range plaintext {
			if plaintext[idx] != decrypted[idx] {
				t.Fatal("Decrypt did not work")
			}
		}
	}
}

func TestEncryptDecryptAndAuthenticate(t *testing.T) {

	key, _ := hex.DecodeString("eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75")
	plaintexts := []string{
		"",
		"a",
		"ab",
		"abc",
		"abcd",
		"short",
		"hello, how are you?",
		"this is very short",
		"this is very long though, like, very very long, should we test very very long things here?",
	}
	ad := []string{
		"blou blou",
		"a",
		"haahahAHAHAHhahaHAHAHahah so funny",
		"you must be fun at parties",
		"this is insanely long oh lala voulait dire le boulanger. C'est a dire que. Je ne sais pas. Merci.",
		"do I really need to do this? This is not fun anymore. Help me please. I am stuck in a keyboard and nobody knows I am here. This is getting quite uncomfortable",
		"bunch of \x00 and stuff \x00 you know",
		"89032",
		"9032ir9032kf9032fk093fewk90 fkwe09fk 903i2r 0932ir 0932ir 3029ir 230rk we0rkwe 09rkwer9 w0ekrw e09rkwe 09rew",
	}
	for idx, plaintext := range plaintexts {
		plaintextBytes := []byte(plaintext)
		adBytes := []byte(ad[idx])
		ciphertext := EncryptAndAuthenticate(key, plaintextBytes, adBytes)
		decrypted, err := DecryptAndAuthenticate(key, ciphertext, adBytes)
		if err != nil {
			t.Fatal("Encrypt/Decrypt did not work")
		}
		if len(plaintext) != len(decrypted) {
			t.Fatal("Decrypt did not work")
		}
		for idx, _ := range plaintext {
			if plaintext[idx] != decrypted[idx] {
				t.Fatal("Decrypt did not work")
			}
		}
	}
}
