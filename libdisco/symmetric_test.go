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

func TestEncryptDecrypt(t *testing.T) {

	key, _ := hex.DecodeString("eda8506c1fb0bbcc3f62626fef074bbf2d09a8c7c608f3fa1482c9a625d00f75")
	plaintext := []byte("hello, how are you?")

	ciphertext := Encrypt(key, plaintext)

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatal("Encrypt/Decrypt did not work")
	}

	for idx, _ := range plaintext {
		if plaintext[idx] != decrypted[idx] {
			t.Fatal("Decrypt did not work")
		}
	}
}
