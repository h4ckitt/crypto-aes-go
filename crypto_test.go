package cryptoAes

import (
	"testing"
)

func Test_EncryptDecryptSuccess(t *testing.T) {
	cases := []string{"Hello", "Test", "Testing", "The Quick Brown Fox Jumped Over The Lazy Dog"}

	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			encrypted, err := Encrypt(c, c)

			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}

			decrypted, err := Decrypt(encrypted, c)

			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}

			if decrypted != c {
				t.Errorf("Expected %s, got %s", c, decrypted)
			}
		})
	}
}

func Test_EncryptBytesDecrypt(t *testing.T) {
	cases := [][]byte{[]byte("Hello"), []byte("Test"), []byte("Testing"), []byte("The Quick Brown Fox Jumped Over The Lazy Dog")}

	for _, c := range cases {
		t.Run(string(c), func(t *testing.T) {
			encrypted, err := EncryptBytes(c, string(c))

			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}

			decrypted, err := Decrypt(encrypted, string(c))

			if err != nil {
				t.Errorf("Expected no error, got %s", err)
			}

			if decrypted != string(c) {
				t.Errorf("Expected %s, got %s", string(c), decrypted)
			}
		})
	}
}
