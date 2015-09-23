package cryptographer

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestPackage(t *testing.T) {

	c, err := New("qwerty", "qwertyuiopasdfghjklzxcvbnm12345", false)
	if err == nil {
		t.Errorf("New() accepts pad smaller than 32 bytes")
	}

	c, err = New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		t.Errorf(err.Error())
	}

	cc, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)

	msg := []byte("hello world")

	enc, err := c.Encrypt(msg)
	if err != nil {
		t.Errorf(err.Error())
	}
	encc, err := cc.Encrypt(msg)

	dec, err := c.Decrypt(msg)
	if err == nil {
		t.Errorf("Decrypt() doesn't check for errors.")
	}
	dec, err = c.Decrypt(enc)
	if err != nil {
		t.Errorf(err.Error())
	}

	if bytes.Compare(dec, msg) != 0 {
		t.Errorf("Decoded uncompressed message '%v' differs from uncompressed encoded message '%v'.", dec, msg)
	}

	decc, err := cc.Decrypt(encc)
	if bytes.Compare(decc, msg) != 0 {
		t.Errorf("Decoded compressed message '%v' differs from compressed encoded message '%v'.", dec, msg)
	}
}

func BenchmarkEncryptUncompessed1K(b *testing.B) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	msg := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, msg)

	for n := 0; n < b.N; n++ {
		_, _ = c.Encrypt(msg)
	}
}

func BenchmarkEncryptCompessed1K(b *testing.B) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)
	msg := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, msg)

	for n := 0; n < b.N; n++ {
		_, _ = c.Encrypt(msg)
	}
}

func BenchmarkDecryptUncompessed1K(b *testing.B) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	msg := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, msg)

	msg, _ = c.Encrypt(msg)
	for n := 0; n < b.N; n++ {
		_, _ = c.Decrypt(msg)
	}
}

func BenchmarkDecryptCompessed1K(b *testing.B) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)
	msg := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, msg)

	msg, _ = c.Encrypt(msg)
	for n := 0; n < b.N; n++ {
		_, _ = c.Decrypt(msg)
	}
}
