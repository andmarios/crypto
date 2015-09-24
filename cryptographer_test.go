package cryptographer

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
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

	decc, err = c.Decrypt(encc)
	if bytes.Compare(decc, msg) != 0 {
		t.Errorf("Decoded compressed message '%v' differs from compressed encoded message '%v' when using a compressing and a non-compressing cryptographer instance.", dec, msg)
	}

	r, _ := NewReader(bytes.NewReader(enc), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456")
	decr, err := ioutil.ReadAll(r)
	if err != nil {
		t.Errorf("Error while decoding with Reader.", err)
	}
	if bytes.Compare(decr, msg) != 0 {
		t.Errorf("Reader() failed. Decoded message '%v' differs from encoded message '%v'.", decr, msg)
	}

	r.Reset(bytes.NewReader(encc))
	decrr, err := ioutil.ReadAll(r)
	if err != nil {
		t.Errorf("Error while decoding with reset Reader.", err)
	}
	if bytes.Compare(decrr, msg) != 0 {
		t.Errorf("Reset() Reader failed. Decoded message '%v' differs from encoded message '%v'.", decrr, msg)
	}

	var encr bytes.Buffer
	w, _ := NewWriter(&encr, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)
	w.Write(msg)
	w.Flush()
	dencr, err := c.Decrypt(encr.Bytes())
	if err != nil {
		t.Errorf("Error while decrypting Writer() output.", err)
	}
	if bytes.Compare(dencr, msg) != 0 {
		t.Errorf("Writer() failed. Decoded message '%v' differs from encoded message '%v'.", dencr, msg)
	}

	var encrr bytes.Buffer
	w.Reset(&encrr)
	w.Write(msg)
	w.Close()
	dencrr, err := c.Decrypt(encrr.Bytes())
	if err != nil {
		t.Errorf("Error while decrypting reset Writer() output.", err)
	}
	if bytes.Compare(dencrr, msg) != 0 {
		t.Errorf("Reset() Writer failed. Decoded message '%v' differs from encoded message '%v'.", dencrr, msg)
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

func BenchmarkReaderUncompressed1K(b *testing.B) {
	msg := make([]byte, 1024)
	_, _ = io.ReadFull(rand.Reader, msg)

	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	msg, _ = c.Encrypt(msg)

	for n := 0; n < b.N; n++ {
		r, _ := NewReader(bytes.NewReader(msg), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456")
		_, _ = ioutil.ReadAll(r)
	}
}
