package padsecret

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
		t.Errorf("Decoded compressed message '%v' differs from compressed encoded message '%v' when using a compressing and a non-compressing padsecret instance.", dec, msg)
	}

	r, err := NewReader(bytes.NewReader(enc), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", 2, false)
	if err == nil {
		t.Errorf("NewReader() accepts non existant mode.")
	}
	r, _ = NewReader(bytes.NewReader(enc), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", DECRYPT, false)
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

	re, _ := NewReader(bytes.NewReader(msg), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", ENCRYPT, false)
	recr, _ := ioutil.ReadAll(re)
	drecr, err := c.Decrypt(recr)
	if bytes.Compare(drecr, msg) != 0 {
		t.Errorf("Reader() encrypt failed. Decoded message '%v' differs from encoded message '%v'.", drecr, msg)
	}

	var encr bytes.Buffer
	w, err := NewWriter(&encr, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", 2, true)
	if err == nil {
		t.Errorf("NewWriter() accepts non existant mode.")
	}
	w, _ = NewWriter(&encr, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", ENCRYPT, true)
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

	var dwncr bytes.Buffer
	wd, _ := NewWriter(&dwncr, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", DECRYPT, true)
	wd.Write(encrr.Bytes())
	wd.Flush()
	if bytes.Compare(dwncr.Bytes(), msg) != 0 {
		t.Errorf("Writer() decrypt failed. Decoded message '%v' differs from encoded message '%v'.", dwncr.Bytes(), msg)
	}

	bigMsg := make([]byte, 1024*1024) // 1MiB
	_, _ = io.ReadFull(rand.Reader, bigMsg)

	bigEnc, err := c.Encrypt(bigMsg)
	if err != nil {
		t.Errorf(err.Error())
	}
	bigDec, err := c.Decrypt(bigEnc)
	if err != nil {
		t.Errorf(err.Error())
	}
	if bytes.Compare(bigDec, bigMsg) != 0 {
		t.Errorf("Decoded big message (len: %d bytes) differs from encoded big message (len: %d bytes).", len(bigDec), len(bigMsg))
	}
	r.Reset(bytes.NewReader(bigEnc))
	bigDecr, err := ioutil.ReadAll(r)
	if err != nil {
		t.Errorf("Error while decoding with reset big Reader.", err)
	}
	if bytes.Compare(bigDecr, bigMsg) != 0 {
		t.Errorf("Reset() Reader failed. Decoded message '%v' differs from encoded message '%v'.", decrr, msg)
	}
	encr.Reset()
	w.Reset(&encr)
	w.Write(bigMsg)
	w.Close()
	bigDencr, err := c.Decrypt(encr.Bytes())
	if err != nil {
		t.Errorf("Error while decrypting big Writer() output.", err)
	}
	if bytes.Compare(bigDencr, bigMsg) != 0 {
		t.Errorf("Big Writer() failed. Decoded big message (len: %d bytes) differs from encoded big message (len: %d bytes).", len(bigDencr), len(bigMsg))
	}
}

func benchmarkEncrypt(b *testing.B, compress bool, msgLength int) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", compress)
	msg := make([]byte, msgLength)
	_, _ = io.ReadFull(rand.Reader, msg)

	for n := 0; n < b.N; n++ {
		_, _ = c.Encrypt(msg)
	}
}

func benchmarkDecrypt(b *testing.B, compress bool, msgLength int) {
	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", compress)
	msg := make([]byte, msgLength)
	_, _ = io.ReadFull(rand.Reader, msg)

	msg, _ = c.Encrypt(msg)
	for n := 0; n < b.N; n++ {
		_, _ = c.Decrypt(msg)
	}
}

func benchmarkWriter(b *testing.B, compress bool, msgLength int) {
	msg := make([]byte, msgLength)
	_, _ = io.ReadFull(rand.Reader, msg)

	w, _ := NewWriter(nil, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", ENCRYPT, compress)

	for n := 0; n < b.N; n++ {
		var enc bytes.Buffer
		w.Reset(&enc)
		w.Write(msg)
		w.Flush()
	}
}

func benchmarkReader(b *testing.B, compress bool, msgLength int) {
	msg := make([]byte, msgLength)
	_, _ = io.ReadFull(rand.Reader, msg)

	c, _ := New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", compress)
	enc, _ := c.Encrypt(msg)

	r, _ := NewReader(nil, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", DECRYPT, false)

	buf := bytes.NewReader(enc)
	readbuf := make([]byte, 1024)

	for n := 0; n < b.N; n++ {
		_, _ = buf.Seek(0, 0)
		r.Reset(buf)
		_, _ = r.Read(readbuf)
	}
}

func BenchmarkEncryptUncompessed100b(b *testing.B) {
	benchmarkEncrypt(b, false, 100)
}
func BenchmarkEncryptUncompessed1K(b *testing.B) {
	benchmarkEncrypt(b, false, 1024)
}

func BenchmarkEncryptUncompessed1M(b *testing.B) {
	benchmarkEncrypt(b, false, 1024*1024)
}

func BenchmarkEncryptCompessed100b(b *testing.B) {
	benchmarkEncrypt(b, true, 100)
}

func BenchmarkEncryptCompessed1K(b *testing.B) {
	benchmarkEncrypt(b, true, 1024)
}

func BenchmarkEncryptCompessed1M(b *testing.B) {
	benchmarkEncrypt(b, true, 1024*1024)
}

func BenchmarkDecryptUncompessed100b(b *testing.B) {
	benchmarkDecrypt(b, false, 100)
}

func BenchmarkDecryptUncompessed1K(b *testing.B) {
	benchmarkDecrypt(b, false, 1024)
}

func BenchmarkDecryptUncompessed1M(b *testing.B) {
	benchmarkDecrypt(b, false, 1024*1024)
}

func BenchmarkDecryptCompessed100b(b *testing.B) {
	benchmarkDecrypt(b, true, 100)
}

func BenchmarkDecryptCompessed1K(b *testing.B) {
	benchmarkDecrypt(b, true, 1024)
}

func BenchmarkDecryptCompessed1M(b *testing.B) {
	benchmarkDecrypt(b, true, 1024*1024)
}

func BenchmarkEncrypWriterUncompressed100b(b *testing.B) {
	benchmarkWriter(b, false, 100)
}

func BenchmarkEncrypWriterUncompressed1K(b *testing.B) {
	benchmarkWriter(b, false, 1024)
}

func BenchmarkEncrypWriterUncompressed1M(b *testing.B) {
	benchmarkWriter(b, false, 1024*1024)
}

func BenchmarkEncrypWriterCompressed1b(b *testing.B) {
	benchmarkWriter(b, true, 100)
}

func BenchmarkEncrypWriterCompressed1K(b *testing.B) {
	benchmarkWriter(b, true, 1024)
}

func BenchmarkEncrypWriterCompressed1M(b *testing.B) {
	benchmarkWriter(b, true, 1024*1024)
}

func BenchmarkDecryptReaderUncompressed100b(b *testing.B) {
	benchmarkReader(b, false, 100)
}

func BenchmarkDecryptReaderUncompressed1K(b *testing.B) {
	benchmarkReader(b, false, 1024)
}

func BenchmarkDecryptReaderUncompressed1M(b *testing.B) {
	benchmarkReader(b, false, 1024*1024)
}

func BenchmarkDecryptReaderCompressed100b(b *testing.B) {
	benchmarkReader(b, true, 100)
}

func BenchmarkDecryptReaderCompressed1K(b *testing.B) {
	benchmarkReader(b, true, 1024)
}

func BenchmarkDecryptReaderCompressed1M(b *testing.B) {
	benchmarkReader(b, true, 1024*1024)
}
