/*
   Package cryptographer implements a simple library for on-the-fly
   NaCl secret key encryption and decryption.

   It is meant to be used for symmetric-key encryption schemes.
   Optionally it can (de)compress the data before (dec)encryption.

*/
package cryptographer

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

// These are defined in golang.org/x/crypto/nacl/secretbox
const (
	keySize   = 32
	nonceSize = 24
)

// A Cryptographer holds the instance's key and the compression settings.
type Cryptographer struct {
	key      *[keySize]byte
	compress bool
}

// New creates a new Cryptographer instance. key is the key used for encryption,
// pad is the padding to be used (at least 32 bytes), if the key is smaller than 32 bytes.
// compress indicates whether the data should be compessed (zlib) before encrypting.
// The pad can be a const in your code.
func New(key, pad string, compress bool) (*Cryptographer, error) {
	tKey := []byte(key)
	tPad := []byte(pad)
	if len(tPad) < 32 {
		return nil, errors.New("cryptographer pad should be 32 bytes or more")
	}
	tKey = append(tKey, tPad...)
	naclKey := new([keySize]byte)
	copy(naclKey[:], tKey[:keySize])
	return &Cryptographer{naclKey, compress}, nil
}

// Encrypt encrypts a message and returns the encrypted msg (nonce + ciphertext).
// If you have enabled compression, it will compress the msg before encrypting it.
func (c Cryptographer) Encrypt(msg []byte) (out []byte, e error) {
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	out = make([]byte, nonceSize)
	copy(out, nonce[:])

	if c.compress {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(msg)
		w.Close()
		msg = b.Bytes()
	}

	out = secretbox.Seal(out, msg, nonce, c.key)
	return out, nil
}

// Decrypt decrypts an encrypted message and returns it (plaintext).
// If you have enabled compression, it wil decompress the msg after decrypting it.
func (c Cryptographer) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < nonceSize+secretbox.Overhead {
		return nil, errors.New("encrypted message length too short")
	}

	nonce := new([nonceSize]byte)
	copy(nonce[:], msg[:nonceSize])

	out, ok := secretbox.Open(nil, msg[nonceSize:], nonce, c.key)
	if !ok {
		return nil, errors.New("could not decrypt message")
	}

	if c.compress {
		b := new(bytes.Buffer)
		r, err := zlib.NewReader(bytes.NewReader(out))
		if err != nil {
			return nil, err
		}
		r.Close()
		_, err = io.Copy(b, r)
		if err != nil {
			return nil, err
		}
		out = b.Bytes()
	}
	return out, nil
}
