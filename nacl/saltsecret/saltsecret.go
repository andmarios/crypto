/*
Package saltsecret implements a simple library for on-the-fly
NaCl secret key (symmetric) encryption and decryption with a
scrypt derived key.

It is meant to be used for symmetric-key encryption schemes.
Optionally it can (de)compress the data before (dec)encryption.

The encryption key is derived from the user provided key and a random
salt for each encryption operation. The salt is used as NaCl's nonce,
so that the receiver can decrypt the message. The key derivation function
(scrypt) makes saltsecret more secure but also very slow. It is more useful
for when you want to exchange a few messages, or for very large messages.

Beyond the recommended methods (Encrypt, Decrypt) it also implements
the io.ReadWriter interface.

One bit of the NaCl's nonce is used to indicate whether the message was
compressed before encrypting. Still the algorithm should remain safe
since nonce collisions are again extremely rare.
*/
package saltsecret

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// Operation mode for Reader and Writer
const (
	ENCRYPT = iota
	DECRYPT
)

// These are defined in golang.org/x/crypto/nacl/secretbox
const (
	keySize   = 32
	nonceSize = 24
)

const compressBit byte = 0x01

// A SaltSecret holds the instance's key and the compression settings.
type SaltSecret struct {
	key      []byte
	compress bool
}

// New creates a new SaltSecret instance. key is the key used for encryption.
// For every message the encryption key will be derived by the key and a random salt.
// compress indicates whether the data should be compessed (zlib) before encrypting.
func New(key []byte, compress bool) *SaltSecret {
	return &SaltSecret{key, compress}
}

// Encrypt encrypts a message and returns the encrypted msg (nonce + ciphertext).
// If you have enabled compression, it will compress the msg before encrypting it.
func (c SaltSecret) Encrypt(msg []byte) (out []byte, e error) {
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	// We use the last bit of the nonce as a compression indicator.
	// This should still keep you safe (extremely rare collisions).
	nonce[23] &= ^compressBit
	if c.compress {
		nonce[23] |= compressBit
	}

	key, err := scrypt.Key(c.key, nonce[:], 2<<14, 8, 1, keySize)
	if err != nil {
		return nil, err
	}

	if c.compress {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(msg)
		w.Close()
		msg = b.Bytes()
	}

	out = make([]byte, nonceSize)
	copy(out, nonce[:])
	naclKey := new([keySize]byte)
	copy(naclKey[:], key)
	out = secretbox.Seal(out, msg, nonce, naclKey)
	return out, nil
}

// Decrypt decrypts an encrypted message and returns it (plaintext).
// If you have enabled compression, it wil detect it and decompress
// the msg after decrypting it.
func (c SaltSecret) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < nonceSize+secretbox.Overhead {
		return nil, errors.New("encrypted message length too short")
	}

	nonce := new([nonceSize]byte)
	copy(nonce[:], msg[:nonceSize])

	key, err := scrypt.Key(c.key, nonce[:], 2<<14, 8, 1, keySize)
	if err != nil {
		return nil, err
	}

	naclKey := new([keySize]byte)
	copy(naclKey[:], key)
	out, ok := secretbox.Open(nil, msg[nonceSize:], nonce, naclKey)
	if !ok {
		return nil, errors.New("could not decrypt message")
	}

	if nonce[23]&compressBit == compressBit {
		r, err := zlib.NewReader(bytes.NewReader(out))
		if err != nil {
			return nil, err
		}
		r.Close()
		out, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// A Reader reads data from another Reader, encrypts or decrypts and,
// if needed, (de)compress them into a []byte variable.
// A Reader may be re-used by using Reset.
type Reader struct {
	r         io.Reader
	msg       []byte
	done      bool
	firstRead bool
	c         *SaltSecret
	mode      int
}

// NewReader creates a new Reader. Reads from the returned Reader read,
// encrypt or decrypt (and (de)compress, if needed), data from r.
// The implementation needs to read all data from r at once, since we do
// not use a stream cipher. mode is either saltsecret.ENCRYPT (0), or
// saltsecret.DECRYPT (1).
func NewReader(r io.Reader, key []byte, mode int, compress bool) (*Reader, error) {
	if mode != ENCRYPT && mode != DECRYPT {
		return &Reader{}, errors.New("Mode should be saltsecret.ENCRYPT or saltsecret.DECRYPT.")
	}
	return &Reader{r, nil, false, true, &SaltSecret{key, compress}, mode}, nil
}

// Read reads into p an encrypted or decrypted and, if needed, (de)compressed
// form of the bytes from the underlying Reader. Read needs to read all
// data from the underlying Reader before it can operate on them.
func (d *Reader) Read(p []byte) (n int, err error) {
	if d.done {
		return 0, io.EOF
	}

	msg, err := ioutil.ReadAll(d.r)
	if err != nil {
		return 0, err
	}

	if d.firstRead {
		switch d.mode {
		case DECRYPT:
			d.msg, err = d.c.Decrypt(msg)
		case ENCRYPT:
			d.msg, err = d.c.Encrypt(msg)
		}
		if err != nil {
			d.done = true
			return 0, errors.New("could not operate on input: " + err.Error())
		}
		d.firstRead = false
	}

	length := len(d.msg)
	if len(p) < length {
		length = len(p)
	}
	for i := 0; i < length; i++ {
		p[i] = d.msg[i]
	}
	if length < len(d.msg) {
		d.msg = d.msg[len(p):]
	} else {
		d.msg = d.msg[:0]
		d.done = true
	}
	return length, nil
}

// Reset returns Reader to its initial state, except it now reads from r.
func (d *Reader) Reset(r io.Reader) {
	d.r = r
	d.msg = nil
	d.done = false
	d.firstRead = true
}

// A Writer takes data written to it and writes the encrypted or decrypted
// and, if needed, (de)compressed form of that data to an underlying writer.
type Writer struct {
	w    io.Writer
	in   []byte
	c    *SaltSecret
	mode int
}

// NewWriter creates a new writer. Writes to the returned Writer are encrypted or
// decrypted and, if needed, (de)compressed and written to w.
//
// It is the caller's responsibility to call Close() on WriteCloser when done, since
// we do not use a stream cipher, we need to have all the data before operating on them.
func NewWriter(w io.Writer, key []byte, mode int, compress bool) (*Writer, error) {
	if mode != ENCRYPT && mode != DECRYPT {
		return &Writer{}, errors.New("Mode should be saltsecret.ENCRYPT or saltsecret.DECRYPT.")
	}
	return &Writer{w, nil, &SaltSecret{key, compress}, mode}, nil
}

// Write writes and encrypts or decrypts (and, if needed, a (de)compressed) form of p to the underlying
// io.Writer. The produced bytes are not written until the Writer is closed or
// explicitly flushed.
func (e *Writer) Write(p []byte) (n int, err error) {
	e.in = append(e.in, p...)
	return len(p), nil
}

// Flush encrypt or decrypts  and (de)compresses, if needed, the data written to the writer.
// After a Flush, the writer has to be Reset in order to write to it again.
func (e *Writer) Flush() error {
	var err error
	write := make([]byte, 0)
	switch e.mode {
	case ENCRYPT:
		write, err = e.c.Encrypt(e.in)
	case DECRYPT:
		write, err = e.c.Decrypt(e.in)
	}
	if err != nil {
		return err
	}
	_, err = e.w.Write(write)
	if err != nil {
		return err
	}
	return nil
}

// Close acts as a placeholder for Flush.
func (e *Writer) Close() error {
	return e.Flush()
}

// Reset clears the sate of the Writer w such that it is equivalent to its
// initial state from NewWriter, but instead writing to w.
func (e *Writer) Reset(w io.Writer) {
	e.w = w
	e.in = nil
}
