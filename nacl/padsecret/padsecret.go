/*
Package padsecret implements a simple library for on-the-fly
NaCl secret key (symmetric) encryption and decryption with
a padded key.

It is meant to be used for symmetric-key encryption schemes.
Optionally it can (de)compress the data before (dec)encryption.

The user key is padded with a user provided pad. The key is common
for all messages that come from a padsecret instance. This makes
padsecret very fast, albeit less secure.

Beyond the recommended methods (Encrypt, Decrypt) it also implements
the io.ReadWriter interface which is slower. You may run the benchmarks
from padsecret_test.go to decide if it is acceptable.

One bit of the NaCl's nonce is used to indicate whether the message was
compressed before encrypting. Still the algorithm should remain safe
since nonce collisions are again extremely rare.
*/
package padsecret

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"
)

// These are defined in golang.org/x/crypto/nacl/secretbox
const (
	keySize   = 32
	nonceSize = 24
)

const compressBit byte = 0x01

// A PadSecret holds the instance's key and the compression settings.
type PadSecret struct {
	key      *[keySize]byte
	compress bool
}

// New creates a new PadSecret instance. key is the key used for encryption,
// pad is the padding to be used (at least 32 bytes), if the key is smaller than 32 bytes.
// compress indicates whether the data should be compessed (zlib) before encrypting.
// The pad can be a const in your code.
func New(key, pad string, compress bool) (*PadSecret, error) {
	naclKey, err := constructKey(key, pad)
	if err != nil {
		return nil, err
	}
	return &PadSecret{naclKey, compress}, nil
}

func constructKey(key, pad string) (naclKey *[32]byte, e error) {
	tKey := []byte(key)
	tPad := []byte(pad)
	if len(tPad) < 32 {
		return nil, errors.New("padsecret pad should be 32 bytes or more")
	}
	tKey = append(tKey, tPad...)
	naclKey = new([keySize]byte)
	copy(naclKey[:], tKey[:keySize])
	return naclKey, nil
}

// Encrypt encrypts a message and returns the encrypted msg (nonce + ciphertext).
// If you have enabled compression, it will compress the msg before encrypting it.
func (c PadSecret) Encrypt(msg []byte) (out []byte, e error) {
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	// We use the last bit of the nonce as a compression indicator.
	// This should still keep you safe (extremely rare collisions).
	nonce[23] &= ^compressBit

	if c.compress {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		w.Write(msg)
		w.Close()
		msg = b.Bytes()
		nonce[23] |= compressBit
	}

	out = make([]byte, nonceSize)
	copy(out, nonce[:])

	out = secretbox.Seal(out, msg, nonce, c.key)
	return out, nil
}

// Decrypt decrypts an encrypted message and returns it (plaintext).
// If you have enabled compression, it wil detect it and decompress
// the msg after decrypting it.
func (c PadSecret) Decrypt(msg []byte) ([]byte, error) {
	if len(msg) < nonceSize+secretbox.Overhead {
		return nil, errors.New("encrypted message length too short")
	}

	nonce := new([nonceSize]byte)
	copy(nonce[:], msg[:nonceSize])

	out, ok := secretbox.Open(nil, msg[nonceSize:], nonce, c.key)
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

// A Reader reads data from another Reader, decrypts and, if needed,
// decompress them into a []byte variable.
// A Reader may be re-used by using Reset.
type Reader struct {
	r         io.Reader
	msg       []byte
	done      bool
	firstRead bool
	c         *PadSecret
}

func newInternal(naclKey *[32]byte, compress bool) *PadSecret {
	return &PadSecret{naclKey, compress}
}

// NewReader creates a new Reader. Reads from the returned Reader read,
// unencrypt and decompress, if needed, data from r. The implementation
// needs to read all data from r at once, since we do not use a stream
// cipher. Pad should be at least 32 bytes long.
func NewReader(r io.Reader, key, pad string) (*Reader, error) {
	naclKey, err := constructKey(key, pad)
	if err != nil {
		return nil, err
	}
	return &Reader{r, nil, false, true, newInternal(naclKey, false)}, nil
}

// Read reads into p an unecrypted and, if needed, uncompressed form
// of the bytes from the underlying Reader. Read needs to read all
// data from the underlying Reader before it can decrypt them.
func (d *Reader) Read(p []byte) (n int, err error) {
	if d.done {
		return 0, io.EOF
	}

	msg, err := ioutil.ReadAll(d.r)
	if err != nil {
		return 0, err
	}

	if d.firstRead {
		d.msg, err = d.c.Decrypt(msg)
		if err != nil {
			d.done = true
			return 0, errors.New("could not decrypt input: " + err.Error())
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

// A Writer takes data written to it and writes the encrypted and, if needed,
// compressed form of that data to an underlying writer.
type Writer struct {
	w           io.Writer
	unencrypted []byte
	c           *PadSecret
}

// NewWriter creates a new writer. Writes to the returned Writer are encrypted and,
// if needed, compressed and written to w.
//
// It is the caller's responsibility to call Close() on WriteCloser when done, since
// we do not use a stream cipher, we need to have all the data before encrypting them.
func NewWriter(w io.Writer, key, pad string, compress bool) (*Writer, error) {
	naclKey, err := constructKey(key, pad)
	if err != nil {
		return nil, err
	}
	return &Writer{w, nil, newInternal(naclKey, compress)}, nil
}

// Write writes and encrypted and, if needed, compressed form of p to the underlying
// io.Writer. The compressed bytes are not written until the Writer is closed or
// explicitly flushed.
func (e *Writer) Write(p []byte) (n int, err error) {
	e.unencrypted = append(e.unencrypted, p...)
	return len(p), nil
}

// Flush encrypts and compresses, if needed, the data written to the writer.
// After a Flush, the writer has to be Reset in order to write to it again.
func (e *Writer) Flush() error {
	var err error
	write, err := e.c.Encrypt(e.unencrypted)
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
	e.unencrypted = nil
}
