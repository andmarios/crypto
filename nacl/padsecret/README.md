# padsecret (golang package)

Padsecret provides a simple way to encrypt or decrypt a message using NaCl secret key cryptography.
Optionally it can compress the data before encrypting them.

The encryption key is padded with a user provided pad. Padsecret is very fast, thus it is useful when you
want to exchange many messages. It is less secure from saltsecret, due to the constant user provided pad and
some other design decisions (i.e key arguments as strings).

Beyond the default methods (`Encrypt(msg []byte)`, `Decrypt(msg []byte)`), it also provides an `io.Reader` and an
`io.Writer` interface to decrypt or encrypt data. Since we don't have a stream cipher, these methods need to have available
all the data before they make available their output. For `Writer` this means you have to `Flush()` or `Close()` before
you can read the `io.Writer` you passed to the `Writer`. For `Reader` it means it will block until it reads all the data from
the `io.Reader` you passed to it.

`Read` and `Write` are slower than `Decrypt` and `Encrypt`.

I use it for symmetric-key encryption schemes. Depending on your usage it may or may not be a safe option.
I do not claim any expertise in cryptography.

Note: The compression status is set inside the message (last bit of the nonce), thus whilst you do need to have a common key and padding between two processes exchanging messages, you do not need to have a common compression setting.

## Usage

    import "github.com/andmarios/crypto/nacl/padsecret"

## Example

You may find more examples in the examples directory.

```go
package main

import (
	"github.com/andmarios/crypto/nacl/padsecret"
	"log"
)

func main() {
	// Create a padsecret instance with "qwerty" key and no compression.
	c, err := padsecret.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}

	// Message to be encrypted
	msg := []byte("Hello World")

	// Encrypt message
	encMsg, err := c.Encrypt(msg)
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Decrypt message
	decMsg, err := c.Decrypt(encMsg)
	if err != nil {
		log.Fatalln("Could not decrypt message")
	}
	log.Printf("Decrypted message is '%s'.\n", decMsg)
}
```

## License

You can find more information inside the `LICENSE` file. In short this software uses
a BSD 3-Clause license.
