# cryptographer (golang package)

Cryptographer provides a simple way to encrypt or decrypt a message using NaCl secret key cryptography.
Optionally it can compress the data before encrypting them.

I use it for symmetric-key encryption schemes. Depending on your usage it may or may not be a safe option.
I do not claim any expertise in cryptography.

Note: The compression status is set inside the message (last bit of the nonce), thus whilst you do need to have a common key and padding between two processes exchanging messages, you do not need to have a common compression setting.

## Usage

    import "github.com/andmarios/cryptographer"

## Example

```go
package main

import (
	"github.com/andmarios/cryptographer"
	"log"
)

func main() {
	// Create a cryptographer instance with "qwerty" key and no compression.
	c, err := cryptographer.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
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
