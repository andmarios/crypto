package cryptographer_test

import (
	"fmt"
	"log"

	"github.com/andmarios/cryptographer"
)

func ExampleCryptographer_Encrypt() {
	// Create a cryptographer instance with "password" key and no compression.
	c, err := cryptographer.New("password", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}

	// Message to be encrypted
	msg := []byte("Hello World")

	// Encrypt message
	encryptedMsg, err := c.Encrypt(msg)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Encrypted message:", encryptedMsg)
}

func ExampleCryptographer_Decrypt() {
	// Create a cryptographer instance with "password" key and no compression.
	c, err := cryptographer.New("password", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}

	encryptedMsg := []byte{24, 68, 38, 21, 142, 73, 109, 222, 45, 135, 233,
		83, 12, 196, 148, 10, 195, 133, 33, 12, 86, 15, 78, 100, 164,
		74, 190, 96, 174, 182, 134, 119, 13, 12, 132, 189, 125, 16, 205,
		79, 14, 204, 15, 20, 235, 42, 24, 4, 7, 82, 39}

	// Decrypt message
	decryptedMsg, err := c.Decrypt(encryptedMsg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Decrypted message is '%s'.\n", decryptedMsg)
	// Output: Decrypted message is 'Hello World'.
}
