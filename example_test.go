package cryptographer_test

import (
	"fmt"
	"log"

	"github.com/andmarios/cryptographer"
)

func ExampleCryptographer_Encrypt() {
	// Create a cryptographer instance with "qwerty" key and no compression.
	c, err := cryptographer.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
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

	fmt.Println("Encrypted message: ", encryptedMsg)
}

func ExampleCryptographer_Decrypt() {
	// Create a cryptographer instance with "qwerty" key and no compression.
	c, err := cryptographer.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}

	encryptedMsg := []byte{173, 25, 228, 30, 140, 142, 245, 186, 114, 121, 122, 174, 252, 221, 52, 154, 25, 3, 119, 18, 222, 148, 0, 80, 32, 190, 67, 167, 34, 69, 7, 38, 5, 139, 165, 56, 32, 131, 13, 185, 10, 43, 148, 3, 81, 181, 31, 155, 48, 209, 169}

	// Decrypt message
	decryptedMsg, err := c.Decrypt(encryptedMsg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Decrypted message is '%s'.\n", decryptedMsg)
	// Output: Decrypted message is 'Hello World'.
}
