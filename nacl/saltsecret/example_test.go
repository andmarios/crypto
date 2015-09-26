package saltsecret_test

import (
	"fmt"
	"log"

	"github.com/andmarios/crypto/nacl/saltsecret"
)

func ExampleSaltSecret_Encrypt() {
	// Create a saltsecret instance with "password" key and no compression.
	key := []byte("password")
	c := saltsecret.New(key, false)

	// Message to be encrypted
	msg := []byte("Hello World")

	// Encrypt message
	encryptedMsg, err := c.Encrypt(msg)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Encrypted message:", encryptedMsg)
}

func ExampleSaltSecret_Decrypt() {
	// Create a saltsecret instance with "password" key and no compression.
	key := []byte("password")
	c := saltsecret.New(key, false)

	encryptedMsg := []byte{40, 145, 30, 139, 112, 75, 178, 223, 40, 199,
		146, 158, 49, 40, 197, 98, 80, 34, 74, 6, 231, 13, 250, 240, 18,
		194, 143, 4, 137, 47, 181, 95, 193, 7, 142, 148, 160, 12, 55,
		140, 229, 223, 49, 4, 115, 165, 125, 206, 187, 13, 52}

	// Decrypt message
	decryptedMsg, err := c.Decrypt(encryptedMsg)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Decrypted message is '%s'.\n", decryptedMsg)
	// DEPOutput: Decrypted message is 'Hello World'.
}
