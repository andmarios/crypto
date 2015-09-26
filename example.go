// Package crypto provides NaCl based encryption libraries.
package main

import (
	"log"

	"github.com/andmarios/crypto/nacl/padsecret"
	"github.com/andmarios/crypto/nacl/saltsecret"
)

// A 1 kilobyte message
var msg1K = []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam egestas mi ut nisl lobortis rhoncus. Cras et tempus elit. Maecenas dictum viverra pretium. Integer porta felis lacus, ac maximus risus volutpat vel. Vivamus fermentum vitae turpis vitae lobortis. Quisque dictum, nunc eget blandit porttitor, risus nisl aliquam ante, vel congue nibh metus at velit. Suspendisse potenti. Pellentesque quis ipsum vitae tortor condimentum malesuada id vitae enim. Mauris mattis elit quis nibh venenatis, ut finibus mauris pulvinar. Duis facilisis tellus nec laoreet cursus. Sed mattis condimentum condimentum. Aenean a leo vel urna pharetra scelerisque tempor accumsan augue. Sed vel ante id turpis tempus ornare. Quisque lobortis enim auctor ipsum lacinia, et bibendum tortor pellentesque.

Vivamus ut elit nec arcu congue malesuada nec eget enim. Aliquam erat volutpat. Phasellus auctor consequat est et hendrerit. Nullam vitae odio ac nisi blandit viverra. Curabitur consequat urna quis ante molestie viverra. Donec malesuada amet.`)

func main() {
	// Saltsecret //
	// Create a saltsecret instance with "qwerty" key and no compression.
	skey := []byte("qwerty")
	s := saltsecret.New(skey, false)
	// Encrypt message
	sMsg, err := s.Encrypt(msg1K)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Saltsecret uncompressed encrypted 1K message size is %d bytes due to overhead.\n", len(sMsg))
	// Decrypt message
	dMsg, err := s.Decrypt(sMsg)
	if err != nil {
		log.Fatalln("Could not decrypt message")
	}
	log.Println("Saltsecret decrypted message is:\n" + string(dMsg))
	// Create a cryptographer instance with "qwerty" key and compression.
	s = saltsecret.New(skey, true)
	// Encrypt message
	sMsg, err = s.Encrypt(msg1K)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Saltsecret compressed encrypted 1K message size is %d bytes despite overhead.\n", len(sMsg))

	// Padsecret //
	// Create a padsecret instance with "qwerty" key and no compression.
	p, err := padsecret.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}
	// Encrypt message
	pMsg, err := p.Encrypt(msg1K)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Padsecret uncompressed encrypted 1K message size is %d bytes due to overhead.\n", len(pMsg))
	// Decrypt message
	dMsg, err = p.Decrypt(pMsg)
	if err != nil {
		log.Fatalln("Could not decrypt message")
	}
	log.Println("Padsecret decrypted message is:\n" + string(dMsg))
}
