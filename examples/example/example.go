package main

import (
	"log"

	"github.com/andmarios/cryptographer"
)

func main() {
	// Create a cryptographer instance with "qwerty" key and no compression.
	c, err := cryptographer.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", false)
	if err != nil {
		log.Fatalln(err)
	}

	// A 1 kilobyte message
	msg1K := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam egestas mi ut nisl lobortis rhoncus. Cras et tempus elit. Maecenas dictum viverra pretium. Integer porta felis lacus, ac maximus risus volutpat vel. Vivamus fermentum vitae turpis vitae lobortis. Quisque dictum, nunc eget blandit porttitor, risus nisl aliquam ante, vel congue nibh metus at velit. Suspendisse potenti. Pellentesque quis ipsum vitae tortor condimentum malesuada id vitae enim. Mauris mattis elit quis nibh venenatis, ut finibus mauris pulvinar. Duis facilisis tellus nec laoreet cursus. Sed mattis condimentum condimentum. Aenean a leo vel urna pharetra scelerisque tempor accumsan augue. Sed vel ante id turpis tempus ornare. Quisque lobortis enim auctor ipsum lacinia, et bibendum tortor pellentesque.

Vivamus ut elit nec arcu congue malesuada nec eget enim. Aliquam erat volutpat. Phasellus auctor consequat est et hendrerit. Nullam vitae odio ac nisi blandit viverra. Curabitur consequat urna quis ante molestie viverra. Donec malesuada amet.`)

	// Encrypt message
	encMsg, err := c.Encrypt(msg1K)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Uncompressed encrypted 1K message size is %d bytes due to overhead.\n", len(encMsg))

	// Decrypt message
	decMsg, err := c.Decrypt(encMsg)
	if err != nil {
		log.Fatalln("Could not decrypt message")
	}
	log.Println("Decrypted message is:\n" + string(decMsg))

	// Create a cryptographer instance with "qwerty" key and compression.
	c, err = cryptographer.New("qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)
	if err != nil {
		log.Fatalln(err)
	}
	// Encrypt message
	encMsg, err = c.Encrypt(msg1K)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Compressed encrypted 1K message size is %d bytes despite overhead.\n", len(encMsg))
}
