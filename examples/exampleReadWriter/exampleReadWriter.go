package main

import (
	"bytes"
	"io/ioutil"
	"log"

	"github.com/andmarios/cryptographer"
)

func main() {
	// A 1 kilobyte message
	msg := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam egestas mi ut nisl lobortis rhoncus. Cras et tempus elit. Maecenas dictum viverra pretium. Integer porta felis lacus, ac maximus risus volutpat vel. Vivamus fermentum vitae turpis vitae lobortis. Quisque dictum, nunc eget blandit porttitor, risus nisl aliquam ante, vel congue nibh metus at velit. Suspendisse potenti. Pellentesque quis ipsum vitae tortor condimentum malesuada id vitae enim. Mauris mattis elit quis nibh venenatis, ut finibus mauris pulvinar. Duis facilisis tellus nec laoreet cursus. Sed mattis condimentum condimentum. Aenean a leo vel urna pharetra scelerisque tempor accumsan augue. Sed vel ante id turpis tempus ornare. Quisque lobortis enim auctor ipsum lacinia, et bibendum tortor pellentesque.

Vivamus ut elit nec arcu congue malesuada nec eget enim. Aliquam erat volutpat. Phasellus auctor consequat est et hendrerit. Nullam vitae odio ac nisi blandit viverra. Curabitur consequat urna quis ante molestie viverra. Donec malesuada amet.`)

	// Create a cryptographer Writer instance with compression enabled and "qwerty" as key.
	var encryptedMsg bytes.Buffer
	w, err := cryptographer.NewWriter(&encryptedMsg, "qwerty", "qwertyuiopasdfghjklzxcvbnm123456", true)
	if err != nil {
		log.Fatalln(err)
	}
	// Write the msg to Writer
	w.Write(msg)
	// Call Flush (or Close) so the Writer knows it got all the data and thus can encrypt them.
	w.Flush()

	// Create a cryptographer Reader instance with "qwerty" key and pass to it the encrypted message.
	r, err := cryptographer.NewReader(bytes.NewReader(encryptedMsg.Bytes()), "qwerty", "qwertyuiopasdfghjklzxcvbnm123456")
	if err != nil {
		log.Fatalln(err)
	}
	// Grab the decrypted message from r.
	decryptedMsg, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Decrypted message is:\n" + string(decryptedMsg))

	// Re-use Writer and Reader

	msgNew := []byte("Hello world")

	// Reset the Writer so we may re-use it:
	encryptedMsg.Reset()
	w.Reset(&encryptedMsg)
	// Write the new message and Close (or Flush, exactly the same):
	w.Write(msgNew)
	w.Close()

	// Reset the Reader so we may re-use it:
	r.Reset(bytes.NewReader(encryptedMsg.Bytes()))
	// Now grab the new message:
	decryptedMsg, err = ioutil.ReadAll(r)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Decrypted new message is:\n" + string(decryptedMsg))
}
