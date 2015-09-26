# crypto (golang) #

Crypto provides two libraries for easy encryption and decryption of data.
It uses NaCl secret-key (symmetric encryption).

Padsecret pads (if needed) the user key with a user-provided pad.
It is less secure but very fast.

Saltsecret creates the encryption key anew for every message by using scrypt and the
user key.
It is more secure but slow.

See the benchmark files or run the benchmarks yourself (`go run test -bench .`) to
make your decision.

You may find documentation and examples in each package's folder.

Also you may check:

https://godoc.org/github.com/andmarios/crypto/nacl/padsecret
https://godoc.org/github.com/andmarios/crypto/nacl/saltsecret
