# Public Private RSA keys basics encrypt/decrypt/sign/validate 

Basic implementation on RSA public private pairs, allowing encrypted and secure communication between client to server.
A double keyPair will be generated (client and server), and both will exchange their public keys with the remote side.

So that:
- Client wants to send messages over a public transport, messages will be encrypted using server public key allowing decryption just to be decrypted by server private key.
- Client wants to sign messages avoiding any possible tampering issue, messages will be signed using client private key. Signature validation will be done server side using client public Key

### Concept commands
You can find config globals as flags on root cmd

Generate Key Pair (dump contents to StdOut)
```
    go run main.go generate
```

Encrypt using server public Key
```
    go run main.go encrypt
```

Sign message using client private key
```
    go run main.go sign
```

Decrypt using server private Key
```
    go run main.go decrypt
```

Validate message signature using client public key (expected base64 encoded signature)
```
    go run main.go validate --signature "s+6iHlXK+xoCn0Kr16PhIJcbGyq7s4gu2WBSl7Urgnro4F3AzhmH9QPDKl9r9XKb+/0ARdE633eFANCYEO18CYSM5FhNg1qgSJbojMfsTtUN0AtK9Wf9mExi6Se+PM6QkKnnpgRm+F/PwWpQN9Ke/YHtG4bUVNGHoB2PGPXJVBYk6sCTL1X/Sh2IysAeQ9Jn4Z9xb0lZe9nhCGspLLQwtduR4hDD2rC7DYww6mZrLzOaMHF7KqgD1NDPupAdTMVZyUwVfibOk4TuAtumcc7riXWrxnZccGeEgAV9RViSYe5zHNAcHG606SrBBUOfTlq6Yqf7fdlTBxTnGz5trR2Now=="
```