package main

// aesWorker defines a type that performs an AES encryption/decryption
// operation on the given data, and returns the result of that operation.
type aesWorker func([]byte) []byte
