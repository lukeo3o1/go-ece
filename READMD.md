# go-ece

[![Go Reference](https://pkg.go.dev/badge/github.com/yourname/go-ece.svg)](https://pkg.go.dev/github.com/yourname/go-ece)

This package provides a Go implementation of **Encrypted Content-Encoding (ECE)**,  
as specified in [IETF RFC 8188](https://datatracker.ietf.org/doc/html/rfc8188).  

## Features

- ✅ AES-128-GCM (standard, RFC 8188 compliant)  
- ✅ AES-256-GCM (extension, not part of RFC 8188 — both parties must support it)  
- ✅ Record-based streaming encryption/decryption according to RFC 8188  
- ✅ `Writer` and `Reader` implement standard `io.Writer` / `io.Reader` interfaces  
- ✅ Configurable record size (default: 4096 bytes)  
- ✅ Optional KeyID support for external key management  


## Installation

```bash
go get github.com/yourname/go-ece
````


## Quick Start Example

```go
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/lukeo3o1/go-ece"
)

func main() {
	// Generate key pairs for sender and receiver
	sender, _ := ecdh.P256().GenerateKey(rand.Reader)
	receiver, _ := ecdh.P256().GenerateKey(rand.Reader)

	// Simulated network buffer
	var buf bytes.Buffer

	// --- Sender side ---
	w := ece.NewWriter(sender, receiver.PublicKey(), &buf)
	w.Write([]byte("Hello, world!"))
	w.Close()

	// --- Receiver side ---
	r := ece.NewReader(receiver, sender.PublicKey(), &buf)
	plaintext, _ := io.ReadAll(r)

	fmt.Println(string(plaintext)) // "Hello, world!"
}
```
