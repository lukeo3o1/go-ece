package ece

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	receiver, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	stream := bytes.NewBuffer(nil)

	e := NewWriter(sender, receiver.PublicKey(), stream)
	if err != nil {
		t.Error(err)
	}
	e.SetRecordSize(DefaultRecordSize * 2)

	d := NewReader(receiver, sender.PublicKey(), stream)
	if err != nil {
		t.Error(err)
	}

	for i := 0; i < DefaultRecordSize; i++ {
		io.WriteString(e, "Hello, World!\n")
	}

	if err := e.Close(); err != nil {
		t.Error(err)
	}

	if _, err := io.Copy(io.Discard, d); err != nil {
		t.Error(err)
	}
}
