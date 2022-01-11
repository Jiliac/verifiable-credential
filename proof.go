package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const ed25519Type = "Ed25519Signature2018"

type Proof struct {
	TypeOfProof string            `json:"type"`
	Created     time.Time         `json:"created"`
	Creator     ed25519.PublicKey `json:"creator"`
	Signature   []byte            `json:"signature"`
}

func SignProof(keys KeyPair, docToSign []byte) Proof {
	proof := Proof{
		TypeOfProof: ed25519Type,
		Created:     time.Now(),
		Creator:     keys.PublicKey,
	}

	proof.Signature = ed25519.Sign(keys.PrivateKey, docToSign)

	return proof
}

func export(i interface{}) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	err := e.Encode(i)
	return buf.Bytes(), err
}
