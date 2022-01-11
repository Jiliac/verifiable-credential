package main

import (
	"crypto/ed25519"
	"fmt"
)

type Subject struct {
	keys KeyPair
}

func CreateSubject() (Subject, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		err = fmt.Errorf("Couldn't create subject keys: %w", err)
		return Subject{}, err
	}

	subject := Subject{
		keys: KeyPair{PublicKey: pub, PrivateKey: priv},
	}

	return subject, err
}

func (s Subject) GetID() []byte {
	return []byte(s.keys.PublicKey)
}

func (s Subject) SignPresentation(credentials Credential, nonce []byte) (
	Presentation, error) {

	presentation := Presentation{PresentationToSign: PresentationToSign{
		Context:            vcContext,
		TypeOfPresentation: []string{presType},
		Credential:         credentials,
		Nonce:              nonce,
	}}

	docToSign, err := presentation.Export()
	if err != nil {
		return presentation, err
	}

	presentation.Proof = SignProof(s.keys, docToSign)
	return presentation, err
}
