package main

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

type Issuer struct {
	keys KeyPair

	ID   string
	Name string
}

func CreateIssuer(id, name string) (Issuer, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		err = fmt.Errorf("Couldn't create issuer keys: %w", err)
		return Issuer{}, err
	}

	issuer := Issuer{
		keys: KeyPair{PublicKey: pub, PrivateKey: priv},
		ID:   id,
		Name: name,
	}

	return issuer, err
}

func (i Issuer) SignCredential(claim Claim, subjectID []byte) (Credential, error) {
	creds := Credential{CredentialToSign: CredentialToSign{
		Context:          vcContext,
		TypeOfCredential: append(claim.GetType(), vcType),
		Issuer:           i,
		IssuanceDate:     time.Now(),
		CredentialSubject: CredentialSubject{
			ID:    subjectID,
			Claim: claim,
		},
	}}

	docToSign, err := creds.Export()
	creds.Proof = SignProof(i.keys, docToSign)

	return creds, err
}
