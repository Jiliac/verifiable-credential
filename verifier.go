package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math/rand"
)

const (
	nonceSize = 12
)

type Verifier struct{}

func CreateVerifier() Verifier {
	return Verifier{}
}

func (v Verifier) MakeNonce() (nonce []byte, err error) {
	nonce = make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	return nonce, err
}

func (v Verifier) VerifiesPresentation(presentation Presentation) (err error) {
	// A - Checks the Presentation is signed by the Subject of the credential
	credential := presentation.Credential
	credentialSubjectID := credential.CredentialSubject.ID
	presentationProver := presentation.Proof.Creator
	if bytes.Compare(credentialSubjectID, presentationProver) != 0 {
		return fmt.Errorf("Presentation prover is not the credential subject.")
	}

	// B - Checks the credential
	signedCred, err := credential.Export()
	if err != nil {
		return fmt.Errorf(
			"Couldn't export credential to verify signature: %w", err,
		)
	}

	okCred := verifiesSignature(credential.Proof, signedCred)
	if !okCred {
		return fmt.Errorf("Invalid credential signature.")
	}

	// C - Checks the presentation
	signedPres, err := presentation.Export()
	if err != nil {
		return fmt.Errorf(
			"Couldn't export presentation to verify signature: %w", err,
		)
	}

	okPres := verifiesSignature(presentation.Proof, signedPres)
	if !okPres {
		return fmt.Errorf("Invalid presentation signature.")
	}

	return err
}

func verifiesSignature(proof Proof, signedDoc []byte) bool {
	pubKey := proof.Creator
	signature := proof.Signature

	return ed25519.Verify(pubKey, signedDoc, signature)
}
