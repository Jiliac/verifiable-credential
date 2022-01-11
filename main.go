package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	vcSpec = "https://www.w3.org/2018/credentials/v1"

	issuerID   = "https://violet.com/issuers/1"
	issuerName = "Violet"
)

var vcContext = []string{vcSpec}

func main() {
	// Part I: Create the issuer, the subject, and the verifier.
	issuer, err := CreateIssuer(issuerID, issuerName)
	if err != nil {
		panic(err)
	}

	subject, err := CreateSubject()
	if err != nil {
		panic(err)
	}

	verifier := CreateVerifier()

	// Part II: The Issuer issues credentials on the Subject.
	credentials, err := part2(issuer, subject)
	if err != nil {
		panic(err)
	}

	// Part III: The Verifier (any third party) can check the claim of the
	// Subject that it holds the credentials
	part3(subject, verifier, credentials)
}

func part2(issuer Issuer, subject Subject) (Credential, error) {
	// Step 1: Create a Subject and a claim to sign about this subject.
	// The claim is created jointly by the Subject and the Issuer. How they come
	// to agree on the claim to sign is out of scope here.
	claim := Claim{
		Age:            24,
		UniversityName: "Oxford",
		Degree:         "Bachelor of Science",
	}

	// Step 2: The Issuer signs the claim about this subject.
	credentials, err := issuer.SignCredential(claim, subject.GetID())
	if err != nil {
		err = fmt.Errorf("Issuer couldn't sign credentials: %w", err)
		return credentials, err
	}

	nicePrint(credentials, "Credential")
	return credentials, err
}

func part3(subject Subject, verifier Verifier, credentials Credential) {
	// @TODO: Get Nonce from Verifier
	presentation, err := subject.CreateAndSignPresentation(credentials)
	if err != nil {
		panic(err)
	}

	nicePrint(presentation, "Presentation")
}

func nicePrint(i interface{}, name string) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")

	fmt.Printf("\n***** %s *****\n\n", name)
	e.Encode(i)
}
