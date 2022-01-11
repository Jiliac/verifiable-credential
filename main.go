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

	// @TODO: Create the verifier

	// Part II: The Issuer issues credentials on the Subject.
	part2(issuer, subject)
}

func part2(issuer Issuer, subject Subject) {
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
		panic(err)
	}
	nicePrint(credentials, "Credential")
}

func nicePrint(i interface{}, name string) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")

	fmt.Printf("\n***** %s *****\n\n", name)
	e.Encode(i)
}
