package main

import (
	"time"
)

const (
	vcType = "VerifiableCredential"
)

type Claim struct {
	Age            int    `json:"age"`
	UniversityName string `json:"universityName"`
	Degree         string `json:"degree"`
}

type CredentialSubject struct {
	ID    []byte `json:"id"`
	Claim Claim  `json:"claim"`
}

type CredentialToSign struct {
	Context           []string          `json:"context"`
	TypeOfCredential  []string          `json:"typeOfCredential"`
	Issuer            Issuer            `json:"issuer"`
	IssuanceDate      time.Time         `json:"issuanceDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

type Credential struct {
	CredentialToSign

	Proof Proof `json:"proof"`
}

func (c Claim) GetType() []string {
	return []string{"GraduationCredential"}
}

func (c Credential) Export() (str []byte, err error) {
	str, err = export(c.CredentialToSign)
	return str, err
}
