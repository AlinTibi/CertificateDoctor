package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func TestInvalidMD5SignatureMustNotVerify(t *testing.T) {
	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootA := issue(t, "Same Name Audit CA", true, nil, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), keyA)
	rootB := issue(t, "Same Name Audit CA", true, nil, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), keyB)
	leaf := issue(t, "audit.example", false, rootA, now.AddDate(0, -1, 0), now.AddDate(0, 1, 0), nil)
	sha256OID := []byte{6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11}
	md5OID := []byte{6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 4}
	tamperedDER := bytes.ReplaceAll(leaf.cert.Raw, sha256OID, md5OID)
	tampered, err := x509.ParseCertificate(tamperedDER)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.SignatureAlgorithm != x509.MD5WithRSA {
		t.Fatal("fixture is not MD5-RSA")
	}
	if err := rootB.cert.CheckSignature(tampered.SignatureAlgorithm, tampered.RawTBSCertificate, tampered.Signature); err == nil {
		t.Fatal("fixture unexpectedly verifies")
	}
	if signedBy(tampered, rootB.cert) {
		t.Error("corrupted MD5-RSA certificate accepted as signed by unrelated same-name issuer")
	}
	analysis := Analyze([]Input{{Name: "synthetic.pem", Parsed: &Parsed{Format: FormatPEM, Certificates: []*x509.Certificate{tampered, rootB.cert}}}}, now, 30)
	for _, chain := range analysis.Chains {
		if chain.LeafID == CertificateID(tampered) && chain.Status == "complete" {
			t.Error("invalid signature reported as complete chain")
		}
	}
	unverified := false
	for _, finding := range analysis.Findings {
		if finding.Code == "signature-unverified" {
			unverified = true
		}
	}
	if !unverified {
		t.Fatal("unsupported signature was not explained")
	}
	rootDER := bytes.ReplaceAll(rootA.cert.Raw, sha256OID, md5OID)
	badRoot, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	if IsSelfSigned(badRoot) {
		t.Fatal("unverified MD5 root accepted as self-signed")
	}
}

func TestSHA1SignatureStillRequiresVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := issue(t, "SHA1 Test Root", true, nil, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), key)
	template := &x509.Certificate{SerialNumber: big.NewInt(9901), Subject: pkix.Name{CommonName: "sha1.example"}, NotBefore: now.AddDate(0, -1, 0), NotAfter: now.AddDate(0, 1, 0), SignatureAlgorithm: x509.SHA1WithRSA}
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !signedBy(leaf, root.cert) {
		t.Fatal("valid SHA1 signature rejected instead of warned")
	}
	leaf.Signature = append([]byte(nil), leaf.Signature...)
	leaf.Signature[0] ^= 1
	if signedBy(leaf, root.cert) {
		t.Fatal("corrupted SHA1 signature accepted")
	}
}
