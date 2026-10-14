package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Certificate is a display-ready description of one X.509 certificate.
type Certificate struct {
	ID                 string    `json:"id"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SubjectName        string    `json:"subjectName"`
	IssuerName         string    `json:"issuerName"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DaysRemaining      int       `json:"daysRemaining"`
	Validity           string    `json:"validity"`
	DNSNames           []string  `json:"dnsNames"`
	IPAddresses        []string  `json:"ipAddresses"`
	EmailAddresses     []string  `json:"emailAddresses"`
	URIs               []string  `json:"uris"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	KeySize            int       `json:"keySize"`
	KeyDescription     string    `json:"keyDescription"`
	IsCA               bool      `json:"isCA"`
	SelfSigned         bool      `json:"selfSigned"`
	Role               string    `json:"role"`
	KeyUsage           []string  `json:"keyUsage"`
	ExtKeyUsage        []string  `json:"extKeyUsage"`
	SubjectKeyID       string    `json:"subjectKeyId"`
	AuthorityKeyID     string    `json:"authorityKeyId"`
	SHA1               string    `json:"sha1"`
	SHA256             string    `json:"sha256"`
	Sources            []string  `json:"sources"`
}

// Fingerprint returns uppercase colon-separated hex, as shown by Windows and OpenSSL.
func Fingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// CertificateID is the lowercase SHA-256 of the DER certificate.
func CertificateID(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// KeyID is the lowercase SHA-256 of the DER SubjectPublicKeyInfo.
func KeyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// IsSelfSigned reports whether the certificate names itself as issuer and its
// signature verifies with its own public key.
func IsSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawIssuer, c.RawSubject) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	return err == nil
}

// DisplayName returns the common name, or the full distinguished name when there is none.
func DisplayName(c *x509.Certificate, subject bool) string {
	name := c.Issuer
	if subject {
		name = c.Subject
	}
	if name.CommonName != "" {
		return name.CommonName
	}
	if len(name.Organization) > 0 {
		return name.Organization[0]
	}
	if s := name.String(); s != "" {
		return s
	}
	return "(empty name)"
}

// KeyDescription returns the algorithm and size of a public key.
func KeyDescription(pub crypto.PublicKey) (algorithm string, size int, description string) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		size = k.N.BitLen()
		return "RSA", size, fmt.Sprintf("RSA %d-bit", size)
	case *ecdsa.PublicKey:
		size = k.Curve.Params().BitSize
		return "ECDSA", size, fmt.Sprintf("ECDSA %s (%d-bit)", k.Curve.Params().Name, size)
	case ed25519.PublicKey:
		return "Ed25519", 256, "Ed25519 (256-bit)"
	}
	return "Unknown", 0, "Unknown key type"
}

// Describe converts a parsed certificate to its display form.
func Describe(c *x509.Certificate, now time.Time, soonDays int) Certificate {
	s1 := sha1.Sum(c.Raw)
	s256 := sha256.Sum256(c.Raw)
	algo, size, desc := KeyDescription(c.PublicKey)
	d := Certificate{
		ID:                 CertificateID(c),
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SubjectName:        DisplayName(c, true),
		IssuerName:         DisplayName(c, false),
		SerialNumber:       Fingerprint(c.SerialNumber.Bytes()),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		DaysRemaining:      int(c.NotAfter.Sub(now).Hours() / 24),
		DNSNames:           nonNil(c.DNSNames),
		EmailAddresses:     nonNil(c.EmailAddresses),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: algo,
		KeySize:            size,
		KeyDescription:     desc,
		IsCA:               c.BasicConstraintsValid && c.IsCA,
		SelfSigned:         IsSelfSigned(c),
		KeyUsage:           keyUsages(c.KeyUsage),
		ExtKeyUsage:        extKeyUsages(c),
		SubjectKeyID:       Fingerprint(c.SubjectKeyId),
		AuthorityKeyID:     Fingerprint(c.AuthorityKeyId),
		SHA1:               Fingerprint(s1[:]),
		SHA256:             Fingerprint(s256[:]),
		IPAddresses:        []string{},
		URIs:               []string{},
		Sources:            []string{},
	}
	if d.Subject == "" {
		d.Subject = "(empty subject)"
	}
	for _, ip := range c.IPAddresses {
		d.IPAddresses = append(d.IPAddresses, ip.String())
	}
	for _, u := range c.URIs {
		d.URIs = append(d.URIs, u.String())
	}
	switch {
	case now.Before(c.NotBefore):
		d.Validity = "not-yet-valid"
	case now.After(c.NotAfter):
		d.Validity = "expired"
	case c.NotAfter.Sub(now) <= time.Duration(soonDays)*24*time.Hour:
		d.Validity = "expiring-soon"
	default:
		d.Validity = "valid"
	}
	switch {
	case d.SelfSigned && d.IsCA:
		d.Role = "Root CA"
	case d.SelfSigned:
		d.Role = "Self-signed"
	case d.IsCA:
		d.Role = "Intermediate CA"
	default:
		d.Role = "End entity"
	}
	return d
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func keyUsages(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital signature"},
		{x509.KeyUsageContentCommitment, "Content commitment"},
		{x509.KeyUsageKeyEncipherment, "Key encipherment"},
		{x509.KeyUsageDataEncipherment, "Data encipherment"},
		{x509.KeyUsageKeyAgreement, "Key agreement"},
		{x509.KeyUsageCertSign, "Certificate signing"},
		{x509.KeyUsageCRLSign, "CRL signing"},
		{x509.KeyUsageEncipherOnly, "Encipher only"},
		{x509.KeyUsageDecipherOnly, "Decipher only"},
	}
	out := []string{}
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsages(c *x509.Certificate) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Any purpose",
		x509.ExtKeyUsageServerAuth:      "Server authentication",
		x509.ExtKeyUsageClientAuth:      "Client authentication",
		x509.ExtKeyUsageCodeSigning:     "Code signing",
		x509.ExtKeyUsageEmailProtection: "Email protection",
		x509.ExtKeyUsageTimeStamping:    "Time stamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSP signing",
	}
	out := []string{}
	for _, u := range c.ExtKeyUsage {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("Other (%d)", u))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}
