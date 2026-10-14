// Package certs parses, inspects, checks and converts X.509 certificate files
// entirely offline. Private keys and passwords are kept in memory only.
package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// MaxFileSize is the largest certificate file accepted. Real certificate files
// are a few kilobytes; the limit protects the application from unrelated input.
const MaxFileSize = 8 << 20

// Format names the detected container of a file.
type Format string

const (
	FormatPEM    Format = "PEM"
	FormatDER    Format = "DER"
	FormatPKCS12 Format = "PKCS#12"
	FormatPKCS7  Format = "PKCS#7"
)

var (
	// ErrPasswordRequired means a PKCS#12 file cannot be opened with an empty password.
	ErrPasswordRequired = errors.New("This PKCS#12 file is password protected. Enter its password")
	// ErrWrongPassword means the supplied PKCS#12 password is incorrect.
	ErrWrongPassword = errors.New("Incorrect password. Check the password and try again")
	// ErrTooLarge means the file exceeds MaxFileSize.
	ErrTooLarge = fmt.Errorf("File is larger than %d MiB and is not a certificate file", MaxFileSize>>20)
	// ErrEmpty means the file has no content.
	ErrEmpty = errors.New("File is empty")
)

// Parsed is the content recognized in one file.
type Parsed struct {
	Format       Format
	Certificates []*x509.Certificate
	Keys         []crypto.Signer
	Notes        []string
}

// ReadFile reads a file with the size limit applied before the whole file is loaded.
func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	return data, nil
}

// IsPKCS12 reports whether data has the outer structure of a PKCS#12 (PFX) file.
func IsPKCS12(data []byte) bool {
	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		Rest     asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(data, &pfx)
	if err != nil || len(bytes.TrimRight(rest, "\x00")) != 0 || pfx.Version != 3 {
		return false
	}
	var ci struct{ ContentType asn1.ObjectIdentifier }
	_, err = asn1.Unmarshal(pfx.AuthSafe.FullBytes, &ci)
	return err == nil && ci.ContentType.Equal(oidData)
}

// Parse recognizes certificates and private keys in data. The password is used
// only for PKCS#12 files and is not retained.
func Parse(data []byte, password string) (*Parsed, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	if len(data) > MaxFileSize {
		return nil, ErrTooLarge
	}
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		return parsePEM(data)
	}
	if IsPKCS12(data) {
		return parsePKCS12(data, password)
	}
	if p, err := parseDER(data); err == nil {
		return p, nil
	}
	// Some .cer files contain bare base64 without PEM armor.
	if decoded, ok := bareBase64(data); ok {
		if IsPKCS12(decoded) {
			return parsePKCS12(decoded, password)
		}
		if p, err := parseDER(decoded); err == nil {
			p.Notes = append(p.Notes, "Content is base64 without PEM headers; it was decoded as DER.")
			return p, nil
		}
	}
	return nil, errors.New("Unrecognized content. Supported: PEM, DER, PKCS#7 (.p7b) and PKCS#12 (.pfx/.p12) certificates and unencrypted private keys")
}

func bareBase64(data []byte) ([]byte, bool) {
	text := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, string(data))
	if len(text) < 64 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

func parseDER(data []byte) (*Parsed, error) {
	if certs, err := x509.ParseCertificates(data); err == nil && len(certs) > 0 {
		return &Parsed{Format: FormatDER, Certificates: certs}, nil
	}
	if certs, err := parsePKCS7(data); err == nil {
		return &Parsed{Format: FormatPKCS7, Certificates: certs}, nil
	}
	if key, err := parseKey(data); err == nil {
		return &Parsed{Format: FormatDER, Keys: []crypto.Signer{key}}, nil
	}
	return nil, errors.New("not DER")
}

func parsePEM(data []byte) (*Parsed, error) {
	p := &Parsed{Format: FormatPEM}
	rest := data
	ignored := map[string]bool{}
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
			der := block.Bytes
			if block.Type == "TRUSTED CERTIFICATE" {
				// OpenSSL appends trust settings after the certificate.
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(der, &raw); err == nil {
					der = raw.FullBytes
				}
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("A PEM certificate block cannot be parsed: %v", err)
			}
			p.Certificates = append(p.Certificates, cert)
		case "PKCS7", "CERTIFICATE CHAIN":
			certs, err := parsePKCS7(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("A PEM PKCS#7 block cannot be parsed: %v", err)
			}
			p.Certificates = append(p.Certificates, certs...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if _, encrypted := block.Headers["Proc-Type"]; encrypted {
				p.Notes = append(p.Notes, "An encrypted legacy PEM private key was found. Certificate Doctor v1.0 cannot decrypt encrypted PEM keys; it was not loaded.")
				continue
			}
			key, err := parseKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("A PEM private key block cannot be parsed: %v", err)
			}
			p.Keys = append(p.Keys, key)
		case "ENCRYPTED PRIVATE KEY":
			p.Notes = append(p.Notes, "An encrypted PKCS#8 private key was found. Certificate Doctor v1.0 cannot decrypt encrypted PEM keys; it was not loaded.")
		case "EC PARAMETERS":
		default:
			ignored[block.Type] = true
		}
	}
	for t := range ignored {
		p.Notes = append(p.Notes, fmt.Sprintf("A PEM block of type %q was ignored.", t))
	}
	if len(p.Certificates) == 0 && len(p.Keys) == 0 {
		if len(p.Notes) > 0 {
			return nil, errors.New(strings.Join(p.Notes, " "))
		}
		return nil, errors.New("No readable PEM certificate or private key blocks were found")
	}
	return p, nil
}

func parseKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return asSigner(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key encoding")
}

func asSigner(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	case *ed25519.PrivateKey:
		return *k, nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}

func parsePKCS12(data []byte, password string) (*Parsed, error) {
	key, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err == nil {
		signer, err := asSigner(key)
		if err != nil {
			return nil, err
		}
		return &Parsed{Format: FormatPKCS12, Certificates: append([]*x509.Certificate{leaf}, cas...), Keys: []crypto.Signer{signer}}, nil
	}
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		if password == "" {
			return nil, ErrPasswordRequired
		}
		return nil, ErrWrongPassword
	}
	// Certificate-only PKCS#12 trust stores have no private key.
	if certs, terr := pkcs12.DecodeTrustStore(data, password); terr == nil && len(certs) > 0 {
		return &Parsed{Format: FormatPKCS12, Certificates: certs, Notes: []string{"This PKCS#12 file contains certificates only, without a private key."}}, nil
	} else if errors.Is(terr, pkcs12.ErrIncorrectPassword) {
		if password == "" {
			return nil, ErrPasswordRequired
		}
		return nil, ErrWrongPassword
	}
	return nil, fmt.Errorf("The PKCS#12 file cannot be read: %v. Files with several private keys or unsupported encryption are not supported in v1.0", strings.TrimPrefix(err.Error(), "pkcs12: "))
}

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

// parsePKCS7 extracts certificates from a PKCS#7 SignedData structure such as a .p7b file.
func parsePKCS7(data []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(data, &ci); err != nil {
		return nil, err
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("not PKCS#7 SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, errors.New("The PKCS#7 file contains no certificates")
	}
	return x509.ParseCertificates(sd.Certificates.Bytes)
}

// EncodePKCS7 builds a certificate-only (degenerate) PKCS#7 SignedData structure.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, c.Raw...)
	}
	empty := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}
	inner, err := asn1.Marshal(struct{ ContentType asn1.ObjectIdentifier }{oidData})
	if err != nil {
		return nil, err
	}
	sd, err := asn1.Marshal(signedData{
		Version:          1,
		DigestAlgorithms: empty,
		ContentInfo:      asn1.RawValue{FullBytes: inner},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: raw},
		SignerInfos:      empty,
	})
	if err != nil {
		return nil, err
	}
	// The explicit [0] wrapper is built by hand: encoding/asn1 does not apply
	// explicit tagging to RawValue fields.
	return asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidSignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
}
