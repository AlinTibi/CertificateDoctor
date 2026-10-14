package certs

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"software.sslmate.com/src/go-pkcs12"
)

// Target is a conversion output format.
type Target string

const (
	TargetPEMChain    Target = "pem-chain"     // certificate chain, PEM
	TargetPEMChainKey Target = "pem-chain-key" // chain plus unencrypted private key, PEM
	TargetKeyPEM      Target = "key-pem"       // unencrypted private key only, PKCS#8 PEM
	TargetDER         Target = "der"           // single certificate, DER
	TargetPKCS7       Target = "p7b"           // certificate chain, PKCS#7 DER
	TargetPFX         Target = "pfx"           // chain plus private key, PKCS#12 (AES-256)
)

// TargetInfo describes the default file name and whether a target contains a private key.
func TargetInfo(t Target) (extension, filter string, containsKey bool, err error) {
	switch t {
	case TargetPEMChain:
		return ".pem", "*.pem;*.crt", false, nil
	case TargetPEMChainKey:
		return ".pem", "*.pem", true, nil
	case TargetKeyPEM:
		return ".key", "*.key;*.pem", true, nil
	case TargetDER:
		return ".cer", "*.cer;*.der", false, nil
	case TargetPKCS7:
		return ".p7b", "*.p7b", false, nil
	case TargetPFX:
		return ".pfx", "*.pfx;*.p12", true, nil
	}
	return "", "", false, fmt.Errorf("Unknown conversion %q", t)
}

// MinPFXPasswordLength is the minimum password length for new PKCS#12 files.
const MinPFXPasswordLength = 8

// Convert builds the output for the chain starting at leafID.
func Convert(set *Set, leafID string, target Target, password string) ([]byte, error) {
	leaf := set.Certificate(leafID)
	if leaf == nil {
		return nil, errors.New("The selected certificate is no longer loaded")
	}
	chain := set.ChainFrom(leaf)
	var key crypto.Signer
	if _, _, needsKey, err := TargetInfo(target); err != nil {
		return nil, err
	} else if needsKey {
		if key = set.KeyFor(leaf); key == nil {
			return nil, errors.New("No loaded private key matches this certificate. Add the private key file first")
		}
	}
	switch target {
	case TargetPEMChain:
		return encodeCertsPEM(chain), nil
	case TargetPEMChainKey:
		keyPEM, err := encodeKeyPEM(key)
		if err != nil {
			return nil, err
		}
		return append(encodeCertsPEM(chain), keyPEM...), nil
	case TargetKeyPEM:
		return encodeKeyPEM(key)
	case TargetDER:
		return append([]byte(nil), leaf.Raw...), nil
	case TargetPKCS7:
		return EncodePKCS7(chain)
	case TargetPFX:
		if utf8.RuneCountInString(password) < MinPFXPasswordLength {
			return nil, fmt.Errorf("Use a PFX password of at least %d characters", MinPFXPasswordLength)
		}
		return pkcs12.Modern2023.Encode(key, leaf, chain[1:], password)
	}
	return nil, fmt.Errorf("Unknown conversion %q", target)
}

func encodeCertsPEM(chain []*x509.Certificate) []byte {
	var out []byte
	for _, c := range chain {
		out = append(out, []byte("# "+DisplayName(c, true)+"\n")...)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func encodeKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// SamePath reports whether two paths name the same file, case-insensitively on Windows.
func SamePath(a, b string) bool {
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	if strings.EqualFold(ca, cb) {
		return true
	}
	ia, errA := os.Stat(ca)
	ib, errB := os.Stat(cb)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

// WriteNew writes data to a new file. It refuses existing files and source paths,
// so originals are never overwritten. A partial file is removed on failure.
func WriteNew(path string, data []byte, sources []string) error {
	for _, s := range sources {
		if SamePath(path, s) {
			return errors.New("Choose a different file name. Certificate Doctor never overwrites a source file")
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("A file with this name already exists. Choose a new file name; existing files are never replaced")
		}
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
