package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Fixtures are generated in a temporary directory for each test.
func writeFixtures(t *testing.T) (dir string, pfxPassword string) {
	t.Helper()
	dir = t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "app.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 20), DNSNames: []string{"app.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pfxPassword = "app-test-password"
	pfx, err := pkcs12.Modern2023.Encode(key, cert, nil, pfxPassword)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"site.pfx":   pfx,
		"site.crt":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"broken.pem": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"notes.txt":  []byte("hello"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, pfxPassword
}

func fileByName(v View, name string) FileView {
	for _, f := range v.Files {
		if f.Name == name {
			return f
		}
	}
	return FileView{}
}

func TestAppLoadUnlockAndRemove(t *testing.T) {
	dir, password := writeFixtures(t)
	a := NewApp()
	p := func(n string) string { return filepath.Join(dir, n) }
	v, err := a.AddFiles([]string{p("site.pfx"), p("site.crt"), p("broken.pem"), p("notes.txt"), p("missing.pem"), p("site.crt")})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Files) != 3 || len(v.Rejected) != 2 {
		t.Fatalf("files %d rejected %v", len(v.Files), v.Rejected)
	}
	pfx := fileByName(v, "site.pfx")
	if pfx.State != "password" || pfx.Error != "" {
		t.Fatalf("pfx %+v", pfx)
	}
	if f := fileByName(v, "broken.pem"); f.State != "error" || f.Error == "" {
		t.Fatalf("broken %+v", f)
	}
	if v.Analysis.Keys == nil || len(v.Analysis.Certificates) != 1 {
		t.Fatalf("certs before unlock %d", len(v.Analysis.Certificates))
	}

	if _, err := a.Unlock(pfx.ID, ""); err == nil {
		t.Fatal("empty password accepted")
	}
	v, err = a.Unlock(pfx.ID, "wrong")
	if err == nil || !strings.Contains(err.Error(), "Incorrect password") {
		t.Fatalf("wrong password error %v", err)
	}
	if f := fileByName(a.State(), "site.pfx"); f.State != "password" || !strings.Contains(f.Error, "Incorrect password") {
		t.Fatalf("after wrong password %+v", f)
	}
	v, err = a.Unlock(pfx.ID, password)
	if err != nil {
		t.Fatal(err)
	}
	if f := fileByName(v, "site.pfx"); f.State != "ready" || f.Keys != 1 || f.Format != "PKCS#12" {
		t.Fatalf("after unlock %+v", f)
	}
	if len(v.Analysis.Certificates) != 1 || len(v.Analysis.Keys) != 1 || !v.Analysis.Keys[0].Matched {
		t.Fatal("unlocked key not matched to certificate")
	}
	for _, f := range a.files {
		if f.data != nil {
			t.Fatalf("%s keeps raw data after loading", f.name)
		}
	}

	codes := map[string]bool{}
	for _, f := range v.Analysis.Findings {
		codes[f.Code] = true
	}
	if !codes["expiring-soon"] {
		t.Fatal("20-day certificate should warn at the default 30-day threshold")
	}
	v = a.SetExpiringSoonDays(14)
	for _, f := range v.Analysis.Findings {
		if f.Code == "expiring-soon" {
			t.Fatal("20-day certificate should not warn at 14 days")
		}
	}
	if a.SetExpiringSoonDays(0).ExpiringSoonDays != 14 {
		t.Fatal("invalid threshold accepted")
	}

	v = a.RemoveFile(pfx.ID)
	if len(v.Files) != 2 || len(v.Analysis.Keys) != 0 {
		t.Fatal("remove did not forget the key")
	}
	if v = a.Clear(); len(v.Files) != 0 || len(v.Analysis.Certificates) != 0 {
		t.Fatal("clear failed")
	}
}

func TestSafeBase(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":           "example.com",
		`*.example.com`:         "_.example.com",
		`a/b\c:d`:               "a_b_c_d",
		"  ..":                  "certificate",
		"(empty name)":          "certificate",
		strings.Repeat("x", 90): strings.Repeat("x", 60),
	} {
		if got := safeBase(in); got != want {
			t.Errorf("safeBase(%q) = %q, want %q", in, got, want)
		}
	}
}
