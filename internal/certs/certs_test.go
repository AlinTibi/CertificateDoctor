package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// All fixtures are generated at test time; no real certificates or keys are stored.

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type pair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial int64 = 100

func issue(t *testing.T, cn string, ca bool, parent *pair, notBefore, notAfter time.Time, key crypto.Signer) *pair {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example Test Org"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.DNSNames = []string{cn, "www." + cn}
		tmpl.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pair{cert, key}
}

type fixture struct{ root, inter, leaf *pair }

func newFixture(t *testing.T) fixture {
	root := issue(t, "Test Root CA", true, nil, now.AddDate(-5, 0, 0), now.AddDate(10, 0, 0), nil)
	inter := issue(t, "Test Intermediate CA", true, root, now.AddDate(-2, 0, 0), now.AddDate(5, 0, 0), nil)
	leaf := issue(t, "example.test", false, inter, now.AddDate(0, -1, 0), now.AddDate(0, 11, 0), nil)
	return fixture{root, inter, leaf}
}

func certPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func keyPEM(t *testing.T, k crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mustParse(t *testing.T, data []byte, password string) *Parsed {
	t.Helper()
	p, err := Parse(data, password)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func findingCodes(a Analysis) map[string]int {
	out := map[string]int{}
	for _, f := range a.Findings {
		out[f.Code]++
	}
	return out
}

func TestParseFormats(t *testing.T) {
	f := newFixture(t)
	p7, err := EncodePKCS7([]*x509.Certificate{f.leaf.cert, f.inter.cert})
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Modern2023.Encode(f.leaf.key, f.leaf.cert, []*x509.Certificate{f.inter.cert}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	ecDER, _ := x509.MarshalECPrivateKey(f.leaf.key.(*ecdsa.PrivateKey))
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name         string
		data         []byte
		format       Format
		certs, keys  int
		wantNoteText string
	}{
		{"pem chain", certPEM(f.leaf.cert, f.inter.cert), FormatPEM, 2, 0, ""},
		{"der certificate", f.leaf.cert.Raw, FormatDER, 1, 0, ""},
		{"pkcs7 der", p7, FormatPKCS7, 2, 0, ""},
		{"pkcs7 pem", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: p7}), FormatPEM, 2, 0, ""},
		{"pem with key and bag attributes", append([]byte("Bag Attributes\n    localKeyID: 01\n"), append(certPEM(f.leaf.cert), keyPEM(t, f.leaf.key)...)...), FormatPEM, 1, 1, ""},
		{"ec key pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), FormatPEM, 0, 1, ""},
		{"rsa key pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), FormatPEM, 0, 1, ""},
		{"pkcs8 der key", mustPKCS8(t, rsaKey), FormatDER, 0, 1, ""},
		{"bare base64", []byte(base64.StdEncoding.EncodeToString(f.leaf.cert.Raw)), FormatDER, 1, 0, "base64"},
		{"crlf pem", bytes.ReplaceAll(certPEM(f.root.cert), []byte("\n"), []byte("\r\n")), FormatPEM, 1, 0, ""},
		{"encrypted key is reported", append(certPEM(f.leaf.cert), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1, 2, 3}})...), FormatPEM, 1, 0, "cannot decrypt"},
		{"csr is ignored", append(certPEM(f.leaf.cert), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}})...), FormatPEM, 1, 0, "CERTIFICATE REQUEST"},
	}
	_ = pfx
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustParse(t, tc.data, "")
			if p.Format != tc.format || len(p.Certificates) != tc.certs || len(p.Keys) != tc.keys {
				t.Fatalf("got %s %d certs %d keys", p.Format, len(p.Certificates), len(p.Keys))
			}
			if tc.wantNoteText != "" && !strings.Contains(strings.Join(p.Notes, " "), tc.wantNoteText) {
				t.Fatalf("notes %q do not mention %q", p.Notes, tc.wantNoteText)
			}
		})
	}
}

func mustPKCS8(t *testing.T, k crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseRejectsInvalidInput(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":       {},
		"text":        []byte("hello, this is not a certificate"),
		"broken pem":  []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"random der":  {0x30, 0x03, 0x02, 0x01, 0x05},
		"only csr":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte{1}}),
		"truncated":   bytes.Repeat([]byte{0x30, 0x82}, 10),
		"huge header": append([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data, ""); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := Parse(make([]byte, MaxFileSize+1), ""); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestPKCS12Passwords(t *testing.T) {
	f := newFixture(t)
	for name, enc := range map[string]*pkcs12.Encoder{"modern": pkcs12.Modern2023, "legacy": pkcs12.LegacyRC2} {
		t.Run(name, func(t *testing.T) {
			pfx, err := enc.Encode(f.leaf.key, f.leaf.cert, []*x509.Certificate{f.inter.cert, f.root.cert}, "s3cret-pass")
			if err != nil {
				t.Fatal(err)
			}
			if !IsPKCS12(pfx) {
				t.Fatal("not detected as PKCS#12")
			}
			if _, err := Parse(pfx, ""); !errors.Is(err, ErrPasswordRequired) {
				t.Fatalf("empty password: %v", err)
			}
			if _, err := Parse(pfx, "wrong"); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("wrong password: %v", err)
			}
			p := mustParse(t, pfx, "s3cret-pass")
			if p.Format != FormatPKCS12 || len(p.Certificates) != 3 || len(p.Keys) != 1 {
				t.Fatalf("got %s %d certs %d keys", p.Format, len(p.Certificates), len(p.Keys))
			}
		})
	}
	t.Run("passwordless trust store", func(t *testing.T) {
		pfx, err := pkcs12.Passwordless.EncodeTrustStore([]*x509.Certificate{f.root.cert, f.inter.cert}, "")
		if err != nil {
			t.Fatal(err)
		}
		p := mustParse(t, pfx, "")
		if len(p.Certificates) != 2 || len(p.Keys) != 0 {
			t.Fatalf("got %d certs %d keys", len(p.Certificates), len(p.Keys))
		}
	})
}

func TestDescribe(t *testing.T) {
	f := newFixture(t)
	d := Describe(f.leaf.cert, now, 30)
	if d.SubjectName != "example.test" || d.IssuerName != "Test Intermediate CA" || d.Role != "End entity" || d.Validity != "valid" {
		t.Fatalf("unexpected description %+v", d)
	}
	if strings.Join(d.DNSNames, ",") != "example.test,www.example.test" || d.IPAddresses[0] != "192.0.2.10" {
		t.Fatalf("SAN %v %v", d.DNSNames, d.IPAddresses)
	}
	if d.KeyDescription != "ECDSA P-256 (256-bit)" || d.KeySize != 256 {
		t.Fatalf("key %q", d.KeyDescription)
	}
	if len(d.SHA256) != 95 || len(d.SHA1) != 59 || d.ID != CertificateID(f.leaf.cert) {
		t.Fatalf("fingerprints %q %q", d.SHA1, d.SHA256)
	}
	if r := Describe(f.root.cert, now, 30); r.Role != "Root CA" || !r.SelfSigned {
		t.Fatalf("root %+v", r)
	}
	if i := Describe(f.inter.cert, now, 30); i.Role != "Intermediate CA" || i.SelfSigned {
		t.Fatalf("intermediate %+v", i)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaLeaf := issue(t, "rsa.test", false, f.inter, now.AddDate(0, -1, 0), now.AddDate(0, 0, 10), rsaKey)
	if r := Describe(rsaLeaf.cert, now, 30); r.KeyDescription != "RSA 2048-bit" || r.Validity != "expiring-soon" || r.DaysRemaining != 10 {
		t.Fatalf("rsa %+v", r)
	}
}

func TestAnalyzeCompleteChainAndKey(t *testing.T) {
	f := newFixture(t)
	// Deliberately out of order and split across files, with a duplicate.
	inputs := []Input{
		{"bundle.pem", mustParse(t, certPEM(f.inter.cert, f.leaf.cert), "")},
		{"root.cer", mustParse(t, f.root.cert.Raw, "")},
		{"leaf.key", mustParse(t, keyPEM(t, f.leaf.key), "")},
		{"leaf.crt", mustParse(t, certPEM(f.leaf.cert), "")},
	}
	a := Analyze(inputs, now, 30)
	if len(a.Certificates) != 3 || len(a.Keys) != 1 || len(a.Chains) != 1 {
		t.Fatalf("got %d certs %d keys %d chains", len(a.Certificates), len(a.Keys), len(a.Chains))
	}
	ch := a.Chains[0]
	if ch.Status != "complete" || len(ch.Links) != 3 || ch.Links[0].Name != "example.test" || ch.Links[2].Name != "Test Root CA" || ch.KeyID == "" {
		t.Fatalf("chain %+v", ch)
	}
	codes := findingCodes(a)
	if codes["chain-complete"] != 1 || codes["key-match"] != 1 || codes["bundle-order"] != 1 || a.Counts[SeverityError] != 0 || a.Verdict != SeverityOK {
		t.Fatalf("findings %v verdict %s", codes, a.Verdict)
	}
	if !a.Keys[0].Matched || a.Keys[0].Source != "leaf.key" {
		t.Fatalf("key %+v", a.Keys[0])
	}
	for _, c := range a.Certificates {
		if c.ID == CertificateID(f.leaf.cert) && strings.Join(c.Sources, ",") != "bundle.pem,leaf.crt" {
			t.Fatalf("sources %v", c.Sources)
		}
	}
}

func TestAnalyzeMissingIntermediateAndRoot(t *testing.T) {
	f := newFixture(t)
	a := Analyze([]Input{{"leaf.pem", mustParse(t, certPEM(f.leaf.cert), "")}}, now, 30)
	if a.Chains[0].Status != "issuer-missing" || findingCodes(a)["issuer-missing"] != 1 || a.Verdict != SeverityWarning {
		t.Fatalf("leaf only: %+v %v", a.Chains[0], findingCodes(a))
	}
	a = Analyze([]Input{{"chain.pem", mustParse(t, certPEM(f.leaf.cert, f.inter.cert), "")}}, now, 30)
	if a.Chains[0].Status != "root-not-provided" || findingCodes(a)["chain-to-intermediate"] != 1 || findingCodes(a)["bundle-order"] != 0 {
		t.Fatalf("leaf + intermediate: %+v %v", a.Chains[0], findingCodes(a))
	}
	// Leaf and root without the intermediate: the gap is reported.
	a = Analyze([]Input{{"gap.pem", mustParse(t, certPEM(f.leaf.cert, f.root.cert), "")}}, now, 30)
	if findingCodes(a)["issuer-missing"] != 1 {
		t.Fatalf("gap: %v", findingCodes(a))
	}
}

func TestAnalyzeExpiryStates(t *testing.T) {
	f := newFixture(t)
	expired := issue(t, "expired.test", false, f.inter, now.AddDate(-1, 0, 0), now.AddDate(0, 0, -3), nil)
	soon := issue(t, "soon.test", false, f.inter, now.AddDate(-1, 0, 0), now.AddDate(0, 0, 12), nil)
	future := issue(t, "future.test", false, f.inter, now.AddDate(0, 0, 5), now.AddDate(1, 0, 0), nil)
	a := Analyze([]Input{{"set.pem", mustParse(t, certPEM(expired.cert, soon.cert, future.cert, f.inter.cert, f.root.cert), "")}}, now, 30)
	codes := findingCodes(a)
	if codes["expired"] != 1 || codes["expiring-soon"] != 1 || codes["not-yet-valid"] != 1 || a.Verdict != SeverityError {
		t.Fatalf("codes %v", codes)
	}
	if len(a.Chains) != 3 {
		t.Fatalf("chains %d", len(a.Chains))
	}
	if a.Findings[0].Severity != SeverityError {
		t.Fatal("errors must sort first")
	}
	// A wider threshold turns the 12-day certificate into a warning; a narrower one does not.
	if findingCodes(Analyze([]Input{{"s.pem", mustParse(t, certPEM(soon.cert), "")}}, now, 7))["expiring-soon"] != 0 {
		t.Fatal("7-day threshold should not warn at 12 days")
	}
	// Intermediate expiring before the leaf.
	shortInter := issue(t, "Short Intermediate", true, f.root, now.AddDate(-1, 0, 0), now.AddDate(0, 2, 0), nil)
	longLeaf := issue(t, "long.test", false, shortInter, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), nil)
	if findingCodes(Analyze([]Input{{"c.pem", mustParse(t, certPEM(longLeaf.cert, shortInter.cert, f.root.cert), "")}}, now, 30))["issuer-expires-first"] != 1 {
		t.Fatal("issuer-expires-first missing")
	}
}

func TestAnalyzeKeyMismatchAndSignatureMismatch(t *testing.T) {
	f := newFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := Analyze([]Input{
		{"leaf.pem", mustParse(t, certPEM(f.leaf.cert, f.inter.cert), "")},
		{"wrong.key", mustParse(t, keyPEM(t, other), "")},
	}, now, 30)
	if findingCodes(a)["key-mismatch"] != 1 || a.Keys[0].Matched || a.Verdict != SeverityError {
		t.Fatalf("mismatch %v", findingCodes(a))
	}
	// An issuer with the same name but a different key did not sign the leaf.
	impostor := issue(t, "Test Intermediate CA", true, f.root, now.AddDate(-1, 0, 0), now.AddDate(3, 0, 0), nil)
	a = Analyze([]Input{{"x.pem", mustParse(t, certPEM(f.leaf.cert, impostor.cert), "")}}, now, 30)
	if findingCodes(a)["signature-mismatch"] != 1 {
		t.Fatalf("signature mismatch %v", findingCodes(a))
	}
	a = Analyze([]Input{{"only.key", mustParse(t, keyPEM(t, other), "")}}, now, 30)
	if findingCodes(a)["key-only"] != 1 {
		t.Fatalf("key only %v", findingCodes(a))
	}
}

func TestAnalyzeSelfSignedAndWeak(t *testing.T) {
	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	self := issue(t, "self.test", false, nil, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), weakKey)
	a := Analyze([]Input{{"self.pem", mustParse(t, certPEM(self.cert), "")}}, now, 30)
	codes := findingCodes(a)
	if a.Chains[0].Status != "self-signed" || codes["self-signed"] != 1 || codes["weak-key"] != 1 || codes["no-key"] != 1 {
		t.Fatalf("codes %v status %s", codes, a.Chains[0].Status)
	}
	if a := Analyze(nil, now, 30); a.VerdictText != "Open certificate files to start." {
		t.Fatalf("empty verdict %q", a.VerdictText)
	}
}

func TestConvertRoundTrips(t *testing.T) {
	f := newFixture(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaLeaf := issue(t, "rsa.test", false, f.inter, now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), rsaKey)
	for name, leaf := range map[string]*pair{"ecdsa": f.leaf, "rsa": rsaLeaf} {
		t.Run(name, func(t *testing.T) {
			set := NewSet([]Input{
				{"chain.pem", mustParse(t, certPEM(f.root.cert, leaf.cert, f.inter.cert), "")},
				{"leaf.key", mustParse(t, keyPEM(t, leaf.key), "")},
			})
			id := CertificateID(leaf.cert)

			out, err := Convert(set, id, TargetPEMChain, "")
			if err != nil {
				t.Fatal(err)
			}
			p := mustParse(t, out, "")
			if len(p.Certificates) != 3 || !p.Certificates[0].Equal(leaf.cert) || !p.Certificates[2].Equal(f.root.cert) || len(p.Keys) != 0 {
				t.Fatal("PEM chain order or content wrong")
			}

			out, err = Convert(set, id, TargetPEMChainKey, "")
			if err != nil {
				t.Fatal(err)
			}
			if p := mustParse(t, out, ""); len(p.Keys) != 1 || !PublicKeysEqual(p.Keys[0].Public(), leaf.cert.PublicKey) {
				t.Fatal("PEM key missing")
			}

			out, err = Convert(set, id, TargetKeyPEM, "")
			if err != nil || !bytes.HasPrefix(out, []byte("-----BEGIN PRIVATE KEY-----")) {
				t.Fatalf("key pem %v", err)
			}

			out, err = Convert(set, id, TargetDER, "")
			if err != nil || !bytes.Equal(out, leaf.cert.Raw) {
				t.Fatalf("der %v", err)
			}

			out, err = Convert(set, id, TargetPKCS7, "")
			if err != nil {
				t.Fatal(err)
			}
			if p := mustParse(t, out, ""); p.Format != FormatPKCS7 || len(p.Certificates) != 3 {
				t.Fatalf("p7b %s %d", p.Format, len(p.Certificates))
			}

			if _, err := Convert(set, id, TargetPFX, "short"); err == nil {
				t.Fatal("short PFX password accepted")
			}
			out, err = Convert(set, id, TargetPFX, "long enough password")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(out, "wrong password"); !errors.Is(err, ErrWrongPassword) {
				t.Fatalf("pfx wrong password: %v", err)
			}
			p = mustParse(t, out, "long enough password")
			if len(p.Certificates) != 3 || len(p.Keys) != 1 || !p.Certificates[0].Equal(leaf.cert) {
				t.Fatal("PFX content wrong")
			}
		})
	}
}

func TestConvertRequiresMatchingKey(t *testing.T) {
	f := newFixture(t)
	set := NewSet([]Input{{"leaf.pem", mustParse(t, certPEM(f.leaf.cert), "")}})
	for _, target := range []Target{TargetPEMChainKey, TargetKeyPEM, TargetPFX} {
		if _, err := Convert(set, CertificateID(f.leaf.cert), target, "long enough password"); err == nil {
			t.Fatalf("%s converted without a key", target)
		}
	}
	if _, err := Convert(set, "missing", TargetPEMChain, ""); err == nil {
		t.Fatal("unknown certificate accepted")
	}
	if _, err := Convert(set, CertificateID(f.leaf.cert), "zip", ""); err == nil {
		t.Fatal("unknown target accepted")
	}
}

func TestWriteNewNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.pem")
	if err := os.WriteFile(src, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(src, []byte("x"), []string{src}); err == nil {
		t.Fatal("source overwrite accepted")
	}
	if err := WriteNew(strings.ToUpper(src[:1])+src[1:], []byte("x"), []string{src}); err == nil {
		t.Fatal("source overwrite with different case accepted")
	}
	existing := filepath.Join(dir, "existing.pem")
	_ = os.WriteFile(existing, []byte("keep"), 0o600)
	if err := WriteNew(existing, []byte("x"), nil); err == nil {
		t.Fatal("existing file replaced")
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Fatal("existing file modified")
	}
	if b, _ := os.ReadFile(src); string(b) != "original" {
		t.Fatal("source modified")
	}
	out := filepath.Join(dir, "new.pem")
	if err := WriteNew(out, []byte("new"), []string{src}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "new" {
		t.Fatal("new file content")
	}
}

func TestReportsContainNoSecrets(t *testing.T) {
	f := newFixture(t)
	pfx, _ := pkcs12.Modern2023.Encode(f.leaf.key, f.leaf.cert, []*x509.Certificate{f.inter.cert}, "report-secret-pw")
	inputs := []Input{
		{"site <b>&.pfx", mustParse(t, pfx, "report-secret-pw")},
		{"root.cer", mustParse(t, f.root.cert.Raw, "")},
	}
	a := Analyze(inputs, now, 30)
	js, err := ReportJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	html, err := ReportHTML(a)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(f.leaf.key)
	keyB64 := base64.StdEncoding.EncodeToString(keyDER)
	d := f.leaf.key.(*ecdsa.PrivateKey).D.Text(16)
	for name, report := range map[string][]byte{"json": js, "html": html} {
		s := string(report)
		for _, secret := range []string{"report-secret-pw", keyB64[:40], d, "PRIVATE KEY-----"} {
			if strings.Contains(strings.ToLower(s), strings.ToLower(secret)) {
				t.Fatalf("%s report contains secret material %q", name, secret[:8])
			}
		}
		if !strings.Contains(s, Fingerprint(sha256Of(f.leaf.cert.Raw))) {
			t.Fatalf("%s report lacks SHA-256 fingerprint", name)
		}
	}
	if strings.Contains(string(html), "<b>&") || !strings.Contains(string(html), "site &lt;b&gt;&amp;.pfx") {
		t.Fatal("HTML report does not escape file names")
	}
	if strings.Contains(string(html), "<script") || strings.Contains(string(html), "http://") {
		t.Fatal("HTML report must be static and self-contained")
	}
	var back Analysis
	if err := json.Unmarshal(js, &back); err != nil || len(back.Certificates) != 3 || back.Chains[0].Status != "complete" {
		t.Fatalf("JSON round trip %v", err)
	}
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
