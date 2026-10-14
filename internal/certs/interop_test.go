package certs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestOpenSSLInterop cross-checks parsing and conversion output with the
// OpenSSL command-line tool when it is available (for example from Git for
// Windows). Every file is generated in a temporary directory.
func TestOpenSSLInterop(t *testing.T) {
	bin, err := exec.LookPath("openssl")
	if err != nil {
		for _, c := range []string{`C:\Program Files\Git\mingw64\bin\openssl.exe`, `C:\Program Files\Git\usr\bin\openssl.exe`} {
			if _, statErr := os.Stat(c); statErr == nil {
				bin, err = c, nil
				break
			}
		}
	}
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	conf := filepath.Join(dir, "openssl.cnf")
	if err := os.WriteFile(conf, []byte("[req]\ndistinguished_name=dn\n[dn]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "OPENSSL_CONF="+conf)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
		return out
	}
	p := func(name string) string { return filepath.Join(dir, name) }

	run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", p("k.pem"), "-out", p("c.pem"), "-subj", "/CN=openssl.test", "-days", "30")
	run("crl2pkcs7", "-nocrl", "-certfile", p("c.pem"), "-outform", "DER", "-out", p("c.p7b"))
	run("pkcs12", "-export", "-inkey", p("k.pem"), "-in", p("c.pem"), "-out", p("c.pfx"), "-passout", "pass:interop-pass")

	read := func(name string) []byte {
		b, err := os.ReadFile(p(name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var inputs []Input
	for _, name := range []string{"c.pem", "k.pem", "c.p7b", "c.pfx"} {
		parsed, err := Parse(read(name), "interop-pass")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		inputs = append(inputs, Input{name, parsed})
	}
	a := Analyze(inputs, time.Now(), 7)
	if len(a.Certificates) != 1 || len(a.Keys) != 1 || !a.Keys[0].Matched {
		t.Fatalf("analysis %d certs %d keys", len(a.Certificates), len(a.Keys))
	}

	set := NewSet(inputs)
	id := a.Certificates[0].ID
	pfx, err := Convert(set, id, TargetPFX, "converted-pass")
	if err != nil {
		t.Fatal(err)
	}
	p7b, err := Convert(set, id, TargetPKCS7, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p("out.pfx"), pfx, 0o600)
	_ = os.WriteFile(p("out.p7b"), p7b, 0o600)
	if out := run("pkcs12", "-in", p("out.pfx"), "-passin", "pass:converted-pass", "-nodes"); !bytes.Contains(out, []byte("BEGIN PRIVATE KEY")) || !bytes.Contains(out, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("openssl did not read the converted PFX")
	}
	if out := run("pkcs7", "-inform", "DER", "-in", p("out.p7b"), "-print_certs"); !bytes.Contains(out, []byte("openssl.test")) {
		t.Fatal("openssl did not read the converted P7B")
	}
}
