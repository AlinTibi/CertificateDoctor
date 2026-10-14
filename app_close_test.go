package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/AlinTibi/CertificateDoctor/internal/certs"
	"testing"
)

func TestCloseFileReleasesKeyReferences(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	app := NewApp()
	app.files = []*loadedFile{{id: "synthetic", name: "synthetic.key", state: "ready", parsed: &certs.Parsed{Format: certs.FormatPEM, Keys: []crypto.Signer{key}}}}
	closed := app.files[0]
	app.RemoveFile("synthetic")
	if len(app.files) != 0 {
		t.Fatal("file still listed")
	}
	if cap(app.files) > 0 && app.files[:cap(app.files)][0] != nil {
		t.Error("removed private-key file still retained in backing array after Close")
	}
	if closed.parsed != nil || closed.data != nil {
		t.Fatal("closed file retains loaded content")
	}
}

func TestClearReleasesAllLoadedContent(t *testing.T) {
	app := NewApp()
	app.files = []*loadedFile{{id: "password", data: []byte("synthetic encrypted content")}, {id: "parsed", parsed: &certs.Parsed{Format: certs.FormatPEM}}}
	backing := app.files
	first, second := app.files[0], app.files[1]
	app.Clear()
	if app.files != nil || backing[0] != nil || backing[1] != nil || first.data != nil || second.parsed != nil {
		t.Fatal("Close all retains loaded content or references")
	}
}
