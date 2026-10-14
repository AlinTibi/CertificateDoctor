package certs

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity of a finding.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
	SeverityOK      Severity = "ok"
)

// Finding is one result of the checks.
type Finding struct {
	Severity      Severity `json:"severity"`
	Code          string   `json:"code"`
	Title         string   `json:"title"`
	Detail        string   `json:"detail"`
	CertificateID string   `json:"certificateId,omitempty"`
}

// ChainLink is one certificate in a built chain.
type ChainLink struct {
	CertificateID string `json:"certificateId"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	Validity      string `json:"validity"`
}

// Chain is the path from an end certificate towards a root, using provided files only.
type Chain struct {
	LeafID  string      `json:"leafId"`
	Name    string      `json:"name"`
	Links   []ChainLink `json:"links"`
	Status  string      `json:"status"`
	Summary string      `json:"summary"`
	KeyID   string      `json:"keyId,omitempty"`
}

// Key describes a private key without exposing key material.
type Key struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	Source        string `json:"source"`
	CertificateID string `json:"certificateId,omitempty"`
	Matched       bool   `json:"matched"`
}

// FileSummary describes one loaded file in reports.
type FileSummary struct {
	Name         string   `json:"name"`
	Format       Format   `json:"format"`
	Certificates int      `json:"certificates"`
	Keys         int      `json:"keys"`
	Notes        []string `json:"notes"`
}

// Input is one successfully parsed file.
type Input struct {
	Name   string
	Parsed *Parsed
}

// Analysis is the complete result of inspecting a set of files.
type Analysis struct {
	Tool             string           `json:"tool"`
	GeneratedAt      time.Time        `json:"generatedAt"`
	ExpiringSoonDays int              `json:"expiringSoonDays"`
	Verdict          Severity         `json:"verdict"`
	VerdictText      string           `json:"verdictText"`
	Counts           map[Severity]int `json:"counts"`
	Files            []FileSummary    `json:"files"`
	Certificates     []Certificate    `json:"certificates"`
	Keys             []Key            `json:"keys"`
	Chains           []Chain          `json:"chains"`
	Findings         []Finding        `json:"findings"`
	Limitations      []string         `json:"limitations"`
}

// Limitations are the checks Certificate Doctor v1.0 does not perform.
var Limitations = []string{
	"Revocation is not checked (no OCSP or CRL requests).",
	"Missing certificates are not downloaded (no AIA fetching); chains are built only from the files you provide.",
	"Trust is not evaluated against the Windows certificate store or any other trust store.",
	"Hostname matching, certificate policies and name constraints are not validated.",
}

// Set is the de-duplicated content of several files, used by checks and conversions.
type Set struct {
	Certs   []*x509.Certificate
	Keys    []crypto.Signer
	sources map[string][]string
	keySrc  map[string]string
}

// NewSet merges inputs, removing duplicate certificates and keys.
func NewSet(inputs []Input) *Set {
	s := &Set{sources: map[string][]string{}, keySrc: map[string]string{}}
	for _, in := range inputs {
		for _, c := range in.Parsed.Certificates {
			id := CertificateID(c)
			if _, seen := s.sources[id]; !seen {
				s.Certs = append(s.Certs, c)
			}
			if !contains(s.sources[id], in.Name) {
				s.sources[id] = append(s.sources[id], in.Name)
			}
		}
		for _, k := range in.Parsed.Keys {
			id := KeyID(k.Public())
			if _, seen := s.keySrc[id]; seen {
				continue
			}
			s.keySrc[id] = in.Name
			s.Keys = append(s.Keys, k)
		}
	}
	return s
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Certificate returns the certificate with the given ID.
func (s *Set) Certificate(id string) *x509.Certificate {
	for _, c := range s.Certs {
		if CertificateID(c) == id {
			return c
		}
	}
	return nil
}

// KeyFor returns the private key whose public key matches the certificate.
func (s *Set) KeyFor(c *x509.Certificate) crypto.Signer {
	for _, k := range s.Keys {
		if PublicKeysEqual(k.Public(), c.PublicKey) {
			return k
		}
	}
	return nil
}

// PublicKeysEqual compares two public keys.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// signedBy reports whether parent's key verified child's signature. SHA-1 and
// other algorithms rejected as insecure are accepted for path building and
// reported separately as weak signatures.
func signedBy(child, parent *x509.Certificate) bool {
	if !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false
	}
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	return err == nil || isInsecureAlgorithm(err)
}

// Issuer returns the provided certificate that issued c, preferring the newest.
func (s *Set) Issuer(c *x509.Certificate) *x509.Certificate {
	var best *x509.Certificate
	for _, p := range s.Certs {
		if p == c || bytes.Equal(p.Raw, c.Raw) || !signedBy(c, p) {
			continue
		}
		if best == nil || p.NotAfter.After(best.NotAfter) {
			best = p
		}
	}
	return best
}

// ChainFrom returns c followed by its issuers found in the set.
func (s *Set) ChainFrom(c *x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{c}
	seen := map[string]bool{CertificateID(c): true}
	for cur := c; !IsSelfSigned(cur); {
		next := s.Issuer(cur)
		if next == nil || seen[CertificateID(next)] {
			break
		}
		seen[CertificateID(next)] = true
		chain = append(chain, next)
		cur = next
	}
	return chain
}

// ends returns certificates that did not issue any other provided certificate.
func (s *Set) ends() []*x509.Certificate {
	issuers := map[string]bool{}
	for _, c := range s.Certs {
		if IsSelfSigned(c) {
			continue
		}
		if p := s.Issuer(c); p != nil {
			issuers[CertificateID(p)] = true
		}
	}
	var out []*x509.Certificate
	for _, c := range s.Certs {
		if !issuers[CertificateID(c)] {
			out = append(out, c)
		}
	}
	return out
}

// Analyze inspects the provided files at time now and reports findings.
func Analyze(inputs []Input, now time.Time, soonDays int) Analysis {
	if soonDays <= 0 {
		soonDays = 30
	}
	set := NewSet(inputs)
	a := Analysis{
		Tool:             "Certificate Doctor 1.0.0",
		GeneratedAt:      now.UTC().Truncate(time.Second),
		ExpiringSoonDays: soonDays,
		Counts:           map[Severity]int{},
		Files:            []FileSummary{},
		Certificates:     []Certificate{},
		Keys:             []Key{},
		Chains:           []Chain{},
		Findings:         []Finding{},
		Limitations:      Limitations,
	}
	add := func(f Finding) { a.Findings = append(a.Findings, f) }
	described := map[string]Certificate{}
	for _, c := range set.Certs {
		d := Describe(c, now, soonDays)
		d.Sources = set.sources[d.ID]
		described[d.ID] = d
		a.Certificates = append(a.Certificates, d)
	}

	for _, in := range inputs {
		notes := in.Parsed.Notes
		if notes == nil {
			notes = []string{}
		}
		a.Files = append(a.Files, FileSummary{Name: in.Name, Format: in.Parsed.Format, Certificates: len(in.Parsed.Certificates), Keys: len(in.Parsed.Keys), Notes: notes})
		for _, n := range in.Parsed.Notes {
			sev := SeverityInfo
			if strings.Contains(n, "cannot decrypt") {
				sev = SeverityWarning
			}
			add(Finding{Severity: sev, Code: "file-note", Title: in.Name, Detail: n})
		}
		checkOrder(in, set, add)
	}

	// Validity and weakness, per certificate.
	for _, c := range set.Certs {
		d := described[CertificateID(c)]
		name := fmt.Sprintf("%s (%s)", d.SubjectName, d.Role)
		switch d.Validity {
		case "expired":
			add(Finding{SeverityError, "expired", "Expired: " + name, fmt.Sprintf("Expired on %s UTC (%d days ago).", d.NotAfter.Format("2006-01-02 15:04"), -d.DaysRemaining), d.ID})
		case "not-yet-valid":
			add(Finding{SeverityError, "not-yet-valid", "Not yet valid: " + name, fmt.Sprintf("Valid from %s UTC. Check the system clock or the certificate dates.", d.NotBefore.Format("2006-01-02 15:04")), d.ID})
		case "expiring-soon":
			add(Finding{SeverityWarning, "expiring-soon", "Expires soon: " + name, fmt.Sprintf("Expires on %s UTC, in %d days.", d.NotAfter.Format("2006-01-02 15:04"), d.DaysRemaining), d.ID})
		}
		if rsaKey, ok := c.PublicKey.(*rsa.PublicKey); ok && rsaKey.N.BitLen() < 2048 {
			add(Finding{SeverityWarning, "weak-key", "Weak key: " + name, fmt.Sprintf("RSA %d-bit keys are below the 2048-bit minimum accepted by current browsers and CAs.", rsaKey.N.BitLen()), d.ID})
		}
		if !d.SelfSigned {
			switch c.SignatureAlgorithm {
			case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.MD5WithRSA, x509.MD2WithRSA:
				add(Finding{SeverityWarning, "weak-signature", "Weak signature: " + name, d.SignatureAlgorithm + " signatures are rejected by modern clients.", d.ID})
			}
		}
	}

	// Chains.
	ends := set.ends()
	sort.SliceStable(ends, func(i, j int) bool {
		ci, cj := ends[i].BasicConstraintsValid && ends[i].IsCA, ends[j].BasicConstraintsValid && ends[j].IsCA
		if ci != cj {
			return !ci
		}
		return DisplayName(ends[i], true) < DisplayName(ends[j], true)
	})
	for _, end := range ends {
		chainCerts := set.ChainFrom(end)
		ch := Chain{LeafID: CertificateID(end), Name: DisplayName(end, true)}
		for _, c := range chainCerts {
			d := described[CertificateID(c)]
			ch.Links = append(ch.Links, ChainLink{d.ID, d.SubjectName, d.Role, d.Validity})
		}
		if k := set.KeyFor(end); k != nil {
			ch.KeyID = KeyID(k.Public())
		}
		top := chainCerts[len(chainCerts)-1]
		topD := described[CertificateID(top)]
		switch {
		case IsSelfSigned(top) && len(chainCerts) == 1 && !topD.IsCA:
			ch.Status = "self-signed"
			ch.Summary = "Self-signed certificate. Clients trust it only if it is installed explicitly."
			add(Finding{SeverityInfo, "self-signed", "Self-signed: " + ch.Name, ch.Summary, ch.LeafID})
		case IsSelfSigned(top) && len(chainCerts) == 1:
			ch.Status = "root-only"
			ch.Summary = "A root certificate on its own."
		case IsSelfSigned(top):
			ch.Status = "complete"
			ch.Summary = fmt.Sprintf("Complete chain of %d certificates up to the root %q provided in your files. Trust is not evaluated.", len(chainCerts), topD.SubjectName)
			add(Finding{SeverityOK, "chain-complete", "Chain complete: " + ch.Name, ch.Summary, ch.LeafID})
		case len(chainCerts) == 1:
			ch.Status = "issuer-missing"
			ch.Summary = fmt.Sprintf("The issuer %q was not provided. An intermediate certificate is probably missing; servers must send it with the certificate.", topD.IssuerName)
			add(Finding{SeverityWarning, "issuer-missing", "Missing issuer: " + ch.Name, ch.Summary, ch.LeafID})
		default:
			ch.Status = "root-not-provided"
			ch.Summary = fmt.Sprintf("Chain of %d certificates ends at %q; its issuer %q was not provided. This is normal when the root is already in the client trust store.", len(chainCerts), topD.SubjectName, topD.IssuerName)
			add(Finding{SeverityOK, "chain-to-intermediate", "Chain linked: " + ch.Name, ch.Summary, ch.LeafID})
		}
		for i := 1; i < len(chainCerts); i++ {
			p := chainCerts[i]
			if !(p.BasicConstraintsValid && p.IsCA) {
				add(Finding{SeverityWarning, "issuer-not-ca", "Issuer is not marked as a CA: " + DisplayName(p, true), "It signed " + DisplayName(chainCerts[i-1], true) + " but lacks the CA basic constraint; clients will reject this chain.", CertificateID(p)})
			}
		}
		for _, c := range chainCerts[1:] {
			if c.NotAfter.Before(end.NotAfter) && now.Before(c.NotAfter) {
				add(Finding{SeverityInfo, "issuer-expires-first", "Issuer expires before the certificate: " + DisplayName(c, true), fmt.Sprintf("The chain stops being valid on %s UTC, before %s expires.", c.NotAfter.UTC().Format("2006-01-02"), DisplayName(end, true)), CertificateID(c)})
				break
			}
		}
		a.Chains = append(a.Chains, ch)
	}
	for _, c := range set.Certs {
		if IsSelfSigned(c) || set.Issuer(c) != nil {
			continue
		}
		for _, p := range set.Certs {
			if p != c && bytes.Equal(c.RawIssuer, p.RawSubject) {
				add(Finding{SeverityError, "signature-mismatch", "Issuer signature does not verify: " + DisplayName(c, true), fmt.Sprintf("A certificate named %q was provided, but it did not sign this certificate. It may be a different generation of the issuer.", DisplayName(p, true)), CertificateID(c)})
				break
			}
		}
	}

	// Private keys.
	for _, k := range set.Keys {
		_, _, desc := KeyDescription(k.Public())
		key := Key{ID: KeyID(k.Public()), Description: desc, Source: set.keySrc[KeyID(k.Public())]}
		for _, c := range set.Certs {
			if PublicKeysEqual(k.Public(), c.PublicKey) {
				key.CertificateID, key.Matched = CertificateID(c), true
				break
			}
		}
		if key.Matched {
			add(Finding{SeverityOK, "key-match", "Private key matches: " + described[key.CertificateID].SubjectName, fmt.Sprintf("The %s private key from %s belongs to this certificate.", desc, key.Source), key.CertificateID})
		} else if len(set.Certs) > 0 {
			add(Finding{SeverityError, "key-mismatch", "Private key matches no certificate", fmt.Sprintf("The %s private key from %s does not belong to any provided certificate.", desc, key.Source), ""})
		} else {
			add(Finding{SeverityInfo, "key-only", "Private key without certificate", fmt.Sprintf("Add the certificate to check that it matches the %s private key from %s.", desc, key.Source), ""})
		}
		a.Keys = append(a.Keys, key)
	}
	if len(set.Keys) == 0 && len(set.Certs) > 0 {
		add(Finding{SeverityInfo, "no-key", "No private key provided", "Key–certificate matching was not checked. Add a .key, .pem or .pfx file containing the private key to check it.", ""})
	}

	order := map[Severity]int{SeverityError: 0, SeverityWarning: 1, SeverityInfo: 2, SeverityOK: 3}
	sort.SliceStable(a.Findings, func(i, j int) bool { return order[a.Findings[i].Severity] < order[a.Findings[j].Severity] })
	for _, f := range a.Findings {
		a.Counts[f.Severity]++
	}
	switch {
	case len(set.Certs) == 0 && len(set.Keys) == 0:
		a.Verdict, a.VerdictText = SeverityInfo, "Open certificate files to start."
	case a.Counts[SeverityError] > 0:
		a.Verdict, a.VerdictText = SeverityError, plural(a.Counts[SeverityError], "problem needs", "problems need")+" attention."
	case a.Counts[SeverityWarning] > 0:
		a.Verdict, a.VerdictText = SeverityWarning, "No errors, "+plural(a.Counts[SeverityWarning], "warning", "warnings")+" to review."
	default:
		a.Verdict, a.VerdictText = SeverityOK, "No problems found in the provided files."
	}
	return a
}

// checkOrder reports multi-certificate files that are not ordered leaf first.
func checkOrder(in Input, set *Set, add func(Finding)) {
	certs := in.Parsed.Certificates
	if len(certs) < 2 || in.Parsed.Format == FormatPKCS7 || in.Parsed.Format == FormatPKCS12 {
		return
	}
	for i := 0; i+1 < len(certs); i++ {
		if !signedBy(certs[i], certs[i+1]) {
			add(Finding{SeverityInfo, "bundle-order", "Bundle order: " + in.Name, "Certificates are not ordered from the end-entity certificate up to its issuers. Many servers expect leaf first, then intermediates. Exporting a PEM chain writes the correct order.", ""})
			return
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
