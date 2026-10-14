package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AlinTibi/CertificateDoctor/internal/certs"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// MaxFiles limits how many files can be inspected together.
const MaxFiles = 32

var supportedExtensions = map[string]bool{".cer": true, ".crt": true, ".pem": true, ".der": true, ".pfx": true, ".p12": true, ".p7b": true, ".p7c": true, ".key": true}

type loadedFile struct {
	id     string
	path   string
	name   string
	data   []byte // kept only while a password is still needed
	parsed *certs.Parsed
	state  string
	err    string
}

// App is the desktop backend bound to the frontend.
type App struct {
	ctx      context.Context
	mu       sync.Mutex
	files    []*loadedFile
	soonDays int
	now      func() time.Time
}

// FileView is the frontend representation of a loaded file.
type FileView struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	State        string       `json:"state"` // ready, password, error
	Error        string       `json:"error"`
	Format       certs.Format `json:"format"`
	Certificates int          `json:"certificates"`
	Keys         int          `json:"keys"`
}

// View is the complete state shown by the frontend.
type View struct {
	Files            []FileView     `json:"files"`
	Analysis         certs.Analysis `json:"analysis"`
	ExpiringSoonDays int            `json:"expiringSoonDays"`
	Rejected         []string       `json:"rejected"`
}

// SaveResult reports the outcome of a save dialog.
type SaveResult struct {
	Cancelled bool   `json:"cancelled"`
	Filename  string `json:"filename"`
}

func NewApp() *App { return &App{soonDays: 30, now: time.Now} }

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("Cannot create an identifier")
	}
	return hex.EncodeToString(b[:])
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	if len(os.Args) > 1 {
		_, _ = a.AddFiles(os.Args[1:])
	}
}

// State returns the current view.
func (a *App) State() View {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.view(nil)
}

func (a *App) view(rejected []string) View {
	v := View{Files: []FileView{}, ExpiringSoonDays: a.soonDays, Rejected: rejected}
	if v.Rejected == nil {
		v.Rejected = []string{}
	}
	var inputs []certs.Input
	for _, f := range a.files {
		fv := FileView{ID: f.id, Name: f.name, State: f.state, Error: f.err}
		if f.parsed != nil {
			fv.Format, fv.Certificates, fv.Keys = f.parsed.Format, len(f.parsed.Certificates), len(f.parsed.Keys)
			inputs = append(inputs, certs.Input{Name: f.name, Parsed: f.parsed})
		}
		v.Files = append(v.Files, fv)
	}
	v.Analysis = certs.Analyze(inputs, a.now(), a.soonDays)
	for _, f := range a.files {
		if f.state != "error" && f.state != "password" {
			continue
		}
		reason, severity, code := f.err, certs.SeverityError, "file-not-inspected"
		if f.state == "password" {
			severity, code = certs.SeverityWarning, "password-required"
			if reason == "" {
				reason = "Enter the PFX password to inspect this file."
			}
		}
		v.Analysis.Files = append(v.Analysis.Files, certs.FileSummary{Name: f.name, Notes: []string{"Not inspected: " + reason}})
		v.Analysis.Findings = append(v.Analysis.Findings, certs.Finding{Severity: severity, Code: code, Title: "File not inspected: " + f.name, Detail: reason})
		v.Analysis.Counts[severity]++
	}
	if v.Analysis.Counts[certs.SeverityError] > 0 {
		v.Analysis.Verdict = certs.SeverityError
		v.Analysis.VerdictText = "Problems need attention. Review findings and files that were not inspected."
	} else if v.Analysis.Counts[certs.SeverityWarning] > 0 {
		v.Analysis.Verdict = certs.SeverityWarning
		v.Analysis.VerdictText = "Warnings need review. Some checks or files may be incomplete."
	}
	order := map[certs.Severity]int{certs.SeverityError: 0, certs.SeverityWarning: 1, certs.SeverityInfo: 2, certs.SeverityOK: 3}
	sort.SliceStable(v.Analysis.Findings, func(i, j int) bool {
		return order[v.Analysis.Findings[i].Severity] < order[v.Analysis.Findings[j].Severity]
	})
	return v
}

func (a *App) set() *certs.Set {
	var inputs []certs.Input
	for _, f := range a.files {
		if f.parsed != nil {
			inputs = append(inputs, certs.Input{Name: f.name, Parsed: f.parsed})
		}
	}
	return certs.NewSet(inputs)
}

func (a *App) sources() []string {
	out := make([]string, 0, len(a.files))
	for _, f := range a.files {
		out = append(out, f.path)
	}
	return out
}

// OpenFiles shows the native open dialog and adds the chosen files.
func (a *App) OpenFiles() (View, error) {
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Open certificate files",
		Filters: []runtime.FileFilter{
			{DisplayName: "Certificates and keys (*.cer; *.crt; *.pem; *.der; *.pfx; *.p12; *.p7b; *.key)", Pattern: "*.cer;*.crt;*.pem;*.der;*.pfx;*.p12;*.p7b;*.p7c;*.key"},
			{DisplayName: "All files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return a.State(), err
	}
	return a.AddFiles(paths)
}

// AddFiles loads files by path, for the open dialog, drag and drop and command-line arguments.
func (a *App) AddFiles(paths []string) (View, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var rejected []string
	for _, path := range paths {
		name := filepath.Base(path)
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			rejected = append(rejected, name+": not a readable file")
			continue
		}
		if !supportedExtensions[strings.ToLower(filepath.Ext(path))] {
			rejected = append(rejected, name+": unsupported file type")
			continue
		}
		duplicate := false
		for _, f := range a.files {
			if certs.SamePath(f.path, path) {
				duplicate = true
			}
		}
		if duplicate {
			continue
		}
		if len(a.files) >= MaxFiles {
			rejected = append(rejected, fmt.Sprintf("%s: at most %d files can be inspected together", name, MaxFiles))
			continue
		}
		f := &loadedFile{id: newID(), path: path, name: name}
		data, err := certs.ReadFile(path)
		if err != nil {
			f.state, f.err = "error", readError(err)
		} else {
			f.load(data, "")
		}
		a.files = append(a.files, f)
	}
	return a.view(rejected), nil
}

func readError(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "Access denied. Check the file permissions"
	}
	if errors.Is(err, certs.ErrTooLarge) {
		return err.Error()
	}
	return "The file cannot be read"
}

func (f *loadedFile) load(data []byte, password string) error {
	parsed, err := certs.Parse(data, password)
	switch {
	case err == nil:
		f.parsed, f.state, f.err, f.data = parsed, "ready", "", nil
	case errors.Is(err, certs.ErrPasswordRequired):
		f.parsed, f.state, f.err, f.data = nil, "password", "", data
	case errors.Is(err, certs.ErrWrongPassword):
		f.parsed, f.state, f.err, f.data = nil, "password", err.Error(), data
	default:
		f.parsed, f.state, f.err, f.data = nil, "error", err.Error(), nil
	}
	return err
}

// Unlock opens a password-protected PKCS#12 file. The password is used once
// and is not stored, logged or written anywhere.
func (a *App) Unlock(id, password string) (View, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range a.files {
		if f.id != id {
			continue
		}
		if f.state != "password" || f.data == nil {
			return a.view(nil), nil
		}
		if password == "" {
			return a.view(nil), errors.New("Enter the password for " + f.name)
		}
		if err := f.load(f.data, password); err != nil {
			return a.view(nil), err
		}
		return a.view(nil), nil
	}
	return a.view(nil), errors.New("This file is no longer loaded")
}

// RemoveFile closes one file and forgets its content.
func (a *App) RemoveFile(id string) View {
	a.mu.Lock()
	defer a.mu.Unlock()
	kept := a.files[:0]
	for _, f := range a.files {
		if f.id != id {
			kept = append(kept, f)
		} else {
			f.data = nil
			f.parsed = nil
		}
	}
	clear(a.files[len(kept):])
	a.files = kept
	return a.view(nil)
}

// Clear closes all files and forgets their content, including private keys.
func (a *App) Clear() View {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, f := range a.files {
		f.data = nil
		f.parsed = nil
	}
	clear(a.files)
	a.files = nil
	return a.view(nil)
}

// SetExpiringSoonDays changes the "expires soon" threshold.
func (a *App) SetExpiringSoonDays(days int) View {
	a.mu.Lock()
	defer a.mu.Unlock()
	if days >= 1 && days <= 365 {
		a.soonDays = days
	}
	return a.view(nil)
}

func safeBase(name string) string {
	name = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`<>:"/\|?*`, r) || r < 32 {
			return '_'
		}
		return r
	}, name)
	name = strings.Trim(name, " .")
	if name == "" || name == "(empty name)" {
		return "certificate"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

// Convert writes the chain of the selected certificate in another format to a
// new file chosen by the user. The sources are never modified.
func (a *App) Convert(leafID string, target string, password string) (SaveResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := certs.Target(target)
	ext, pattern, _, err := certs.TargetInfo(t)
	if err != nil {
		return SaveResult{}, err
	}
	set := a.set()
	data, err := certs.Convert(set, leafID, t, password)
	if err != nil {
		return SaveResult{}, err
	}
	base := safeBase(certs.DisplayName(set.Certificate(leafID), true))
	suffix := map[certs.Target]string{certs.TargetPEMChain: "-chain", certs.TargetPEMChainKey: "-chain-with-key", certs.TargetKeyPEM: "", certs.TargetDER: "", certs.TargetPKCS7: "-chain", certs.TargetPFX: ""}[t]
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save converted copy",
		DefaultFilename: base + suffix + ext,
		Filters:         []runtime.FileFilter{{DisplayName: strings.ToUpper(strings.TrimPrefix(ext, ".")) + " file", Pattern: pattern}},
	})
	if err != nil {
		return SaveResult{}, err
	}
	if path == "" {
		return SaveResult{Cancelled: true}, nil
	}
	if err := certs.WriteNew(path, data, a.sources()); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Filename: filepath.Base(path)}, nil
}

// ExportReport saves the current analysis as an HTML or JSON report.
func (a *App) ExportReport(format string) (SaveResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.view(nil)
	var data []byte
	var err error
	switch format {
	case "html":
		data, err = certs.ReportHTML(v.Analysis)
	case "json":
		data, err = certs.ReportJSON(v.Analysis)
	default:
		return SaveResult{}, fmt.Errorf("Unknown report format %q", format)
	}
	if err != nil {
		return SaveResult{}, err
	}
	name := "certificate-report-" + a.now().Format("2006-01-02") + "." + format
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save report",
		DefaultFilename: name,
		Filters:         []runtime.FileFilter{{DisplayName: strings.ToUpper(format) + " report", Pattern: "*." + format}},
	})
	if err != nil {
		return SaveResult{}, err
	}
	if path == "" {
		return SaveResult{Cancelled: true}, nil
	}
	if err := certs.WriteNew(path, data, a.sources()); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{Filename: filepath.Base(path)}, nil
}
