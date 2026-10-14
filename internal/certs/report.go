package certs

import (
	"bytes"
	"encoding/json"
	"html/template"
	"strings"
	"time"
)

// ReportJSON returns the analysis as indented JSON. It never contains private
// key material or passwords; keys are identified by their public key hash.
func ReportJSON(a Analysis) ([]byte, error) {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

var reportFuncs = template.FuncMap{
	"date":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"join":  func(v []string) string { return strings.Join(v, ", ") },
	"upper": strings.ToUpper,
	"count": func(a Analysis, s string) int { return a.Counts[Severity(s)] },
	"cert": func(a Analysis, id string) *Certificate {
		for i := range a.Certificates {
			if a.Certificates[i].ID == id {
				return &a.Certificates[i]
			}
		}
		return nil
	},
}

var reportTemplate = template.Must(template.New("report").Funcs(reportFuncs).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Certificate Doctor report</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--text:#18202b;--muted:#5b6675;--line:#dde2e8;--error:#b42318;--warning:#a15c07;--ok:#067647;--info:#175cd3}
@media (prefers-color-scheme:dark){:root{--bg:#0d131d;--card:#141d2a;--text:#e7edf6;--muted:#9aa8ba;--line:#26344a;--error:#f97066;--warning:#fdb022;--ok:#47cd89;--info:#84caff}}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px;font-size:24px}h2{font-size:17px;margin:28px 0 10px}h3{font-size:15px;margin:0 0 8px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:10px 0}
.verdict{font-size:16px;font-weight:600}.error{color:var(--error)}.warning{color:var(--warning)}.ok{color:var(--ok)}.info{color:var(--info)}
.tag{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;border:1px solid currentColor;border-radius:999px;padding:0 8px;margin-right:8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:5px 8px;border-top:1px solid var(--line)}th{width:190px;color:var(--muted);font-weight:600}
code,.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12.5px;word-break:break-all}
ol{margin:0;padding-left:20px}footer{margin-top:32px;color:var(--muted);font-size:12px}
</style>
</head>
<body><main>
<h1>Certificate Doctor report</h1>
<p class="muted">Generated {{date .GeneratedAt}} by {{.Tool}} · “Expires soon” threshold: {{.ExpiringSoonDays}} days · Offline inspection of the files listed below</p>
<div class="card"><span class="verdict {{.Verdict}}">{{.VerdictText}}</span>
<div class="muted">{{count . "error"}} error(s) · {{count . "warning"}} warning(s) · {{count . "info"}} note(s) · {{count . "ok"}} passed</div></div>

<h2>Files</h2>
<div class="card"><table>{{range .Files}}<tr><th>{{.Name}}</th><td>{{if .Format}}{{.Format}} · {{.Certificates}} certificate(s) · {{.Keys}} private key(s){{else}}Not inspected{{end}}{{range .Notes}}<br><span class="muted">{{.}}</span>{{end}}</td></tr>{{end}}</table></div>

<h2>Findings</h2>
{{range .Findings}}<div class="card"><span class="tag {{.Severity}}">{{upper (print .Severity)}}</span><strong>{{.Title}}</strong><div class="muted">{{.Detail}}</div></div>{{end}}

<h2>Chains</h2>
{{$a := .}}{{range .Chains}}<div class="card"><h3>{{.Name}}</h3><ol>{{range .Links}}<li>{{.Name}} <span class="muted">· {{.Role}} · {{.Validity}}</span></li>{{end}}</ol><p class="muted">{{.Summary}}</p></div>{{else}}<p class="muted">No certificates.</p>{{end}}

<h2>Certificates</h2>
{{range .Certificates}}<div class="card"><h3>{{.SubjectName}} <span class="muted">· {{.Role}}</span></h3><table>
<tr><th>Subject</th><td>{{.Subject}}</td></tr>
<tr><th>Issuer</th><td>{{.Issuer}}</td></tr>
<tr><th>Valid from</th><td>{{date .NotBefore}}</td></tr>
<tr><th>Valid until</th><td>{{date .NotAfter}} <span class="{{if eq .Validity "valid"}}ok{{else if eq .Validity "expiring-soon"}}warning{{else}}error{{end}}">({{.Validity}}, {{.DaysRemaining}} days)</span></td></tr>
{{if .DNSNames}}<tr><th>DNS names</th><td>{{join .DNSNames}}</td></tr>{{end}}
{{if .IPAddresses}}<tr><th>IP addresses</th><td>{{join .IPAddresses}}</td></tr>{{end}}
{{if .EmailAddresses}}<tr><th>Email addresses</th><td>{{join .EmailAddresses}}</td></tr>{{end}}
{{if .URIs}}<tr><th>URIs</th><td>{{join .URIs}}</td></tr>{{end}}
<tr><th>Public key</th><td>{{.KeyDescription}}</td></tr>
<tr><th>Signature algorithm</th><td>{{.SignatureAlgorithm}}</td></tr>
{{if .KeyUsage}}<tr><th>Key usage</th><td>{{join .KeyUsage}}</td></tr>{{end}}
{{if .ExtKeyUsage}}<tr><th>Extended key usage</th><td>{{join .ExtKeyUsage}}</td></tr>{{end}}
<tr><th>Serial number</th><td class="mono">{{.SerialNumber}}</td></tr>
<tr><th>SHA-1</th><td class="mono">{{.SHA1}}</td></tr>
<tr><th>SHA-256</th><td class="mono">{{.SHA256}}</td></tr>
<tr><th>Found in</th><td>{{join .Sources}}</td></tr>
</table></div>{{end}}

{{if .Keys}}<h2>Private keys</h2>
<div class="card"><table>{{range .Keys}}<tr><th>{{.Description}}</th><td>From {{.Source}} · {{if .Matched}}<span class="ok">matches {{with cert $a .CertificateID}}{{.SubjectName}}{{end}}</span>{{else}}<span class="error">matches no provided certificate</span>{{end}}</td></tr>{{end}}</table>
<p class="muted">Key material is never included in reports.</p></div>{{end}}

<h2>Not checked</h2>
<div class="card"><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul></div>
<footer>Certificate Doctor · ALMARFELD · https://almarfeld.com/software/certificate-doctor/</footer>
</main></body></html>
`))

// ReportHTML renders a self-contained HTML report without scripts or external resources.
func ReportHTML(a Analysis) ([]byte, error) {
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, a); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
