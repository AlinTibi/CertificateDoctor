# Contributing

Keep this a focused, offline certificate inspection and conversion tool. Never commit real certificates, keys or key stores; generate fixtures inside tests. Do not add networking, telemetry, automatic downloads, revocation fetching or trust-store access without a documented design change.

Run frontend tests/build, `go vet ./...` and `go test ./...`. For Windows packaging use the Wails CLI version in go.mod and `-webview2 browser`; WebView2 must remain a separate dependency.
