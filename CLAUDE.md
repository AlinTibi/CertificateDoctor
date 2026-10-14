# Working rules for this repository

## Process

- One step at a time. After each step report what changed, how to test it and what comes next, then wait for "continue".
- Write complete files, not fragments. Make careful, reversible changes; do not delete or rewrite anything that was not requested.
- No `Co-Authored-By`, no "Generated with" lines and no other attribution in commits, pull requests or files. AlinTibi is the only contributor. Do not add collaborators.
- Small commits with clear English messages, on `main`, never force push. Do not make the repository public and do not publish releases without explicit approval from the owner.
- All public content (README, UI, texts, comments) is in English. Talk to the owner in Romanian.
- Do not claim something is verified unless the command or test was actually run.

## Product constraints

- Windows 10/11 x64, portable self-contained ZIP, no installer.
- Fully offline: no network, accounts, telemetry, analytics or ads.
- Stack: Go + Wails v2 + TypeScript, like CSV Doctor and API Model Forge.
- v1.0 scope and limits are defined in `docs/SPEC.md`. No revocation (OCSP/CRL), AIA downloads, CSR generation, signing or editing.
- Private keys and passwords are never logged and never written to disk except on an explicit user export. Passwords stay in memory only. Originals are never overwritten.
- Never commit real certificates or keys. Test fixtures are generated inside the tests.

## Commands

```powershell
cd frontend; npm ci; npm test; npm run build; cd ..
go vet ./...
go test ./...
wails build -clean -s -webview2 browser
./scripts/package.ps1 -Version 1.0.0
```
