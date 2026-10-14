# Validation

Validated on Windows 11 x64 with Node 22.23.3, Go 1.27.0 and Wails 2.16.0.

## Automated

- Frontend: `npm ci`, 6 tests (escaping, validity labels, UTC dates, conversion availability, PFX password rules, file ordering), TypeScript checking and Vite production build pass.
- Go: `go vet ./...` and `go test ./...` pass. Certificate engine statement coverage: 87%.
- Formats: PEM chains, DER, PKCS#7 (DER and PEM), PEM with OpenSSL bag attributes, CRLF PEM, bare base64, PKCS#8/PKCS#1/EC keys, encrypted PEM keys reported, ignored CSR blocks, invalid and oversized input rejected.
- PKCS#12: modern AES and legacy RC2 files, password required, wrong password, correct password, passwordless certificate-only stores.
- Checks: complete chain from out-of-order files, missing intermediate, root not provided, gap between leaf and root, expired, not yet valid, expiring soon at different thresholds, issuer expiring first, key mismatch, same-name issuer that did not sign, key without certificate, self-signed, weak RSA key, bundle order.
- Conversions: PEM chain, PEM chain with key, key only, DER, P7B and PFX for RSA and ECDSA keys, parsed back successfully; short PFX passwords and conversions without a matching key are refused.
- Writes: source files and existing files are never overwritten (including a different-case path); new files are created.
- Reports: HTML and JSON contain fingerprints and no password or key material; HTML escapes file names and has no scripts or remote resources.
- App: unlocking with an empty, wrong and correct password; raw PFX data is released after loading; unsupported and missing files are rejected; threshold changes; closing files forgets keys.
- OpenSSL 3.5 interoperability: OpenSSL-generated PEM, key, P7B and PFX files load and match; Certificate Doctor PFX and P7B outputs are read by OpenSSL.
- Windows `certutil -dump` reads a Certificate Doctor PFX (chain and key, "Encryption test passed") and P7B.

## Interface

- The production frontend with the real Go backend was exercised through `wails dev` in a browser: loading six synthetic files, wrong PFX password message next to the file, successful unlock, complete chains, key matches, expiring-soon warning, convert dialog with key-dependent options and PFX password validation, and the HTML report layout.
- The screenshots in `docs/` were captured from that interface with synthetic "Contoso Demo" certificates generated for the purpose.
- Production build: `wails build -clean -s -webview2 browser` passes. Executable metadata: Certificate Doctor, ALMARFELD, 1.0.0.
- Portable package: the ZIP extracted into a folder whose path contains spaces starts `CertificateDoctor.exe` with the window title "Certificate Doctor", from an unrelated working directory.

## Not yet verified manually

Explorer drag and drop, the native Open/Save dialogs in the packaged executable, opening files passed on the command line, the missing-WebView2 message, and taskbar/Alt+Tab icon rendering. These paths use the same code as CSV Doctor but were not exercised for this release.

The executable is not Authenticode signed.

## v1.0.1 correction validation

The invalid MD5-RSA chain and retained closed-file references were independently reproduced before correction using generated certificates/keys in disposable copies of the project. Regression tests now reject an unverified MD5 issuer/root, verify valid SHA-1 signatures and reject corrupted SHA-1 signatures, and check individual/all-file content release.

`go vet ./...`, Go tests, all 6 frontend tests, TypeScript/Vite production build, and the clean Windows Wails production build pass locally. No dependencies were changed. Full packaged Windows interface checks are recorded separately after execution; previous v1.0.0 manual gaps above are historical and are not retroactively claimed as tested.

### Packaged Windows v1.0.1 RC.2 checks

On Windows 11, the freshly extracted portable RC.2 launched from a directory containing spaces. The real native Open dialog loaded PEM/key/PFX files together and reported malformed and unsupported inputs clearly. Unlocking the generated PFX succeeded and its key matched the certificate. Incomplete file inspection remained an error until the invalid file was closed; closing it removed the stale finding.

Native JSON export created a parseable report containing the uninspected file and no private-key blocks or synthetic PFX password. Cancelling a second export created no file. Native PEM conversion produced a new copy with certificate DER bytes identical to the original. Every original synthetic input retained its SHA-256.

The portable EXE also launched in Windows Sandbox without source/build directories. That Sandbox image already includes WebView2. Its window and taskbar showed the Certificate Doctor icon, and Explorer showed the packaged executable icon; the ICO contains 16, 32, 48, 64, 128 and 256 pixel frames.

Missing-runtime validation: not safely reproduced as a true absent-runtime environment. The standard Sandbox contains WebView2, and a separate disposable runtime-discovery simulation did not yield a verifiable result. No host runtime, registry or Windows security setting was altered. Explorer cross-window drag/drop and Alt+Tab rendering are not claimed as manually verified. Backend AddFiles and all supported conversion round trips are covered by automated tests.
