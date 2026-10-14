# Certificate Doctor v1.0 — Specification

Certificate Doctor is an offline Windows utility from ALMARFELD for inspecting, checking and converting X.509 certificate files.

## Platform and distribution

- Windows 10/11 x64.
- Portable, self-contained ZIP. No installer.
- Requires the separately installed Microsoft Edge WebView2 Runtime (present on current Windows 10/11). Nothing is downloaded or installed automatically.
- Go + Wails v2 + TypeScript. Dark, clean, professional interface.

## Offline and privacy

- No network access, accounts, telemetry, analytics or advertising.
- Private keys and passwords are never logged and never written to disk, except when the user explicitly exports a converted file that contains a key.
- PKCS#12 passwords are used once to open the file and are kept in memory only. They are not stored in settings, reports or logs.
- Original files are never modified or overwritten. Every output is a new file; existing files are refused.
- Reports (HTML and JSON) contain certificate details, fingerprints and findings. They never contain private key material or passwords, and they name files by basename only.

## Supported input

| Extension | Content |
| --- | --- |
| `.cer`, `.crt`, `.der` | DER or PEM certificates (also bare base64 without PEM headers) |
| `.pem` | One or more PEM blocks: certificates, PKCS#7, unencrypted private keys (PKCS#8, PKCS#1, SEC1) |
| `.key` | Unencrypted private key (PEM or DER) |
| `.pfx`, `.p12` | PKCS#12 with one private key and its certificates, or certificate-only trust stores; modern (AES/PBES2) and legacy (3DES/RC2) encryption |
| `.p7b`, `.p7c` | PKCS#7 certificate bundles, DER or PEM |

Content is detected by structure, not by extension. Files are limited to 8 MiB; up to 32 files can be inspected together.

## Inspection

For each certificate: subject, issuer, serial number, validity period and days remaining, Subject Alternative Names (DNS, IP, email, URI), public key algorithm and size, signature algorithm, key usage, extended key usage, subject/authority key identifiers, role (end entity, intermediate CA, root CA, self-signed), SHA-1 and SHA-256 fingerprints, and the files where it was found. Duplicate certificates across files are merged.

## Checks

- **Chain**: built from the provided files only, by issuer name and signature verification. Reports a complete chain to a provided root, a chain ending at an intermediate whose root was not provided (normal for server bundles), a missing issuer (probably a missing intermediate), self-signed certificates, issuers that lack the CA basic constraint, an issuer with the right name that did not sign the certificate, and issuers that expire before the certificate.
- **Validity**: expired, not yet valid, and expiring within a configurable threshold (7, 14, 30, 60 or 90 days; default 30).
- **Weakness**: RSA keys below 2048 bits; SHA-1/MD5 signatures on non-root certificates.
- **Key match**: every private key is compared with every certificate's public key. Unmatched keys are errors.
- **Bundle order**: PEM files with several certificates not ordered leaf first.
- Encrypted PEM private keys are reported but not decrypted in v1.0.

## Conversions (always to a new file)

For a selected chain:

- PEM certificate chain (leaf first)
- DER certificate (`.cer`, selected certificate only)
- PKCS#7 chain (`.p7b`, certificates only)
- PKCS#12 / PFX with the matching private key, protected by a new password of at least 8 characters, AES-256-CBC with PBKDF2 and SHA-256 MAC (Windows 10 1709+, OpenSSL 1.1.1+, Java 11+)
- PEM chain plus unencrypted private key
- Unencrypted private key only (PKCS#8 PEM)

Outputs containing an unencrypted key show an explicit warning first. Output files inherit the permissions of the destination folder; choose a protected location for keys.

## Reports

HTML (self-contained, no scripts or external resources, light/dark) and JSON (machine-readable, same data).

## Out of scope for v1.0

- Revocation checks (OCSP, CRL)
- Downloading missing certificates (AIA)
- Trust evaluation against the Windows certificate store or any other trust store
- Hostname matching, policy and name-constraint validation
- CSR generation, signing, certificate or key editing
- Decrypting encrypted PEM private keys; PKCS#12 files with several private keys

These limits are stated in the README, on the product page and in the application.
