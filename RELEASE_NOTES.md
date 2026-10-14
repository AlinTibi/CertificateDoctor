# Certificate Doctor v1.0.1

- Requires successful cryptographic signature verification before accepting an issuer or a self-signed root. MD5/MD2 verification is unavailable and is reported explicitly, rather than treated as successful.
- Releases loaded file/key references when closing one file or all files. This removes application references; it does not promise cryptographic erasure of process memory.
- Fixes CodeQL workflow permissions and adds signed-tag release automation.

Revocation, trust-store and hostname checks remain unavailable. Processing remains offline; originals and existing output files are never overwritten. Microsoft Edge WebView2 Runtime is required separately. Windows binaries are not Authenticode signed.

# v1.0.0

- Offline inspection of .cer, .crt, .pem, .der, .key, .pfx/.p12 and .p7b files: subject, issuer, validity, SAN, key algorithm and size, signature algorithm, key usages and SHA-1/SHA-256 fingerprints.
- Chain building from the provided files with clear results for complete chains, missing intermediates, roots not provided, self-signed certificates and issuer signature mismatches.
- Expired, not-yet-valid and expiring-soon checks with a configurable threshold; weak key and weak signature warnings.
- Private key to certificate matching.
- Conversion to new files: PEM chain, DER, P7B, PFX (AES-256, new password), PEM chain with key and key only.
- HTML and JSON reports without key material or passwords.
- Clear messages for password-protected PFX files and incorrect passwords.

Not included: revocation (OCSP/CRL), AIA downloads, trust-store evaluation, CSR generation, signing and editing. The executable is not Authenticode signed. Microsoft Edge WebView2 Runtime is required separately.
