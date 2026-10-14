# v1.0.0

- Offline inspection of .cer, .crt, .pem, .der, .key, .pfx/.p12 and .p7b files: subject, issuer, validity, SAN, key algorithm and size, signature algorithm, key usages and SHA-1/SHA-256 fingerprints.
- Chain building from the provided files with clear results for complete chains, missing intermediates, roots not provided, self-signed certificates and issuer signature mismatches.
- Expired, not-yet-valid and expiring-soon checks with a configurable threshold; weak key and weak signature warnings.
- Private key to certificate matching.
- Conversion to new files: PEM chain, DER, P7B, PFX (AES-256, new password), PEM chain with key and key only.
- HTML and JSON reports without key material or passwords.
- Clear messages for password-protected PFX files and incorrect passwords.

Not included: revocation (OCSP/CRL), AIA downloads, trust-store evaluation, CSR generation, signing and editing. The executable is not Authenticode signed. Microsoft Edge WebView2 Runtime is required separately.
