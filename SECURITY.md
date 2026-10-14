# Security

Report vulnerabilities privately to security@almarfeld.com. Never send real private keys, PFX files or passwords; reproduce problems with generated test certificates.

Certificate Doctor works offline and does not contact OCSP responders, CRL distribution points or AIA URLs. It does not evaluate trust, revocation or hostnames, so a "complete chain" is not a statement that a certificate is trusted or safe. Binaries are not Authenticode signed; verify downloads with the published SHA-256 checksum.

Passwords are used in memory only. Private keys are written to disk only on explicit export, and reports never contain key material. Changes must keep these guarantees, refuse to overwrite existing files and be covered by regression tests.
