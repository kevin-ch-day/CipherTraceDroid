# Research data policy

`data/raw/` is intentionally ignored except for its placeholder. Store raw captures outside Git and record their SHA-256 values in the session manifest. The primary processing path retains packet metadata only; it must not export plaintext, URLs, DNS hostnames, TLS SNI, certificates, credentials, cookies, or tokens as features.
