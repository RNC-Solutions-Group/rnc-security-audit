# CP4 private-key and structured-secret handling

> **Status:** Implemented and locally regression-tested; CI evidence is recorded
> in [CP4 validation](cp4-validation.md). All validation is offline. No parsed
> key is used, exported, uploaded or checked against a provider.

## Supported representations

| Representation | Rule | Recognition | Validation | Status |
| --- | --- | --- | --- | --- |
| Traditional PEM (`RSA`, `EC`, `DSA`) | `pem-private-key` | Bounded BEGIN/END labels, optional indentation, CRLF/LF, optional bounded log prefix | UTF-8, label match, base64, decoded size, DER child shape, placeholder checks | Supported |
| PKCS#8 (`PRIVATE KEY`) | `pem-private-key` | Same PEM framing | DER sequence with integer + algorithm sequence + bounded content | Supported |
| Encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) | `pem-private-key` | Same PEM framing | DER sequence with encryption parameters; payload remains encrypted and unverified | Supported; structural |
| OpenSSH (`OPENSSH PRIVATE KEY`) | `pem-private-key` | Same PEM framing | `openssh-key-v1\0` magic and bounded decoded size | Supported; structural |
| Escaped PEM in JSON/source strings | `pem-private-key-escaped` | Literal `\n`, optional `\r`, and bounded encoded body inside a JSON/source string | Bounded unescape, then the same PEM structural validator | Supported; source coordinates preserved |
| Base64-wrapped PEM | `pem-private-key-base64` | Documented base64 prefix for `-----BEGIN ` plus bounded base64 body | Bounded base64 decode, then private-key label and structural validation | Supported; structural |
| OpenPGP secret-key armor | `pem-private-key-pgp` | `-----BEGIN PGP PRIVATE KEY BLOCK-----`, bounded headers/body/checksum, END label | Armor framing, base64, optional CRC-24, secret-key/subkey packet tag | Supported; structural, plausible only |
| PEM in application logs | `pem-private-key` | Up to 256 bytes of bounded non-newline log prefix before the PEM boundary | Same PEM validator; finding starts at the PEM boundary | Supported |
| Public keys and certificates | none | `BEGIN PUBLIC KEY`, `BEGIN CERTIFICATE` and PGP public labels are not private-key labels | Explicitly rejected | Not emitted |

## Structural semantics

- A PEM block must have matching BEGIN and END labels. Mismatched or incomplete
  blocks are rejected.
- Base64 must decode. Bodies are bounded to 400 encoded lines and 64 KiB.
- Repeated/single-character bodies and known documentation placeholders are
  rejected.
- `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `PRIVATE KEY` and
  `ENCRYPTED PRIVATE KEY` have distinct bounded DER shape checks.
- OpenSSH content must begin with the `openssh-key-v1\0` magic. This does not
  prove the key is usable.
- PGP armor must begin with a secret-key label; the first decoded packet must be
  tag 5 (secret key) or 7 (secret subkey). A CRC-24 line, when present, must
  match. PGP public-key armor is rejected.
- A malformed or unverifiable structure is not silently promoted to a confirmed
  key. If the container is recognizable but the internal shape cannot be
  established, the finding is `PLAUSIBLE_UNVERIFIED` with a static structural
  note instead of `FORMAT_VALID`.

The validators never require, derive or test operational usability. They do not
perform cryptographic operations on the key and do not establish that the key
is unencrypted, complete, authorized or non-revoked.

## Escaped representations and source attribution

The escaped-PEM rule matches the original encoded bytes. Validation decodes a
bounded set of escapes in memory, then runs the PEM checks. The finding event
still points at the original JSON/source byte range, original line and original
evidence digest. Decoded data is never substituted into the evidence span.

The same principle applies to base64-wrapped PEM: the finding covers the
base64 text in the original file, not the decoded container.

## Malformed and boundary tests

Positive coverage includes PEM in a log line, escaped JSON, base64-wrapped PEM
and PGP secret armor. Negative coverage includes:

- PEM public-key and certificate blocks;
- PGP public-key armor;
- truncated private-key armor;
- base64-wrapped public keys;
- a PGP block with an invalid CRC;
- repeated placeholder key bodies and malformed base64;
- same-line and multiline surrounding text;
- whole-file and streaming modes and all four matching strategies.

The Rust fixture uses a deliberately inconsistent PKCS#8-shaped container. It
is not a usable private key and is never committed as a real credential.

## Limits and residual risk

- PEM detection is bounded but not a complete ASN.1 parser. Complex or
  proprietary containers can be reported as structurally plausible without
  proving their semantics.
- Encrypted PKCS#8 and OpenSSH keys may hide their internal key material; the
  scanner reports the container, not the decrypted material.
- PGP packet parsing validates the first packet tag and bounded armor, not the
  complete packet stream or cryptographic integrity.
- Alternate encodings beyond escaped strings and base64-wrapped PEM are not
  implemented.
- Key detection is not proof that the key is currently usable or unrevoked.
