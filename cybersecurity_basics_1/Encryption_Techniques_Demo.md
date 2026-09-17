# Encryption Techniques — AES & Hashing Demonstration

**Author:** Kyrell Green
**Date:** 2026-09-14
**Module:** Cyber Threats & Vulnerabilities / SOC Security Analyst track
**Method:** AES-256-CBC (symmetric encryption) + SHA-256 / MD5 (hashing) via the system
`openssl` toolkit. All outputs below were generated in this lab and are reproducible with the
exact commands shown.

---

## Part A — Symmetric Encryption (AES-256-CBC)

**What it is:** AES (Advanced Encryption Standard) is a symmetric cipher — **the same key
encrypts and decrypts**. This demo uses **AES-256-CBC**: a 256-bit key, Cipher Block Chaining
(each ciphertext block depends on the previous one, so repeated plaintext never repeats in
the ciphertext), plus a random **salt** with **PBKDF2** so the key is *derived* from the
passphrase instead of stored. The base64 output is `Salted__`-prefixed by OpenSSL.

### Worked example

**Plaintext (the secret):**
```
SOC alert GH-1024: successful logins observed on kali-lab-02 from 198.51.100.7 (ATT&CK T1078). Analyst approval required before containment.
```

**Encryption command used:**
```bash
printf '%s' 'SOC alert GH-1024: successful logins observed on kali-lab-02 from 198.51.100.7 (ATT&CK T1078). Analyst approval required before containment.' \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 120000 -salt -a -pass pass:'LabDemo!Passphrase2026'
```

**Ciphertext (base64, what is stored/transmitted instead of the secret):**
```
U2FsdGVkX194H/vF8ToOyHym+NF9OU1HWhZhUStFQ7e5MVZlH/9BMhDhjes3iiau
hfMZmug94N5Itt/4LmWcMudJO8MhQrJqDxXxaUdhfMrwFJ5vEsfn/Bpn+9pXszD2
yCEkZ3kvlyUmV3eGt8mV/0nMZZQ/mASz5wyOPYqw9tkMEidWOthXNlM7xxrr50Vi
91GbaKcX154HFCzRIcadmQ==
```

**Decryption command used (proving the round-trip works):**
```bash
printf '%s' 'U2FsdGVkX194H/vF8ToOyHym+NF9OU1HWhZhUStFQ7e5MVZlH/9BMhDhjes3iiau
hfMZmug94N5Itt/4LmWcMudJO8MhQrJqDxXxaUdhfMrwFJ5vEsfn/Bpn+9pXszD2
yCEkZ3kvlyUmV3eGt8mV/0nMZZQ/mASz5wyOPYqw9tkMEidWOthXNlM7xxrr50Vi
91GbaKcX154HFCzRIcadmQ==' \
  | openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -salt -a -pass pass:'LabDemo!Passphrase2026'
```

**Decrypted plaintext (verified identical to the input):**
```
SOC alert GH-1024: successful logins observed on kali-lab-02 from 198.51.100.7 (ATT&CK T1078). Analyst approval required before containment.
```

Recovered output matches the original byte-for-byte — the encryption is *reversible* with the
correct passphrase (this is what distinguishes encryption from hashing in Part B).

---

## Part B — Hashing (SHA-256 and MD5)

**What it is:** a hash is a **one-way, fixed-length fingerprint** of a text. Given only a
digest, the input cannot be recovered; even a one-character change to the input produces a
completely different digest. Hashes verify **integrity** ("did this file/message change?"),
not confidentiality. **MD5 is shown only for illustration — it is cryptographically broken and
must not be used for security decisions; SHA-256 is the standard for this purpose.**

**Text hashed:**
```
SOC alert GH-1024: successful logins observed on kali-lab-02 from 198.51.100.7 (ATT&CK T1078). Analyst approval required before containment.
```

| Algorithm | Command used | Digest (hex) |
|---|---|---|
| **SHA-256** | `printf '%s' '<text>' \| openssl dgst -sha256` | `12f464ad34334ddcea101cab799b7b3f25766c30d43b58c1586db59ac26ac59c` |
| MD5 (illustration only) | `printf '%s' '<text>' \| openssl dgst -md5` | `aef34abee9e241a4b4c66643ac5551d4` |

**Immediate verifiable property — a one-character change destroys the digest.** Changing
`GH-1024` to `GH-1025` re-hashes to an entirely unrelated value, which is why hashes are used
to detect tampering (the file-integrity use case, not a secret-keeping use case).

---

## Part C — Encryption vs. Hashing (why a SOC needs both)

| Property | AES encryption (Part A) | SHA-256 hashing (Part B) |
|---|---|---|
| Direction | Reversible (decrypt with key/passphrase) | One-way (cannot reverse) |
| Protects | **Confidentiality** (secrets stay secret) | **Integrity** (data is unaltered) |
| Output | Variable-length ciphertext | Fixed-length digest (64 hex chars for SHA-256) |
| Key/passphrase | Required to decrypt | None (a hash needs no key) |
| SOC example | TLS on the Wazuh API (`55000`), encrypted DB/es at rest | Wazuh FIM comparing file hashes; password-storage digests |

### Connected to the lab
- The Wazuh API already uses **TLS encryption** (the `https://` in `WAZUH_API_URL`) — this
  demo is the same concept at the data level: encrypt anything sensitive before storing or
  sending it, keep the passphrase out of code (secrets policy, per the Comprehensive Security
  Policy).
- **FIM (Wazuh `syscheck`)** applies Part B in practice: baseline file hashes are computed
  and re-checked — any unexpected hash change raises an Integrity alert. Passwords in any
  real system should likewise be stored as **SHA-256 (or stronger, e.g. bcrypt/Argon2)
  salted hashes**, never plaintext and never encrypted-only.

---

## Rubric Coverage

| Requirement | Addressed in |
|---|---|
| Encrypted text + corresponding decrypted plaintext using a consistent method (AES) | Part A — AES-256-CBC plaintext → ciphertext → exact decryption to the same plaintext |
| Text hashed with a standard hashing function (MD5 or SHA) | Part B — SHA-256 + MD5 digests of the same text with commands |
| Shared context for both | Part C — reversible encryption vs. one-way hashing, mapped to the CIA Triad and the lab |