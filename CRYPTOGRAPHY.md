# Cryptography Documentation – SecureVault  
(Deutsch weiter unten / German below)

Effective Date: 2025-01-01  
Product: SecureVault – Encrypted Data Vault  
Owner: BYLICKILABS – Intelligence Systems & Communications  

---

## 1. Overview
SecureVault ensures strong and modern encryption for all stored data.  
All cryptographic operations are executed **locally**, never in the cloud.

There are **no recovery keys**, **no backdoors**, and **no plaintext persistence**.

---

## 2. Key Derivation (KDF)
| Component | Value |
|----------|------|
| Algorithm | Argon2id |
| Output Key Length | 256-bit |
| Salt Size | 16 bytes |
| Parameters | t=3 iterations, m=64 MiB, p=4 parallelism |

**Rationale:**  
Argon2id protects against GPU and ASIC brute-force attacks while preventing side-channel leaks.

---

## 3. Encryption Algorithms
SecureVault supports a dual AEAD encryption option:

| Mode | Purpose | Nonce | Strength |
|------|---------|-------|----------|
| AES-256-GCM | Default; high performance & hardware support | 12 bytes | Enterprise-grade |
| XChaCha20-Poly1305 | Modern alternative; extended nonce for maximum safety | 24 bytes | Robust & future-proof |

**AEAD** = Authenticated Encryption with Associated Data  
→ Ensures both **confidentiality** and **integrity**.

---

## 4. Container Format Specification
Data is stored inside a single encrypted container (`*.svc`):

| Offset | Description |
|--------|-------------|
| 0–4 | Magic Header (`SVLT1`) |
| 5 | Version |
| 6 | Cipher ID (1=AES-GCM / 2=XChaCha20) |
| 7–22 | Argon2 Salt |
| 23–34 | Argon2 Parameters (t, m, p) |
| 35 | Nonce Length |
| 36–… | Cipher Nonce |
| … | Ciphertext (compressed, authenticated) |

Container payload is **zlib-compressed JSON**.

---

## 5. Memory Handling
To minimize attack surface:
- Decrypted data exists **only in RAM**
- No key material written to disk
- Container automatically locked and wiped on close

---

## 6. Integrity Guarantees
Cryptographic authentication prevents:
- Tampering
- Bit flips
- Replay attacks
- Unauthorized modifications

A failed authentication = vault access instantly denied.

---

## 7. Password Protection
Passwords are:
- Never stored
- Never transmitted
- Not cached on disk

Forgotten password = **irreversible lockout**.

---

## 8. Threat Model Summary
Protected against:
- Offline brute-force attacks
- Malware reading stored vault data
- Disk theft & unauthorized access
- File format tampering

Not protected against (user responsibility):
- Compromised device / keyloggers
- Weak or reused passwords
- Users exposing decrypted data

Full threat analysis in [THREAT_MODEL](THREAT_MODEL.md)

---

## 9. Cryptographic Libraries
All operations leverage well-maintained, industry-trusted libraries:
- **cryptography** (AES-GCM)
- **libsodium / PyNaCl** (XChaCha20)
- **Argon2** reference implementation

Version details included in [REQUIREMENTS](requirements.txt)

---

## 10. Road to Future Enhancements
Planned improvements:
- Hardware-isolated key storage (TPM / Secure Enclave)
- Optional Shamir Secret Sharing for recovery
- Multi-party vault unlock options

---
