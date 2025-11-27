# Threat Model – SecureVault

Effective Date: 2025-01-01  
Product: SecureVault – Encrypted Data Vault  
Owner: BYLICKILABS – Intelligence Systems & Communications  

---

## 1. Objective
This threat model evaluates security risks associated with the protection of locally stored, encrypted user data. The analysis follows a Zero-Trust principle where **no external system is trusted**.

Primary security objective:
> Prevent unauthorized access to protected data — even if the system is compromised at rest.

---

## 2. Assets to Protect
| Asset | Description |
|-------|-------------|
| Encrypted container (*.svc) | All protected user files and metadata |
| Master encryption key | Derived from user password via Argon2id |
| User password | Sole factor for local data access |
| Decrypted data in memory | Plaintext only during active session |

All assets are considered **high-value**.

---

## 3. Threat Actors
| Threat Actor | Capabilities | Motivation |
|-------------|-------------|------------|
| Opportunistic attacker | Low skill; theft of device | Financial gain / curiosity |
| Advanced malware | Keylogging, memory scanning | Data extraction |
| Insider threat | Authorized physical access | Abuse of privileges |
| Forensic adversary | Offline cracking tools | Targeted exploitation |

Worst-case assumption: **Attackers gain full access to the stored vault file.**

---

## 4. Attack Surface
| Surface | Exposure | Mitigation |
|---------|----------|------------|
| Stolen encrypted container | Likely | Strong encryption (AES-GCM / XChaCha20) |
| Password brute-force | Likely | Argon2id with high memory cost |
| Container manipulation | Possible | AEAD authentication failure |
| Memory scraping | Risk during session | Minimal exposure time; no key persistence |
| Phishing / social engineering | Human factor | User awareness required |

---

## 5. Security Controls
| Control Category | Applied Measures |
|------------------|----------------|
| Cryptographic security | AES-256-GCM, XChaCha20-Poly1305, Argon2id |
| Data at rest protection | Full encryption, zero plaintext persistence |
| Data in memory | Temporary only; cleared on lock/exit |
| Network security | No telemetry; no cloud interaction |
| Principle of least knowledge | App does not know contents nor identity of the user |

No external services = **no remote attack vectors**.

---

## 6. Known Limitations and User Responsibilities
SecureVault **does not protect against**:
- Keyloggers or compromised operating systems
- Screen scraping or spyware capturing decrypted content
- Shoulder surfing or unsafe environments
- Weak or reused passwords chosen by users

> If the device is compromised while unlocked, plaintext can be stolen.

---

## 7. Risk Rating Summary

| Threat | Residual Risk | Status |
|--------|----------------|--------|
| Offline dictionary attacks | Low | Strong KDF parameters |
| Container corruption | Low | AEAD verification |
| OS-level compromise | Medium | Outside product scope |
| Weak user password | Medium–High | Requires user discipline |

SecureVault’s strongest defense is **offline-only security**.

---

## 8. Future Security Enhancements
Planned measures to reduce residual risks:
- Optional MFA to mitigate password weakness
- Hardware key isolation (TPM, Secure Enclave)
- Secure memory-hardening techniques
- Behavior-based warnings when environment seems unsafe
- 
---

## 9. Conclusion
SecureVault provides a robust security posture against:
- Device loss
- Unauthorized local access
- Offline brute-force adversaries

Residual vulnerabilities remain **only on compromised devices** — fully aligned with Zero-Trust assumptions.

> Local. Private. Encrypted. Always.

