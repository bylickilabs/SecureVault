# Security Policy – SecureVault

Effective Date: 2025-01-01  
Product: SecureVault – Encrypted Data Vault  
Owner: BYLICKILABS – Intelligence Systems & Communications  

---

## 1. Security Commitment
SecureVault is designed with a strict security-first architecture.  
We protect user data using strong encryption and zero-trust principles.

There are **no backdoors**, **no recovery keys**, and **no external access** to vault contents.

---

## 2. Supported Versions
Security patches are guaranteed for the latest major Stable Release:
- SecureVault v1.x (Active support)

Older versions may receive updates only for critical vulnerabilities.

The current version is documented in the repository root.

---

## 3. Reporting a Vulnerability
We strongly encourage responsible disclosure.

To report a security issue, please contact:

> **Email:** bylicki@mail.de

> **PGP:** Available upon request  

> **Contact Form:** GitHub Issues may be used for *non-sensitive* matters  

Please include:
- A clear description of the vulnerability
- Steps to reproduce (if applicable)
- Potential security impact

We will acknowledge receipt within **72 hours** and provide a remediation plan if required.

---

## 4. Disclosure Process
1. Vulnerability received and validated
2. Internal risk and impact assessment
3. Fix developed and tested privately
4. Coordinated release and security advisory (if required)
5. Public CVE assignment (critical issues only)

Researchers are recognized upon request.

---

## 5. Cryptography Policy
SecureVault uses:
- **AES-256-GCM** and/or **XChaCha20-Poly1305**
- **Argon2id** for password-based key derivation
- Encrypted storage exclusively (no plaintext)

Full technical details: `CRYPTOGRAPHY.md`

We never downgrade to legacy or weakened cryptography.

---

## 6. No Telemetry
SecureVault sends **no data** to external systems:
- No tracking
- No analytics
- No cloud services

Security is enforced **offline and locally**.

---

## 7. Code Transparency
Open-source components enable full verification:
- Code review welcome
- Reproducible builds encouraged

Community participation strengthens security.

---

## 8. Contact
For privacy or security-related inquiries:

**BYLICKILABS – Intelligence Systems & Communications**  
Email: bylicki@mail.de

> Website: 
  - https://bylickilabs.de
  - https://bylickilabs.com
