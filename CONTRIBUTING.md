# Contributing to SecureVault

Thank you for your interest in contributing to **SecureVault – Encrypted Data Vault**,  
a project developed and maintained by **BYLICKILABS – Intelligence Systems & Communications**.

This document explains how to report issues, propose features, and submit code contributions.

---

## 1. Code of Conduct
All contributors are expected to adhere to our community standards:

- Be respectful and professional in all communications  
- Focus on constructive collaboration  
- No personal attacks, discrimination, or harassment  

Violations may result in removal from the project community.

---

## 2. Getting Started

### 2.1 Fork and Clone
```bash
# Fork the repository on GitHub
git clone https://github.com/bylickilabs/SecureVault.git
cd SecureVault
```

### 2.2 Setup Local Environment
```bash
python -m venv venv
source venv/bin/activate        

# On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2.3 Code Style
All code must comply with the following:
- **PEP 8** style guide  
- Explicit **type hints** (`typing` module)  
- English comments and docstrings  
- Security-aware error handling  
- No plaintext logging of sensitive data

Run static checks before committing:
```bash
flake8 securevault/
black --check securevault/
```

---

## 3. Branching & Workflow

| Step | Description |
|------|--------------|
| `main` | Stable, release-ready branch |
| `develop` | Active development branch |
| `feature/*` | Feature branches (new functionality) |
| `fix/*` | Bugfix branches |
| `security/*` | Security-specific improvements |

Submit all changes through **Pull Requests (PRs)** targeting the `develop` branch.

Each PR must:
- Contain a clear description of the change  
- Reference related issues  
- Pass CI checks (tests, linting, build)  

---

## 4. Commit Guidelines
Use **clear and conventional** commit messages:

```
feat: add AES-GCM encryption fallback
fix: resolve UI freeze during container load
docs: update installation instructions
refactor: improve Argon2id key derivation flow
```

Avoid vague messages such as “update code” or “fix bug”.

---

## 5. Testing
Before submitting a PR, ensure:
- All **unit tests pass**  
- No regressions in encryption or file handling  
- UI interactions are validated if applicable

Run:
```bash
pytest -v
```

Add new tests for each major feature or fix.

---

## 6. Security Reports
If you discover a vulnerability, **do not** open a public GitHub issue.

Instead, contact the security team directly:
```
bylicki@mail.de
```

Refer to the official [SECURITY](SECURITY.md)

---

## 7. Documentation
All public functions and classes must include concise docstrings explaining:
- Purpose and parameters  
- Expected behavior  
- Possible exceptions  

If your change adds new features, update:
- [DEVELOPMENT](DEVELOPMENT.md)

---

## 8. Licensing
By submitting code, you agree that:
- Your contribution will be licensed under the project’s open-source license  
- You hold the rights to the code you submit  
- You grant BYLICKILABS the right to maintain and distribute it

---

## 9. Recognition
Contributors who make meaningful improvements will be acknowledged in:
- The official documentation  
- Release notes  
- Project credits section

---

> SecureVault welcomes professional, security-focused contributions.  
> Together we build trusted, verifiable, and resilient software.
