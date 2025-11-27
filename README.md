### 🔐 SecureVault  - Encrypted Data Vault (DE/EN)

```yarn
Intelligence Systems & Communications  
```

|<img width="1280" height="640" alt="VirtualDrive" src="https://github.com/user-attachments/assets/2d6a7bde-7fbd-4fbe-b36c-cbaed42a6b7b" />  |
|---|

> SecureVault bietet vollständige zweisprachige Unterstützung – verfügbar auf Deutsch und Englisch für ein nahtloses Nutzererlebnis. 
 - Die bevorzugte Sprache lässt sich jederzeit direkt in der Anwendung einstellen.“
 - Encrypted Data Vault
 - Version 1.0.0
 
---

### 🧭 Übersicht

**SecureVault** ist eine hochsichere Anwendung zur lokalen Speicherung vertraulicher Daten in verschlüsselter Form.  
Alle Dateien werden in einer **einzigen Containerdatei (.svc)** abgelegt, die vollständig mit modernsten kryptografischen Verfahren gesichert ist.  
Während einer Sitzung werden Inhalte ausschließlich im Arbeitsspeicher entschlüsselt – niemals auf der Festplatte im Klartext abgelegt.

SecureVault wurde entwickelt, um **professionelle Datensicherheit, kompromisslose Offline-Verschlüsselung und Zero-Trust-Prinzipien** in einer benutzerfreundlichen Oberfläche zu vereinen.

---

### ⚙️ Hauptfunktionen

| Kategorie | Beschreibung |
|------------|--------------|
| **Verschlüsselung** | AES-256-GCM oder XChaCha20-Poly1305 |
| **Schlüsselableitung (KDF)** | Argon2id (Memory-Hard gegen GPU-Bruteforce) |
| **Datenspeicherung** | Komprimierter JSON-Container mit Base64-Dateidaten |
| **Offline-Modus** | Keine Cloud, keine Telemetrie, 100 % lokale Verarbeitung |
| **Mehrsprachigkeit** | Benutzeroberfläche in Deutsch und Englisch |
| **GUI** | PySide6-basiert, modernes Dark-UI |
| **Integritätsschutz** | Authenticated Encryption – schützt vor Manipulation |
| **Benutzeraktionen** | Tresor erstellen, öffnen, sperren, Datei hinzufügen/exportieren/löschen |

---

### 🔐 Sicherheitsarchitektur

| Komponente | Technische Details |
|-------------|--------------------|
| **KDF (Argon2id)** | 3 Iterationen • 64 MiB RAM • Parallelität 4 |
| **Verschlüsselung** | AES-256-GCM oder XChaCha20-Poly1305 |
| **Integrität** | AEAD-Modus schützt automatisch vor Datenverfälschung |
| **Datenstruktur** | Zlib-komprimiertes JSON-Objekt |
| **Salt** | 16 Byte, zufällig generiert pro Tresor |
| **Nonce** | 12 Byte (AES) / 24 Byte (XChaCha) |
| **Lokale Sicherheit** | Keine unverschlüsselten Temporärdateien, keine Caches |

> **Hinweis:** Wenn das Passwort verloren geht, sind die Daten unwiederbringlich verloren.  
> Dies ist ein gewolltes Sicherheitsmerkmal, kein Fehler.

---

### 🧩 Datenfluss beim Speichern

```
Datei → Base64-Encoding → JSON-Struktur → zlib-Kompression → 
Argon2id-Key-Derivation → AEAD-Verschlüsselung → .svc-Container
```

Beim Öffnen läuft der Prozess in umgekehrter Richtung.  
Die Entschlüsselung erfolgt ausschließlich im RAM.

---

### 🧠 Bedrohungsmodell

| Angriffsszenario | Schutzmechanismus |
|------------------|-------------------|
| Wörterbuch- & GPU-Bruteforce | Memory-Hard Argon2id-KDF |
| Manipulierte Containerdatei | AEAD-Authentifizierung |
| Disk-Forensics / Wiederherstellung | Keine Klartext-Writes |
| Malware / Keylogger | Nur Passwortabgriff möglich, kein Klartextzugriff |
| Netzwerkangriffe | Kein Netzwerkzugriff, keine Telemetrie |

---

### 🧰 Systemanforderungen

| Komponente | Minimum |
|-------------|----------|
| Betriebssystem | Windows 10/11, Linux, macOS |
| Python | 3.10 oder höher |
| RAM | 8 GB empfohlen (für Argon2) |
| Bibliotheken | PySide6, cryptography, pynacl, argon2-cffi |

---

### 🛠️ Installation

```bash
git clone https://github.com/bylickilabs/SecureVault.git
cd SecureVault
pip install -r requirements.txt
python SecureVault.py
```

---

### 📘 Verwendung

1. Tresor-Datei auswählen oder erstellen (`*.svc`)  
2. Passwort festlegen  
3. Verschlüsselungsmodus wählen (AES-GCM oder XChaCha20)  
4. Tresor öffnen oder anlegen  
5. Dateien hinzufügen, exportieren oder löschen  
6. Tresor sperren – RAM wird geleert

---

### 💡 Best Practices

- Verwende starke Passwörter (≥ 12 Zeichen)  
- Keine Wiederverwendung von Passwörtern  
- Keine Speicherung im Klartext  
- Backup der `.svc`-Datei auf externem Medium  
- XChaCha20 bevorzugen für Zukunftssicherheit

---

### 🧱 Roadmap

| Feature | Status |
|----------|:------:|
| CLI-Unterstützung | 🟡 geplant |
| Passwortrotation | 🟡 geplant |
| Secure Delete (DoD 5220.22-M) | 🟢 Entwicklung |
| Virtuelles Laufwerk | 🔜 |
| Hardware-Token (YubiKey) | 🔜 |
| Audit Report | 🔜 |

---

### 📄 Lizenz

© 2025 BYLICKILABS – Intelligence Systems & Communications  
Lizenz: [LICENSE](LICENSE)

<br>

---

<br>

### 🧭 Overview

> SecureVault provides full bilingual support — available in German and English for a seamless user experience.
– The preferred language can be changed at any time directly within the application.
– Encrypted Data Vault
– Version 1.0.0

---

### ⚙️ Key Features

| Category | Description |
|-----------|-------------|
| **Encryption** | AES-256-GCM or XChaCha20-Poly1305 |
| **Key Derivation** | Argon2id – GPU-resistant KDF |
| **Data Structure** | Compressed JSON with Base64-encoded file data |
| **User Interface** | PySide6 GUI, dual-language (DE/EN) |
| **Offline Mode** | 100 % local, no telemetry |
| **Integrity** | AEAD for tamper-proof encryption |
| **Vault Operations** | Create, open, lock, add, export, remove files |

---

### 🔐 Security Architecture

| Component | Details |
|------------|----------|
| Key Derivation | Argon2id – 3 passes, 64 MiB RAM, 4 threads |
| Encryption | AES-256-GCM or XChaCha20-Poly1305 |
| Integrity | AEAD (Authenticated Encryption) |
| Compression | zlib |
| Salt | 16-byte random per vault |
| Nonce | 12 or 24 bytes |
| Offline Policy | No cleartext cache, no telemetry |

---

### 🧩 Data Flow

```
File → Base64 → JSON → zlib → Argon2id → AEAD → .svc
```

Reverse order for decryption.

---

### 🧠 Threat Model

| Threat | Mitigation |
|---------|-------------|
| Password cracking | Argon2id KDF |
| File tampering | AEAD integrity check |
| Disk analysis | No plaintext writes |
| Network attacks | Offline architecture |
| Memory compromise | Vault lock purges RAM instantly |

---

### 🛠️ Installation

```bash
git clone https://github.com/bylickilabs/SecureVault.git
cd SecureVault
pip install -r requirements.txt
python SecureVault.py
```

---

### 🧱 Roadmap

| Feature | Status |
|----------|:------:|
| CLI mode | Planned |
| Password rotation | Planned |
| Secure Delete | Development |
| Virtual Mount | Planned |
| Hardware keys | Planned |

---

### 📄 License

© 2025 BYLICKILABS – Intelligence Systems & Communications  
License: [LICENSE](LICENSE)
