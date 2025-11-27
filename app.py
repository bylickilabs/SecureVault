import sys
import os
import webbrowser
import json
import zlib
import base64
import struct
from enum import Enum, auto
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QPushButton,
    QLabel,
    QLineEdit,
    QFileDialog,
    QVBoxLayout,
    QHBoxLayout,
    QComboBox,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QFrame,
)
from PySide6.QtCore import Qt

from argon2.low_level import hash_secret_raw, Type as ArgonType
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)


APP_NAME = "SecureVault"
APP_COMPANY = "©Thorsten Bylicki | ©BYLICKILABS – Intelligence Systems"
APP_VERSION = "1.0.0"
APP_TITLE = f"{APP_NAME} v{APP_VERSION}"


GITHUB_URL = "https://github.com/bylickilabs"


class CipherMode(Enum):
    AES_GCM = auto()
    XCHACHA20_POLY1305 = auto()


@dataclass
class AppState:
    current_lang: str = "de"
    selected_vault_path: str | None = None
    cipher_mode: CipherMode = CipherMode.AES_GCM
    vault_open: bool = False
    vault_data: dict | None = None  


TRANSLATIONS = {
    "de": {
        "app_title": "Verschlüsselter Datentresor",
        "lbl_vault_path": "Tresor-Datei:",
        "btn_browse": "Auswählen…",
        "lbl_password": "Passwort:",
        "btn_create_vault": "Neuen Tresor anlegen",
        "btn_open_vault": "Tresor öffnen",
        "btn_lock_vault": "Tresor sperren",
        "lbl_cipher": "Verschlüsselungsmethode:",
        "cipher_aes": "AES-256-GCM (Standard)",
        "cipher_xchacha": "XChaCha20-Poly1305 (Modern)",
        "lbl_language": "Sprache:",
        "lang_de": "Deutsch",
        "lang_en": "English",
        "btn_github": "GitHub",
        "btn_info": "Info",
        "lbl_files": "Dateien im Tresor:",
        "btn_add_file": "Datei hinzufügen",
        "btn_export_file": "Datei exportieren",
        "btn_remove_file": "Datei löschen",
        "msg_no_path": "Bitte wähle zuerst eine Tresor-Datei aus.",
        "msg_no_password": "Bitte gib ein sicheres Passwort ein.",
        "msg_vault_created": "Tresor wurde erfolgreich erstellt und verschlüsselt.",
        "msg_vault_opened": "Tresor wurde erfolgreich geöffnet.",
        "msg_vault_locked": "Tresor wurde gesperrt und aus dem Speicher entfernt.",
        "msg_error": "Fehler",
        "msg_info_title": "Über SecureVault",
        "info_text": (
            f"<b>{APP_TITLE}</b><br>"
            f"<i>{APP_COMPANY}</i><br><br>"
            "<b>SecureVault – Verschlüsselter Datentresor</b><br><br>"
            "SecureVault speichert vertrauliche Dateien in einer verschlüsselten Container-Datei. "
            "Alle Daten liegen im Ruhezustand verschlüsselt vor und werden nur im Arbeitsspeicher "
            "für den Zeitraum der geöffneten Sitzung entschlüsselt.<br><br>"
            "<b>Technische Eckdaten:</b><br>"
            "- Passwortbasierte Schlüsselableitung mit Argon2id<br>"
            "- Verschlüsselung: AES-256-GCM <i>oder</i> XChaCha20-Poly1305<br>"
            "- Container-Format mit Magic-Header, Salt und KDF-Parametern<br>"
            "- Keine Cloud, keine Telemetrie, 100% lokale Verarbeitung<br><br>"
            "Der Tresor bildet ein virtuelles Laufwerk innerhalb der Anwendung ab. "
            "Dateien werden beim Hinzufügen verschlüsselt im Container abgelegt und können "
            "bei geöffnetem Tresor wieder entschlüsselt exportiert werden."
        ),
        "file_dialog_title": "Tresor-Datei auswählen oder anlegen",
        "file_filter": "SecureVault Container (*.svc);;Alle Dateien (*.*)",
        "msg_open_first": "Bitte öffne zuerst einen Tresor.",
        "msg_select_file_first": "Bitte wähle eine Datei im Tresor aus.",
        "msg_add_success": "Datei wurde dem Tresor hinzugefügt und verschlüsselt.",
        "msg_export_success": "Datei wurde entschlüsselt und exportiert.",
        "msg_remove_confirm": "Möchtest du die gewählte Datei wirklich aus dem Tresor löschen?",
        "msg_remove_success": "Datei wurde aus dem Tresor entfernt.",
        "msg_wrong_password": "Der Tresor konnte mit diesem Passwort nicht entschlüsselt werden.",
        "msg_vault_corrupt": "Die Tresor-Datei ist beschädigt oder kein gültiger SecureVault-Container.",
    },
    "en": {
        "app_title": "Encrypted Data Vault",
        "lbl_vault_path": "Vault file:",
        "btn_browse": "Browse…",
        "lbl_password": "Password:",
        "btn_create_vault": "Create new vault",
        "btn_open_vault": "Open vault",
        "btn_lock_vault": "Lock vault",
        "lbl_cipher": "Encryption mode:",
        "cipher_aes": "AES-256-GCM (Standard)",
        "cipher_xchacha": "XChaCha20-Poly1305 (Modern)",
        "lbl_language": "Language:",
        "lang_de": "German",
        "lang_en": "English",
        "btn_github": "GitHub",
        "btn_info": "Info",
        "lbl_files": "Files in vault:",
        "btn_add_file": "Add file",
        "btn_export_file": "Export file",
        "btn_remove_file": "Delete file",
        "msg_no_path": "Please select a vault file first.",
        "msg_no_password": "Please enter a secure password.",
        "msg_vault_created": "Vault has been created and encrypted successfully.",
        "msg_vault_opened": "Vault opened successfully.",
        "msg_vault_locked": "Vault locked and cleared from memory.",
        "msg_error": "Error",
        "msg_info_title": "About SecureVault",
        "info_text": (
            f"<b>{APP_TITLE}</b><br>"
            f"<i>{APP_COMPANY}</i><br><br>"
            "<b>SecureVault – Encrypted Data Vault</b><br><br>"
            "SecureVault stores confidential files inside a single encrypted container file. "
            "All data at rest is encrypted and only decrypted in memory while the vault is open.<br><br>"
            "<b>Technical highlights:</b><br>"
            "- Password-based key derivation using Argon2id<br>"
            "- Encryption: AES-256-GCM <i>or</i> XChaCha20-Poly1305<br>"
            "- Container format with magic header, salt and KDF parameters<br>"
            "- No cloud, no telemetry, 100% local processing<br><br>"
            "The vault represents a virtual drive inside the application. "
            "Files are encrypted into the container when added and can be decrypted "
            "and exported while the vault is open."
        ),
        "file_dialog_title": "Select or create a vault file",
        "file_filter": "SecureVault container (*.svc);;All files (*.*)",
        "msg_open_first": "Please open a vault first.",
        "msg_select_file_first": "Please select a file in the vault.",
        "msg_add_success": "File has been added to the vault and encrypted.",
        "msg_export_success": "File has been decrypted and exported.",
        "msg_remove_confirm": "Do you really want to remove the selected file from the vault?",
        "msg_remove_success": "File has been removed from the vault.",
        "msg_wrong_password": "Vault could not be decrypted with this password.",
        "msg_vault_corrupt": "Vault file is corrupted or not a valid SecureVault container.",
    },
}


MAGIC = b"SVLT1"


def derive_key(password: str, salt: bytes, t=3, m=64 * 1024, p=4, length=32) -> bytes:
    """
    Leitet mit Argon2id aus Passwort + Salt einen symmetrischen Schlüssel ab.
    t  = time_cost, m = memory_cost (KiB), p = parallelism
    """
    return hash_secret_raw(
        password.encode("utf-8"),
        salt,
        t,
        m,
        p,
        length,
        ArgonType.ID,
    )


def encrypt_vault_obj(vault_obj: dict, password: str, mode: CipherMode) -> bytes:
    """
    Serialisiert und verschlüsselt das Vault-Objekt in eine Container-Struktur.

    Format:
    - 5  Bytes: MAGIC
    - 1  Byte : Version
    - 1  Byte : Cipher-ID (1 = AES-GCM, 2 = XChaCha20-Poly1305)
    - 16 Bytes: Salt
    - 4  Bytes: Argon2 time_cost (big endian)
    - 4  Bytes: Argon2 memory_cost (KiB)
    - 4  Bytes: Argon2 parallelism
    - 1  Byte : Nonce-Länge (12 oder 24)
    - N  Bytes: Nonce
    - Rest   : Ciphertext
    """
    version = 1
    cipher_id = 1 if mode == CipherMode.AES_GCM else 2
    salt = os.urandom(16)
    t, m, p = 3, 64 * 1024, 4

    key = derive_key(password, salt, t, m, p)

    payload_json = json.dumps(vault_obj).encode("utf-8")
    payload = zlib.compress(payload_json)

    if mode == CipherMode.AES_GCM:
        nonce = os.urandom(12)
        aead = AESGCM(key)
        ct = aead.encrypt(nonce, payload, None)
    else:
        nonce = os.urandom(24)
        ct = crypto_aead_xchacha20poly1305_ietf_encrypt(payload, None, None, nonce, key)

    header = (
        MAGIC
        + bytes([version, cipher_id])
        + salt
        + struct.pack(">III", t, m, p)
        + bytes([len(nonce)])
        + nonce
    )
    return header + ct


def decrypt_vault_obj(data: bytes, password: str) -> dict:
    """
    Entschlüsselt ein Vault-Objekt aus der Container-Struktur.
    Wirft ValueError bei fehlerhaftem Passwort oder beschädigtem Format.
    """
    min_len = 5 + 1 + 1 + 16 + 4 + 4 + 4 + 1
    if len(data) < min_len:
        raise ValueError("Container too small")

    magic = data[:5]
    if magic != MAGIC:
        raise ValueError("Invalid magic header")

    version = data[5]
    cipher_id = data[6]
    salt = data[7:23]
    t, m, p = struct.unpack(">III", data[23:35])
    nonce_len = data[35]

    nonce_start = 36
    nonce_end = nonce_start + nonce_len
    if nonce_end > len(data):
        raise ValueError("Invalid nonce length")

    nonce = data[nonce_start:nonce_end]
    ct = data[nonce_end:]

    key = derive_key(password, salt, t, m, p)

    try:
        if cipher_id == 1:
            aead = AESGCM(key)
            payload = aead.decrypt(nonce, ct, None)
        elif cipher_id == 2:
            payload = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key)
        else:
            raise ValueError("Unsupported cipher ID")
    except Exception as exc:
        raise ValueError("Decryption failed") from exc

    try:
        payload_json = zlib.decompress(payload)
        vault_obj = json.loads(payload_json)
    except Exception as exc:
        raise ValueError("Invalid payload format") from exc

    if not isinstance(vault_obj, dict) or "files" not in vault_obj:
        raise ValueError("Invalid vault structure")

    return vault_obj


class SecureVaultWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.state = AppState()
        self._init_ui()
        self._apply_translations()
        self._update_vault_state_ui()


    def _init_ui(self):
        self.setMinimumSize(780, 480)
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(10)


        self.lbl_vault_path = QLabel()
        self.edit_vault_path = QLineEdit()
        self.edit_vault_path.setReadOnly(True)
        self.btn_browse = QPushButton()
        self.btn_browse.clicked.connect(self.on_browse_clicked)

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.lbl_vault_path)
        path_layout.addWidget(self.edit_vault_path, 1)
        path_layout.addWidget(self.btn_browse)


        self.lbl_password = QLabel()
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.Password)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.lbl_password)
        password_layout.addWidget(self.edit_password)


        self.lbl_cipher = QLabel()
        self.cmb_cipher = QComboBox()
        self.cmb_cipher.addItem("AES-256-GCM", CipherMode.AES_GCM)
        self.cmb_cipher.addItem("XChaCha20-Poly1305", CipherMode.XCHACHA20_POLY1305)
        self.cmb_cipher.currentIndexChanged.connect(self.on_cipher_changed)

        cipher_layout = QHBoxLayout()
        cipher_layout.addWidget(self.lbl_cipher)
        cipher_layout.addWidget(self.cmb_cipher)
        cipher_layout.addStretch()


        self.btn_create_vault = QPushButton()
        self.btn_open_vault = QPushButton()
        self.btn_lock_vault = QPushButton()

        self.btn_create_vault.clicked.connect(self.on_create_vault)
        self.btn_open_vault.clicked.connect(self.on_open_vault)
        self.btn_lock_vault.clicked.connect(self.on_lock_vault)

        vault_button_layout = QHBoxLayout()
        vault_button_layout.addWidget(self.btn_create_vault)
        vault_button_layout.addWidget(self.btn_open_vault)
        vault_button_layout.addWidget(self.btn_lock_vault)


        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)


        self.lbl_files = QLabel()
        self.list_files = QListWidget()

        self.btn_add_file = QPushButton()
        self.btn_export_file = QPushButton()
        self.btn_remove_file = QPushButton()

        self.btn_add_file.clicked.connect(self.on_add_file)
        self.btn_export_file.clicked.connect(self.on_export_file)
        self.btn_remove_file.clicked.connect(self.on_remove_file)

        file_button_layout = QHBoxLayout()
        file_button_layout.addWidget(self.btn_add_file)
        file_button_layout.addWidget(self.btn_export_file)
        file_button_layout.addWidget(self.btn_remove_file)


        self.lbl_language = QLabel()
        self.cmb_language = QComboBox()
        self.cmb_language.addItem("Deutsch", "de")
        self.cmb_language.addItem("English", "en")
        self.cmb_language.currentIndexChanged.connect(self.on_language_changed)

        self.btn_github = QPushButton()
        self.btn_info = QPushButton()

        self.btn_github.clicked.connect(self.on_github_clicked)
        self.btn_info.clicked.connect(self.on_info_clicked)

        footer_layout = QHBoxLayout()
        footer_layout.addWidget(self.lbl_language)
        footer_layout.addWidget(self.cmb_language)
        footer_layout.addStretch()
        footer_layout.addWidget(self.btn_github)
        footer_layout.addWidget(self.btn_info)


        main_layout.addLayout(path_layout)
        main_layout.addLayout(password_layout)
        main_layout.addLayout(cipher_layout)
        main_layout.addLayout(vault_button_layout)
        main_layout.addWidget(separator)
        main_layout.addWidget(self.lbl_files)
        main_layout.addWidget(self.list_files, 1)
        main_layout.addLayout(file_button_layout)
        main_layout.addLayout(footer_layout)

        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #050816;
            }
            QLabel {
                color: #e5e7eb;
                font-size: 14px;
            }
            QLineEdit, QListWidget {
                background-color: #0f172a;
                color: #e5e7eb;
                border: 1px solid #1f2937;
                border-radius: 6px;
                padding: 4px 8px;
            }
            QPushButton {
                background-color: #111827;
                color: #e5e7eb;
                border: 1px solid #374151;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: #1f2937;
            }
            QPushButton#primary {
                background-color: #ff69b4;
                border-color: #ff69b4;
                color: #020617;
                font-weight: 600;
            }
            QPushButton#primary:hover {
                background-color: #f472b6;
            }
            QComboBox {
                background-color: #0f172a;
                color: #e5e7eb;
                border: 1px solid #1f2937;
                border-radius: 6px;
                padding: 4px 8px;
            }
        """)
        self.btn_create_vault.setObjectName("primary")
        self.btn_open_vault.setObjectName("primary")


    def _apply_translations(self):
        t = TRANSLATIONS[self.state.current_lang]
        self.setWindowTitle(f"{APP_TITLE} – {t['app_title']}")
        self.lbl_vault_path.setText(t["lbl_vault_path"])
        self.btn_browse.setText(t["btn_browse"])
        self.lbl_password.setText(t["lbl_password"])
        self.lbl_cipher.setText(t["lbl_cipher"])
        self.btn_create_vault.setText(t["btn_create_vault"])
        self.btn_open_vault.setText(t["btn_open_vault"])
        self.btn_lock_vault.setText(t["btn_lock_vault"])
        self.lbl_language.setText(t["lbl_language"])
        self.btn_github.setText(t["btn_github"])
        self.btn_info.setText(t["btn_info"])
        self.lbl_files.setText(t["lbl_files"])
        self.btn_add_file.setText(t["btn_add_file"])
        self.btn_export_file.setText(t["btn_export_file"])
        self.btn_remove_file.setText(t["btn_remove_file"])


        self.cmb_language.blockSignals(True)
        self.cmb_language.setItemText(0, t["lang_de"])
        self.cmb_language.setItemText(1, t["lang_en"])
        if self.state.current_lang == "de":
            self.cmb_language.setCurrentIndex(0)
        else:
            self.cmb_language.setCurrentIndex(1)
        self.cmb_language.blockSignals(False)


    def _update_vault_state_ui(self):
        vault_open = self.state.vault_open
        self.list_files.setEnabled(vault_open)
        self.btn_add_file.setEnabled(vault_open)
        self.btn_export_file.setEnabled(vault_open)
        self.btn_remove_file.setEnabled(vault_open)

    def _refresh_file_list(self):
        self.list_files.clear()
        if not self.state.vault_data:
            return
        files = self.state.vault_data.get("files", {})
        for name in sorted(files.keys()):
            item = QListWidgetItem(name)
            self.list_files.addItem(item)


    def on_language_changed(self, index: int):
        code = self.cmb_language.itemData(index)
        if code not in ("de", "en"):
            return
        self.state.current_lang = code
        self._apply_translations()

    def on_cipher_changed(self, index: int):
        mode = self.cmb_cipher.itemData(index)
        if isinstance(mode, CipherMode):
            self.state.cipher_mode = mode

    def on_browse_clicked(self):
        t = TRANSLATIONS[self.state.current_lang]
        path, _ = QFileDialog.getSaveFileName(
            self,
            t["file_dialog_title"],
            os.path.expanduser("~"),
            t["file_filter"],
        )
        if path:
            self.state.selected_vault_path = path
            self.edit_vault_path.setText(path)

    def _validate_vault_path_and_password(self) -> bool:
        t = TRANSLATIONS[self.state.current_lang]
        if not self.state.selected_vault_path:
            QMessageBox.warning(self, t["msg_error"], t["msg_no_path"])
            return False
        if not self.edit_password.text():
            QMessageBox.warning(self, t["msg_error"], t["msg_no_password"])
            return False
        return True


    def on_create_vault(self):
        if not self._validate_vault_path_and_password():
            return
        t = TRANSLATIONS[self.state.current_lang]
        password = self.edit_password.text()
        path = self.state.selected_vault_path
        mode = self.state.cipher_mode

        vault_obj = {"files": {}}

        try:
            data = encrypt_vault_obj(vault_obj, password, mode)
            with open(path, "wb") as f:
                f.write(data)
            self.state.vault_data = vault_obj
            self.state.vault_open = True
            self._refresh_file_list()
            self._update_vault_state_ui()
            QMessageBox.information(self, APP_NAME, t["msg_vault_created"])
        except Exception as ex:
            QMessageBox.critical(self, t["msg_error"], f"{t['msg_error']}: {ex}")

    def on_open_vault(self):
        if not self._validate_vault_path_and_password():
            return
        t = TRANSLATIONS[self.state.current_lang]
        password = self.edit_password.text()
        path = self.state.selected_vault_path

        if not os.path.exists(path):
            QMessageBox.critical(self, t["msg_error"], t["msg_vault_corrupt"])
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
            vault_obj = decrypt_vault_obj(data, password)

            cipher_id = data[6]
            if cipher_id == 1:
                self.state.cipher_mode = CipherMode.AES_GCM
                self.cmb_cipher.setCurrentIndex(0)
            elif cipher_id == 2:
                self.state.cipher_mode = CipherMode.XCHACHA20_POLY1305
                self.cmb_cipher.setCurrentIndex(1)

            self.state.vault_data = vault_obj
            self.state.vault_open = True
            self._refresh_file_list()
            self._update_vault_state_ui()
            QMessageBox.information(self, APP_NAME, t["msg_vault_opened"])
        except ValueError as ex:
            msg = str(ex)
            if "Decryption failed" in msg:
                QMessageBox.warning(self, t["msg_error"], t["msg_wrong_password"])
            else:
                QMessageBox.critical(self, t["msg_error"], t["msg_vault_corrupt"])
        except Exception as ex:
            QMessageBox.critical(self, t["msg_error"], f"{t['msg_error']}: {ex}")

    def on_lock_vault(self):
        t = TRANSLATIONS[self.state.current_lang]
        self.state.vault_data = None
        self.state.vault_open = False
        self._refresh_file_list()
        self._update_vault_state_ui()
        QMessageBox.information(self, APP_NAME, t["msg_vault_locked"])

    def _save_vault(self):
        """
        Speichert den aktuellen Vault-Zustand wieder in die Container-Datei.
        """
        if not (self.state.vault_data and self.state.selected_vault_path):
            return
        password = self.edit_password.text()
        path = self.state.selected_vault_path
        mode = self.state.cipher_mode
        data = encrypt_vault_obj(self.state.vault_data, password, mode)
        with open(path, "wb") as f:
            f.write(data)


    def on_add_file(self):
        t = TRANSLATIONS[self.state.current_lang]
        if not self.state.vault_open or not self.state.vault_data:
            QMessageBox.warning(self, t["msg_error"], t["msg_open_first"])
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, t["btn_add_file"], os.path.expanduser("~")
        )
        if not file_path:
            return

        file_name = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            b64 = base64.b64encode(content).decode("ascii")
            self.state.vault_data.setdefault("files", {})[file_name] = b64
            self._save_vault()
            self._refresh_file_list()
            QMessageBox.information(self, APP_NAME, t["msg_add_success"])
        except Exception as ex:
            QMessageBox.critical(self, t["msg_error"], f"{t['msg_error']}: {ex}")

    def on_export_file(self):
        t = TRANSLATIONS[self.state.current_lang]
        if not self.state.vault_open or not self.state.vault_data:
            QMessageBox.warning(self, t["msg_error"], t["msg_open_first"])
            return

        current_item = self.list_files.currentItem()
        if not current_item:
            QMessageBox.warning(self, t["msg_error"], t["msg_select_file_first"])
            return

        file_name = current_item.text()
        files = self.state.vault_data.get("files", {})
        if file_name not in files:
            QMessageBox.warning(self, t["msg_error"], t["msg_select_file_first"])
            return

        export_path, _ = QFileDialog.getSaveFileName(
            self,
            t["btn_export_file"],
            os.path.join(os.path.expanduser("~"), file_name),
            "All files (*.*)",
        )
        if not export_path:
            return

        try:
            content = base64.b64decode(files[file_name])
            with open(export_path, "wb") as f:
                f.write(content)
            QMessageBox.information(self, APP_NAME, t["msg_export_success"])
        except Exception as ex:
            QMessageBox.critical(self, t["msg_error"], f"{t['msg_error']}: {ex}")

    def on_remove_file(self):
        t = TRANSLATIONS[self.state.current_lang]
        if not self.state.vault_open or not self.state.vault_data:
            QMessageBox.warning(self, t["msg_error"], t["msg_open_first"])
            return

        current_item = self.list_files.currentItem()
        if not current_item:
            QMessageBox.warning(self, t["msg_error"], t["msg_select_file_first"])
            return

        file_name = current_item.text()
        reply = QMessageBox.question(
            self,
            APP_NAME,
            t["msg_remove_confirm"],
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            files = self.state.vault_data.get("files", {})
            if file_name in files:
                del files[file_name]
                self._save_vault()
                self._refresh_file_list()
                QMessageBox.information(self, APP_NAME, t["msg_remove_success"])
        except Exception as ex:
            QMessageBox.critical(self, t["msg_error"], f"{t['msg_error']}: {ex}")


    def on_github_clicked(self):
        webbrowser.open(GITHUB_URL)

    def on_info_clicked(self):
        t = TRANSLATIONS[self.state.current_lang]
        msg = QMessageBox(self)
        msg.setWindowTitle(t["msg_info_title"])
        msg.setTextFormat(Qt.RichText)
        msg.setText(t["info_text"])
        msg.setIcon(QMessageBox.Information)
        msg.exec()


def main():
    app = QApplication(sys.argv)
    window = SecureVaultWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
