"""
PyQt6-based GUI for Cerberus Password Manager.
"""
from __future__ import annotations

import sys
from dataclasses import asdict
from typing import Optional, List

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QLabel,
    QLineEdit,
    QTextEdit,
    QMessageBox,
    QInputDialog,
    QFileDialog,
)

from ..core.password_manager import PasswordManager, VaultError
from ..core.models import PasswordEntry


class MainWindow(QMainWindow):
    def __init__(self, pm: PasswordManager):
        super().__init__()
        self.pm = pm
        self.setWindowTitle("Cerberus Password Manager")
        self.resize(900, 600)

        # Root container
        root = QWidget()
        layout = QHBoxLayout()
        root.setLayout(layout)
        self.setCentralWidget(root)

        # Left: list
        left = QWidget()
        left_layout = QVBoxLayout()
        left.setLayout(left_layout)
        layout.addWidget(left, 1)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search website, username, tags...")
        self.search_input.textChanged.connect(self.refresh_list)
        left_layout.addWidget(self.search_input)

        self.list_widget = QListWidget()
        self.list_widget.itemSelectionChanged.connect(self.on_selection_changed)
        left_layout.addWidget(self.list_widget, 1)

        btn_bar = QHBoxLayout()
        self.btn_add = QPushButton("Add")
        self.btn_edit = QPushButton("Edit")
        self.btn_rotate = QPushButton("Rotate")
        self.btn_delete = QPushButton("Delete")
        self.btn_export = QPushButton("Export")
        self.btn_import = QPushButton("Import")
        btn_bar.addWidget(self.btn_add)
        btn_bar.addWidget(self.btn_edit)
        btn_bar.addWidget(self.btn_rotate)
        btn_bar.addWidget(self.btn_delete)
        btn_bar.addWidget(self.btn_export)
        btn_bar.addWidget(self.btn_import)
        left_layout.addLayout(btn_bar)

        # Right: detail
        right = QWidget()
        right_layout = QVBoxLayout()
        right.setLayout(right_layout)
        layout.addWidget(right, 2)

        self.lbl_website = QLineEdit()
        self.lbl_username = QLineEdit()
        self.lbl_password = QLineEdit()
        self.lbl_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.lbl_url = QLineEdit()
        self.txt_notes = QTextEdit()

        right_layout.addWidget(QLabel("Website"))
        right_layout.addWidget(self.lbl_website)
        right_layout.addWidget(QLabel("Username"))
        right_layout.addWidget(self.lbl_username)
        right_layout.addWidget(QLabel("Password"))
        right_layout.addWidget(self.lbl_password)
        right_layout.addWidget(QLabel("URL"))
        right_layout.addWidget(self.lbl_url)
        right_layout.addWidget(QLabel("Notes"))
        right_layout.addWidget(self.txt_notes, 1)

        act_bar = QHBoxLayout()
        self.btn_save = QPushButton("Save")
        self.btn_copy_user = QPushButton("Copy User")
        self.btn_copy_pass = QPushButton("Copy Pass")
        act_bar.addWidget(self.btn_save)
        act_bar.addWidget(self.btn_copy_user)
        act_bar.addWidget(self.btn_copy_pass)
        right_layout.addLayout(act_bar)

        # Wire actions
        self.btn_add.clicked.connect(self.on_add)
        self.btn_edit.clicked.connect(self.on_edit)
        self.btn_rotate.clicked.connect(self.on_rotate)
        self.btn_delete.clicked.connect(self.on_delete)
        self.btn_export.clicked.connect(self.on_export)
        self.btn_import.clicked.connect(self.on_import)
        self.btn_save.clicked.connect(self.on_save)
        self.btn_copy_user.clicked.connect(self.on_copy_user)
        self.btn_copy_pass.clicked.connect(self.on_copy_pass)

        # Data
        self.entries: List[PasswordEntry] = []
        self.current: Optional[PasswordEntry] = None
        self.refresh_list()

    def refresh_list(self) -> None:
        query = self.search_input.text().lower().strip()
        try:
            self.entries = self.pm.get_entries()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load entries: {e}")
            self.entries = []
        self.list_widget.clear()
        for e in self.entries:
            if query and not (
                query in (e.website or '').lower()
                or query in (e.username or '').lower()
                or query in (e.notes or '').lower()
                or any(query in t.lower() for t in (e.tags or []))
            ):
                continue
            item = QListWidgetItem(f"{e.website} — {e.username}")
            item.setData(Qt.ItemDataRole.UserRole, e.id)
            self.list_widget.addItem(item)

    def on_selection_changed(self) -> None:
        item = self.list_widget.currentItem()
        if not item:
            self.current = None
            return
        entry_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            # get_entry may accept id or website; ensure id fetch
            entry = self.pm.get_entry(entry_id)
        except Exception:
            # fallback: find in self.entries
            entry = next((x for x in self.entries if x.id == entry_id), None)
        self.current = entry
        if entry:
            self.lbl_website.setText(entry.website)
            self.lbl_username.setText(entry.username)
            self.lbl_password.setText(entry.password)
            self.lbl_url.setText(entry.url)
            self.txt_notes.setText(entry.notes)

    def on_add(self) -> None:
        website, ok = QInputDialog.getText(self, "Add Entry", "Website:")
        if not ok or not website:
            return
        username, ok = QInputDialog.getText(self, "Add Entry", "Username:")
        if not ok or not username:
            return
        # Generate or prompt for password
        choice = QMessageBox.question(self, "Password", "Generate a strong password?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if choice == QMessageBox.StandardButton.Yes:
            password = self.pm.generate_password()
        else:
            password, ok = QInputDialog.getText(self, "Add Entry", "Password:")
            if not ok or not password:
                return
        try:
            entry = PasswordEntry(
                id=self.pm.generate_id(),
                website=website,
                username=username,
                password=password,
            )
            self.pm.add_entry(entry)
            self.refresh_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add entry: {e}")

    def on_edit(self) -> None:
        if not self.current:
            return
        self.lbl_website.setFocus()

    def on_save(self) -> None:
        if not self.current:
            return
        try:
            self.current.website = self.lbl_website.text()
            self.current.username = self.lbl_username.text()
            self.current.password = self.lbl_password.text()
            self.current.url = self.lbl_url.text()
            self.current.notes = self.txt_notes.toPlainText()
            self.pm.update_entry(self.current)
            self.refresh_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save entry: {e}")

    def on_rotate(self) -> None:
        if not self.current:
            return
        try:
            new_password = self.pm.generate_password(length=24)
            self.current.password = new_password
            self.pm.update_entry(self.current)
            self.lbl_password.setText(new_password)
            QMessageBox.information(self, "Rotated", "Password rotated and saved.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to rotate: {e}")

    def on_delete(self) -> None:
        if not self.current:
            return
        if QMessageBox.question(self, "Delete", f"Delete entry for {self.current.website}?") == QMessageBox.StandardButton.Yes:
            try:
                self.pm.delete_entry(self.current.id)
                self.current = None
                self.refresh_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete: {e}")

    def on_copy_user(self) -> None:
        if not self.current:
            return
        try:
            import pyperclip
            pyperclip.copy(self.current.username)
            QMessageBox.information(self, "Copied", "Username copied to clipboard.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Clipboard failed: {e}")

    def on_copy_pass(self) -> None:
        if not self.current:
            return
        try:
            import pyperclip
            pyperclip.copy(self.current.password)
            QMessageBox.information(self, "Copied", "Password copied to clipboard.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Clipboard failed: {e}")


def run_app() -> None:
    # Prompt for master password
    app = QApplication(sys.argv)
    from PyQt6.QtWidgets import QInputDialog

    pw, ok = QInputDialog.getText(None, "Cerberus", "Master password:")
    if not ok or not pw:
        return
    try:
        pm = PasswordManager(master_password=pw)
    except VaultError as e:
        QMessageBox.critical(None, "Error", f"Failed to unlock vault: {e}")
        return
    win = MainWindow(pm)
    win.show()
    sys.exit(app.exec())
