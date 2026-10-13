"""Settings dialog for managing API keys and preferences."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Optional

try:
    from PyQt5.QtCore import QUrl
    from PyQt5.QtGui import QDesktopServices
    from PyQt5.QtWidgets import (
        QDialog,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QFormLayout,
        QTabWidget,
        QWidget,
        QMessageBox,
    )
    PYQT5_AVAILABLE = True
except ImportError:
    QDialog = object
    PYQT5_AVAILABLE = False

try:
    from cybersentinel.config import AI_MODELS
except ImportError:
    from config import AI_MODELS

logger = logging.getLogger(__name__)


class SettingsManager:
    """Manages persistent application settings and API keys."""

    def __init__(self, config_file: Optional[Path] = None) -> None:
        if config_file is None:
            # Store settings in user's home directory
            config_dir = Path.home() / ".cybersecurity_toolkit"
            config_dir.mkdir(exist_ok=True, parents=True)
            config_file = config_dir / "settings.json"
        
        self.config_file = config_file
        self.settings = self._load_settings()

    def _load_settings(self) -> Dict[str, str]:
        """Load settings from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    return json.load(f)
            except Exception as exc:
                logger.warning("Could not load settings: %s", exc)
                return {}
        return {}

    def _save_settings(self) -> None:
        """Save settings to file."""
        try:
            self.config_file.parent.mkdir(exist_ok=True, parents=True)
            with open(self.config_file, "w") as f:
                json.dump(self.settings, f, indent=2)
            # Make file readable only by owner (basic security)
            self.config_file.chmod(0o600)
        except Exception as exc:
            logger.error("Could not save settings: %s", exc)

    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for a provider."""
        return self.settings.get(f"api_key_{provider}")

    def set_api_key(self, provider: str, api_key: str) -> None:
        """Set API key for a provider."""
        if api_key.strip():
            self.settings[f"api_key_{provider}"] = api_key.strip()
        elif f"api_key_{provider}" in self.settings:
            del self.settings[f"api_key_{provider}"]
        self._save_settings()

    def get_all_api_keys(self) -> Dict[str, str]:
        """Get all stored API keys."""
        result = {}
        for provider in AI_MODELS.keys():
            key = self.get_api_key(provider)
            if key:
                result[provider] = key
        return result

    def clear_api_key(self, provider: str) -> None:
        """Clear API key for a provider."""
        if f"api_key_{provider}" in self.settings:
            del self.settings[f"api_key_{provider}"]
        self._save_settings()

    def clear_all_api_keys(self) -> None:
        """Clear all stored API keys."""
        for provider in AI_MODELS.keys():
            self.clear_api_key(provider)


class SettingsDialog(QDialog):
    """Dialog for managing application settings and API keys."""

    def __init__(self, parent=None, settings_manager: Optional[SettingsManager] = None) -> None:
        if not PYQT5_AVAILABLE:
            raise ImportError("PyQt5 is required to launch SettingsDialog graphical interface.")
        super().__init__(parent)
        self.settings_manager = settings_manager or SettingsManager()
        self.setWindowTitle("Settings - CyberSentinel Toolkit")
        self.setGeometry(100, 100, 600, 400)
        self._build_ui()
        self._load_current_settings()

    def _build_ui(self) -> None:
        """Build the settings dialog UI."""
        layout = QVBoxLayout(self)

        # Create tabs for different settings sections
        tabs = QTabWidget()
        tabs.addTab(self._build_api_keys_tab(), "API Keys")
        tabs.addTab(self._build_about_tab(), "About")

        layout.addWidget(tabs)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        save_button = QPushButton("Save & Close")
        save_button.clicked.connect(self._on_save)
        button_layout.addWidget(save_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)

    def _build_api_keys_tab(self) -> QWidget:
        """Build the API keys settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header_label = QLabel("<b>Configure AI Provider API Keys</b>")
        layout.addWidget(header_label)
        layout.addWidget(QLabel("Click the button next to each provider to open the official login/key page. Then paste the generated API key here."))
        layout.addWidget(QLabel(""))

        form_layout = QFormLayout()
        self.api_key_inputs = {}

        provider_links = {
            "openrouter": "https://openrouter.ai",
            "claude": "https://console.anthropic.com",
            "gemini": "https://aistudio.google.com",
        }

        for provider_key, provider_info in AI_MODELS.items():
            label_text = f"{provider_info['name']} ({provider_info['api_key_env']})"
            input_field = QLineEdit()
            input_field.setEchoMode(QLineEdit.Password)
            input_field.setPlaceholderText(f"Enter your {provider_info['api_key_env']}")
            self.api_key_inputs[provider_key] = input_field
            form_layout.addRow(label_text, input_field)

            open_button = QPushButton(f"Open {provider_info['name']} site")
            open_button.clicked.connect(
                lambda _, url=provider_links[provider_key]: QDesktopServices.openUrl(QUrl(url))
            )
            form_layout.addRow("", open_button)

        layout.addLayout(form_layout)
        layout.addWidget(QLabel(""))
        layout.addWidget(QLabel("<i>API keys are stored securely in ~/.cybersecurity_toolkit/settings.json</i>"))
        layout.addStretch()
        return widget

    def _build_about_tab(self) -> QWidget:
        """Build the about tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        about_text = QLabel(
            "<b>CyberSentinel Toolkit v1.0</b><br><br>"
            "An automated penetration testing toolkit with AI-powered analysis.<br><br>"
            "<b>Supported AI Providers:</b><br>"
            "• Claude (Anthropic) - Get key at <a href='https://console.anthropic.com'>console.anthropic.com</a><br>"
            "• Gemini (Google) - Get key at <a href='https://aistudio.google.com'>aistudio.google.com</a><br><br>"
            "<b>Ethical Use:</b><br>"
            "Only scan targets you own or have explicit authorization to test.<br>"
            "Unauthorized scanning is illegal and unethical."
        )
        about_text.setOpenExternalLinks(True)
        about_text.setWordWrap(True)

        layout.addWidget(about_text)
        layout.addStretch()
        return widget

    def _load_current_settings(self) -> None:
        """Load current settings into the dialog."""
        for provider, input_field in self.api_key_inputs.items():
            key = self.settings_manager.get_api_key(provider)
            if key:
                input_field.setText(key)

    def _on_save(self) -> None:
        """Save all settings."""
        try:
            for provider, input_field in self.api_key_inputs.items():
                api_key = input_field.text().strip()
                if api_key:
                    self.settings_manager.set_api_key(provider, api_key)
                else:
                    self.settings_manager.clear_api_key(provider)

            QMessageBox.information(
                self,
                "Settings Saved",
                "Your API keys have been saved securely.",
            )
            self.accept()
        except Exception as exc:
            logger.exception("Error saving settings")
            QMessageBox.critical(
                self,
                "Error",
                f"Could not save settings: {exc}",
            )

    def get_api_key(self, provider: str) -> Optional[str]:
        """Get the API key for a provider from the current dialog state."""
        if provider in self.api_key_inputs:
            key = self.api_key_inputs[provider].text().strip()
            return key if key else None
        return None
