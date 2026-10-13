"""Tests for configuration and settings management."""

import json
import tempfile
from pathlib import Path

import pytest

from cybersentinel.config import (
    AI_MODELS,
    PORT_PRIORITIES,
    RISK_SCORE_WEIGHTS,
    get_ai_api_key,
    set_ai_api_key,
)
from cybersentinel.gui.settings_dialog import SettingsManager


def test_config_constants():
    assert "openrouter" in AI_MODELS
    assert "claude" in AI_MODELS
    assert "gemini" in AI_MODELS
    assert 80 in PORT_PRIORITIES
    assert 443 in PORT_PRIORITIES
    assert "missing_security_header" in RISK_SCORE_WEIGHTS


def test_set_and_get_ai_api_key():
    set_ai_api_key("openrouter", "mock-openrouter-key")
    assert get_ai_api_key("openrouter") == "mock-openrouter-key"


def test_settings_manager_persistence():
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "test_settings.json"
        manager = SettingsManager(config_file=config_path)

        assert manager.get_api_key("claude") is None

        manager.set_api_key("claude", "sk-ant-testkey123")
        assert manager.get_api_key("claude") == "sk-ant-testkey123"

        # Verify disk persistence
        assert config_path.exists()
        with open(config_path, "r") as f:
            data = json.load(f)
        assert data.get("api_key_claude") == "sk-ant-testkey123"

        # Clear key
        manager.clear_api_key("claude")
        assert manager.get_api_key("claude") is None
