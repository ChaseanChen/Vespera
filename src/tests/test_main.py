# tests/test_main.py
import pytest
import sys
from unsealer.__main__ import main

def test_main_dispatch_to_samsung(mocker):
    """验证 'unsealer samsung' 命令分发到 samsung 模块"""
    mocker.patch.object(sys, "argv", ["unsealer", "samsung", "input.spass"])
    mock_samsung_cli = mocker.patch("unsealer.samsung.cli.main")
    
    main()
    mock_samsung_cli.assert_called_once()

def test_main_dispatch_to_google(mocker):
    """验证 'unsealer google' 命令分发到 google 模块"""
    mocker.patch.object(sys, "argv", ["unsealer", "google", "otpauth://..."])
    mock_google_cli = mocker.patch("unsealer.google.cli.main")
    
    main()
    mock_google_cli.assert_called_once()