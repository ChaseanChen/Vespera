# src/tests/test_samsung_cli.py

import pytest
import sys
from pathlib import Path
from unsealer.samsung import cli

def test_samsung_cli_success_flow(mocker):
    """
    Test the successful data export workflow of the Samsung Pass CLI module.
    """
    # 1. Mock command line arguments (Simulated: unsealer samsung test_input.spass -f md)
    mocker.patch.object(sys, "argv", ["unsealer", "samsung", "test_input.spass", "-f", "md"])
    
    # 2. Mock decrypter return data consistent with the current internal schema
    mock_data = {
        "logins": [
            {"title": "Test site", "username_value": "admin", "password_value": "12345"}
        ],
        "notes": [
            {"note_title": "Secret Note", "note_detail": "This is a secret"}
        ]
    }
    
    # Mock file I/O and core decryption logic
    mocker.patch("pathlib.Path.read_bytes", return_value=b"mocked_base64_content")
    mock_decrypt = mocker.patch("unsealer.samsung.cli.decrypt_and_parse", return_value=mock_data)
    
    # Mock interactive terminal password prompt
    mocker.patch("rich.prompt.Prompt.ask", return_value="master_password")
    
    # Mock save functions to avoid generating physical files during test execution
    mock_save_md = mocker.patch("unsealer.samsung.cli.save_as_md")
    
    # Mock console status to prevent multi-threading interference in CI/CD environments
    mocker.patch("rich.console.Console.status")

    # Execute the CLI entry point
    cli.main()

    # 3. Assertion Verification
    # Verify the decryption function was invoked with correct parameters
    mock_decrypt.assert_called_once_with(b"mocked_base64_content", "master_password")
    
    # Verify the markdown save function was called with the expected transformed path
    # Note: CLI automatically changes extension from .spass to .md
    expected_output_path = Path("test_input.md")
    mock_save_md.assert_called_once()
    assert mock_save_md.call_args[0][1] == expected_output_path

def test_samsung_cli_invalid_password(mocker):
    """
    Test error handling when decryption fails due to an incorrect master password.
    """
    mocker.patch.object(sys, "argv", ["unsealer", "samsung", "bad.spass"])
    mocker.patch("pathlib.Path.read_bytes", return_value=b"some_data")
    mocker.patch("rich.prompt.Prompt.ask", return_value="wrong_password")
    
    # Simulate a decryption failure via ValueError
    mocker.patch(
        "unsealer.samsung.cli.decrypt_and_parse", 
        side_effect=ValueError("Decryption failed. Please verify your master password.")
    )
    
    # Ensure the program exits gracefully with a non-zero status code
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    
    # Verify the exit code is 1 (Standard error code)
    assert excinfo.value.code == 1