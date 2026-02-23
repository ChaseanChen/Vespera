# tests/test_samsung_decrypter.py

import pytest
import base64
from unsealer.samsung.decrypter import _safe_b64_decode, _parse_json_field, parse_decrypted_content

def test_safe_b64_decode():
    """
    Test the robust Base64 decoding utility, including handling of null placeholders.
    """
    # Standard decoding
    assert _safe_b64_decode("SGVsbG8=") == "Hello"
    # Handling of empty strings and Samsung's specific NULL placeholder
    assert _safe_b64_decode("JiYmTlVMTCYmJg==") == ""
    assert _safe_b64_decode("") == ""

def test_parse_json_field():
    """
    Test parsing of nested JSON fields extracted from decrypted content.
    """
    # Simulate common escaped JSON strings found in Samsung Pass backups
    input_str = '{\\"secret\\":\\"ABC\\",\\"name\\":\\"test\\"}'
    result = _parse_json_field(input_str)
    assert isinstance(result, dict)
    assert result["secret"] == "ABC"

def test_parse_decrypted_content_structure():
    """
    Test the structural parsing of raw decrypted text blocks against schema.json.
    """
    # Simulate the raw CSV-style content after decryption (containing fingerprint fields)
    # Fields: title='Test', username_value='admin', password_value='pass'
    # Values are Base64 encoded as they are inside the decrypted block
    raw_content = (
        "origin_url;username_value;password_value;title\n"
        "Y29tLmFwcA==;YWRtaW4=;cGFzcw==;VGVzdA==\n"
        "next_table\n"
    )
    
    result = parse_decrypted_content(raw_content)
    
    assert "logins" in result
    assert len(result["logins"]) == 1
    assert result["logins"][0]["title"] == "Test"
    assert result["logins"][0]["username_value"] == "admin"

def test_decryption_logic_failure():
    """
    Test that the decryption engine raises a ValueError for malformed Base64 input.
    """
    from unsealer.samsung.decrypter import decrypt_and_parse
    
    with pytest.raises(ValueError, match="Decryption failed"):
        # Provide completely non-Base64 bytes
        decrypt_and_parse(b"not-a-base64-string", "password")