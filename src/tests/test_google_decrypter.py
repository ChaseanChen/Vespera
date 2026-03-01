# src/tests/test_google_decrypter.py

import pytest
import base64
from unsealer.google.decrypter import decrypt_google_auth_uri

def test_google_uri_parsing_success():
    """
    Test Google migration URI parsing using program-generated, fully aligned data.
    """
    # This URI payload represents:
    # Secret: 'password' (8 bytes)
    # Name: 'user'
    # Issuer: 'service'
    # Corresponding binary sequence: 0a 19 0a 08 70 61 73 73 77 6f 72 64 12 04 75 73 65 72 1a 07 73 65 72 76 69 63 65
    uri = "otpauth-migration://offline?data=ChkKCHBhc3N3b3JkEgR1c2VyGgdzZXJ2aWNl"
    
    accounts = decrypt_google_auth_uri(uri)
    
    # Calculate the expected Base32 encoded secret
    expected_b32 = base64.b32encode(b"password").decode('utf-8').rstrip('=')
    
    assert len(accounts) == 1
    assert accounts[0]["issuer"] == "service"
    assert accounts[0]["name"] == "user"
    assert accounts[0]["totp_secret"] == expected_b32

def test_google_uri_invalid_data():
    """
    Test that invalid binary data in the URI triggers an appropriate ValueError.
    """
    with pytest.raises(ValueError, match="Failed to parse migration data"):
        # 0x0F (binary 00001 111) represents Tag 1, Wire Type 7 (Invalid/Reserved)
        decrypt_google_auth_uri("otpauth-migration://offline?data=Dw==")