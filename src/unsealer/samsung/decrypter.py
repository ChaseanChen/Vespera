# src/unsealer/samsung/decrypter.py

import base64
import hashlib
import csv
import io
import re
import json
import sys
import binascii
from typing import List, Dict, Any, Union
from pathlib import Path

# Attempt to import cryptographic primitives
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Fatal Error: Core cryptographic library 'pycryptodome' is missing.")
    print("Please install it by running: pip install pycryptodome")
    sys.exit(1)

# --- Load parsing rules from the schema file ---
try:
    SCHEMA_PATH = Path(__file__).parent / "schema.json"
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        TABLE_SCHEMA = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"Fatal Error: Failed to load or parse 'schema.json'. Path: {SCHEMA_PATH}")
    print(f"Details: {e}", file=sys.stderr)
    sys.exit(1)


# --- Cryptographic Constants ---
SALT_SIZE = 20  # Length of the salt in bytes
IV_SIZE = 16    # AES Initialization Vector length in bytes
KEY_SIZE = 32   # AES-256 key size in bytes

# The iteration count is defined by Samsung's encryption standards.
# 70,000 rounds are required for a successful key derivation.
PBKDF2_ITERATIONS = 70000


# --- Helper Parsing Functions ---

def _safe_b64_decode(b64_string: str) -> str:
    """Decodes a base64 string safely, handling specific null-placeholders."""
    if not b64_string or b64_string.strip() in ["", "JiYmTlVMTCYmJg=="]:
        return ""
    try:
        return base64.b64decode(b64_string).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        # Return raw string if decoding fails
        return b64_string

def _parse_json_field(field_value: str) -> Union[Dict, str]:
    """Cleans and parses strings that contain nested JSON data."""
    try:
        # Samsung data often escapes quotes; we need to clean them before parsing
        cleaned_value = field_value.replace('\\"', '"').strip()
        if cleaned_value.startswith('"') and cleaned_value.endswith('"'):
            cleaned_value = cleaned_value[1:-1]
        return json.loads(cleaned_value)
    except (json.JSONDecodeError, TypeError):
        return field_value

def _parse_multi_b64_field(field_value: str) -> List[str]:
    """Parses fields containing multiple base64-encoded items separated by '&&&'."""
    if not field_value:
        return []
    decoded_parts = []
    # Split the field into components and decode each valid part
    parts = field_value.split("&&&")
    for part in parts:
        if not part:
            continue
        # Extract the base64 portion (before the '#' if present)
        b64_part = part.split("#")[0]
        decoded = _safe_b64_decode(b64_part)
        if decoded:
            decoded_parts.append(decoded)
    return decoded_parts

def clean_android_url(url: str) -> str:
    """Sanitizes Android-specific app URLs for better readability."""
    if not url or re.search(r"\.[a-zA-Z]{2,}", url) or url.startswith("http"):
        return url
    if url.startswith("android://"):
        try:
            # Extract the package name/label after the '@' symbol
            return url.split("@")[-1]
        except Exception:
            return url
    return url


# --- Core Parsing Logic ---

def parse_decrypted_content(decrypted_content: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parses the raw decrypted text into structured tables based on the schema."""
    all_tables: Dict[str, List[Dict[str, Any]]] = {}
    # The decrypted content consists of multiple tables separated by 'next_table'
    blocks = decrypted_content.split("next_table")
    unknown_table_count = 0

    for block_index, block in enumerate(blocks):
        clean_block = block.strip()
        if not clean_block or clean_block.count(";") < 2:
            continue

        try:
            # The data format is semicolon-delimited CSV
            reader = csv.DictReader(io.StringIO(clean_block), delimiter=";")
            headers = reader.fieldnames
            if not headers:
                continue

            # Identify the table type using the fingerprints defined in schema.json
            table_name = None
            schema = {}
            for name, sch in TABLE_SCHEMA.items():
                if all(fp in headers for fp in sch.get("fingerprint", [])):
                    table_name = name
                    schema = sch
                    break

            # If no fingerprint matches, mark as unknown data
            if not table_name:
                if "24" in headers and len(headers) == 1:
                    continue
                unknown_table_count += 1
                table_name = f"unknown_data_{unknown_table_count}"
                schema = {"useful_fields": headers}

            table_entries: List[Dict[str, Any]] = []
            for row in reader:
                entry = {}
                for field in schema.get("useful_fields", []):
                    raw_value_pre = row.get(field)
                    if raw_value_pre is None:
                        continue

                    # Each field value is typically base64 encoded
                    raw_value = _safe_b64_decode(raw_value_pre)
                    if not raw_value:
                        continue

                    # Apply specific parsing logic based on the field type
                    if field in schema.get("json_fields", []):
                        entry[field] = _parse_json_field(raw_value)
                    elif field in schema.get("multi_b64_fields", []):
                        entry[field] = _parse_multi_b64_field(raw_value)
                    elif field == "origin_url":
                        entry[field] = clean_android_url(raw_value)
                    else:
                        entry[field] = raw_value

                if entry:
                    table_entries.append(entry)

            if table_entries:
                all_tables[table_name] = table_entries

        except Exception as e:
            print(
                f"Warning: Issue encountered while parsing block #{block_index}. Skipping. Error: {e}",
                file=sys.stderr,
            )
            continue

    if not all_tables:
        raise ValueError("Decryption succeeded, but no valuable data could be extracted.")

    return all_tables


def decrypt_and_parse(
    file_content_bytes: bytes, password: str
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Main entry point for decrypting and structured parsing of the .spass content.
    """
    try:
        # The input file is a base64 encoded string containing the binary payload
        binary_data = base64.b64decode(file_content_bytes.decode("utf-8").strip())

        # Partition the binary data into its cryptographic components
        salt_end = SALT_SIZE
        iv_end = salt_end + IV_SIZE

        salt, iv, encrypted_data = (
            binary_data[:salt_end],
            binary_data[salt_end:iv_end],
            binary_data[iv_end:],
        )

        # Derive the 256-bit AES key using PBKDF2 with SHA-256
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
            dklen=KEY_SIZE,
        )

        # Decrypt using AES-256-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(
            cipher.decrypt(encrypted_data), AES.block_size, style="pkcs7"
        )

        # Parse the plain text result into structured objects
        return parse_decrypted_content(decrypted_data.decode("utf-8"))

    except (ValueError, binascii.Error):
        raise ValueError(
            "Decryption failed. Please verify your master password and ensure the file is a valid .spass backup."
        )
    except Exception as e:
        raise ValueError(f"An unexpected error occurred during decryption: {str(e)}")