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
import urllib.parse

# Attempt to import cryptographic primitives
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Fatal Error: Core cryptographic library 'pycryptodome' is missing.")
    print("Please install it by running: pip install pycryptodome")
    sys.exit(1)

SCHEMA_PATH = Path(__file__).parent / "schema.json"
# --- Load parsing rules from the schema file ---
try:
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
        # Clean escaped quotes before parsing
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
    """Normalizes URL/App identifiers, removing internal protocol prefixes."""
    if not url:
        return ""
    
    # 1. Return standard http/https links directly
    if url.startswith("http"):
        return url
        
    # 2. Keep strings that contain domain features even without the android protocol
    if not url.startswith("android://") and re.search(r"\.[a-zA-Z]{2,}", url):
        return url
        
    # 3. Handle android:// protocol
    if url.startswith("android://"):
        # If standard "android://package@Label" format, extract the Label portion
        if "@" in url:
            try:
                return url.split("@")[-1]
            except Exception:
                return url
        # Return raw URL if it doesn't match the expected contract
        return url
            
    return url

# --- Core Parsing Logic ---

def parse_decrypted_content(decrypted_content: str) -> Dict[str, List[Dict[str, Any]]]:
    """Parses raw decrypted text into structured tables based on the schema."""
    all_tables: Dict[str, List[Dict[str, Any]]] = {}
    blocks = decrypted_content.split("next_table")
    unknown_table_count = 0

    for block_index, block in enumerate(blocks):
        clean_block = block.strip()
        if not clean_block or clean_block.count(";") < 2:
            continue

        try:
            # Data format is semicolon-delimited CSV
            reader = csv.DictReader(io.StringIO(clean_block), delimiter=";")
            headers = reader.fieldnames
            if not headers:
                continue

            # Identify table type using fingerprints from schema.json
            table_name = None
            schema = {}
            for name, sch in TABLE_SCHEMA.items():
                fps = sch.get("fingerprint", [])
                # Match if any fingerprint field is present in the headers
                if any(fp in headers for fp in fps):
                    table_name = name
                    schema = sch
                    break

            # Mark as unknown data if no fingerprints match
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

                    # Apply specific parsing logic based on field type defined in schema
                    if field in schema.get("json_fields", []):
                        entry[field] = _parse_json_field(raw_value)
                    elif field in schema.get("multi_b64_fields", []):
                        entry[field] = _parse_multi_b64_field(raw_value)
                    elif field == "origin_url":
                        entry[field] = clean_android_url(raw_value)
                    else:
                        entry[field] = raw_value

                if entry:
                    table_entries.append(_flatten_entry(entry))

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
    """Derives AES key and decrypts the .spass binary payload."""
    try:
        # Decode the initial base64 wrapper from the file
        binary_data = base64.b64decode(file_content_bytes.decode("utf-8").strip())

        # Extract salt, IV, and the encrypted payload
        salt_end = SALT_SIZE
        iv_end = salt_end + IV_SIZE

        salt, iv, encrypted_data = (
            binary_data[:salt_end],
            binary_data[salt_end:iv_end],
            binary_data[iv_end:],
        )

        # Derive the key using PBKDF2-HMAC-SHA256
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

        return parse_decrypted_content(decrypted_data.decode("utf-8"))

    except (ValueError, binascii.Error):
        raise ValueError(
            "Decryption failed. Please verify your master password and ensure the file is a valid .spass backup."
        )
    except Exception as e:
        raise ValueError(f"An unexpected error occurred during decryption: {str(e)}")
    
    
def _flatten_entry(entry: Dict) -> Dict:
    """核心修正：将嵌套 JSON 展平并映射语义化字段名"""
    flattened = {}
    # 字段语义映射表：将 Samsung 原始字段名转换为通用的、合理的名称
    RENAME_MAP = {
        "reserved_5": "bank_name",
        "reserved_4": "card_brand",
        "card_number_encrypted": "card_number",
        "mIDCardNumber": "id_number",
        "mUsername": "full_name",
        "mBirthDay": "birth_date",
        "password_value": "password",
        "username_value": "username",
        "credential_memo": "memo",
        "note_title": "title",  # 增加映射，让笔记和账户在 Markdown 中标题对齐
        "note_detail": "content",
        "secret": "totp_secret",
    }
    
    for k, v in entry.items():
        # 1. 处理嵌套字典 (如 otp 字段, id_card_detail 字段)
        if not v: continue
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                # 优先寻找映射名，找不到则组合名称
                if not sub_v: continue
                new_key = RENAME_MAP.get(sub_k, f"{k}_{sub_k}")
                flattened[new_key] = sub_v
        # 2. 处理多值列表 (如 identities 中的电话、邮件列表)
        elif isinstance(v, list):
            flattened[k] = " | ".join(map(str, v))
        # 3. 处理普通字段
        else:
            new_key = RENAME_MAP.get(k, k)
            flattened[new_key] = v
            
    return flattened