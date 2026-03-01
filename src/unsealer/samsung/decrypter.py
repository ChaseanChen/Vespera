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
from unsealer.common.models import Credential

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Fatal Error: Core cryptographic library 'pycryptodome' is missing.")
    sys.exit(1)

SCHEMA_PATH = Path(__file__).parent / "schema.json"
try:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        TABLE_SCHEMA = json.load(f)
except Exception as e:
    print(f"Fatal Error: Failed to load schema.json: {e}")
    sys.exit(1)

# --- Cryptographic Constants ---
SALT_SIZE = 20
IV_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 70000

def _safe_b64_decode(b64_string: str) -> str:
    if not b64_string or b64_string.strip() in ["", "JiYmTlVMTCYmJg=="]:
        return ""
    try:
        return base64.b64decode(b64_string).decode("utf-8")
    except:
        return b64_string

def _parse_json_field(field_value: str) -> Union[Dict, str]:
    try:
        cleaned_value = field_value.replace('\\"', '"').strip()
        if cleaned_value.startswith('"') and cleaned_value.endswith('"'):
            cleaned_value = cleaned_value[1:-1]
        return json.loads(cleaned_value)
    except:
        return field_value

def _parse_multi_b64_field(field_value: str) -> List[str]:
    if not field_value: return []
    decoded_parts = []
    parts = field_value.split("&&&")
    for part in parts:
        if not part: continue
        b64_part = part.split("#")[0]
        decoded = _safe_b64_decode(b64_part)
        if decoded: decoded_parts.append(decoded)
    return decoded_parts

def clean_android_url(url: str) -> str:
    if not url: return ""
    if url.startswith("http"): return url
    if not url.startswith("android://") and re.search(r"\.[a-zA-Z]{2,}", url): return url
    if url.startswith("android://"):
        if "@" in url:
            try: return url.split("@")[-1]
            except: return url
    return url

def _to_unified_model(raw_entry: Dict, table_type: str) -> Credential:
    """将解码后的原始字段映射到统一模型"""
    if table_type == "logins":
        otp_data = raw_entry.get("otp")
        otp_secret = otp_data.get("secret", "") if isinstance(otp_data, dict) else ""
        return Credential(
            title=raw_entry.get("title") or clean_android_url(raw_entry.get("origin_url", "Unknown")),
            username=raw_entry.get("username_value", ""),
            password=raw_entry.get("password_value", ""),
            url=raw_entry.get("origin_url", ""),
            secret=otp_secret,
            note=raw_entry.get("credential_memo", ""),
            category="login"
        )
    elif table_type == "notes":
        return Credential(
            title=raw_entry.get("note_title", "Untitled Note"),
            note=raw_entry.get("note_detail", ""),
            category="note"
        )
    elif table_type == "cards":
        return Credential(
            title=raw_entry.get("reserved_5") or "Payment Card",
            username=raw_entry.get("name_on_card", ""),
            password=raw_entry.get("card_number_encrypted", ""),
            category="card",
            extra={
                "brand": raw_entry.get("reserved_4"),
                "expiry": f"{raw_entry.get('expiration_month')}/{raw_entry.get('expiration_year')}"
            }
        )
    # 对于 identities 和 addresses，我们将所有字段存入 extra 以保留深度
    return Credential(title=table_type.capitalize(), category=table_type, extra=raw_entry)

def parse_decrypted_content(decrypted_content: str) -> Dict[str, List[Dict[str, Any]]]:
    all_tables: Dict[str, List[Dict[str, Any]]] = {}
    blocks = decrypted_content.split("next_table")
    unknown_table_count = 0

    for block in blocks:
        clean_block = block.strip()
        if not clean_block or clean_block.count(";") < 2: continue

        try:
            reader = csv.DictReader(io.StringIO(clean_block), delimiter=";")
            headers = reader.fieldnames
            if not headers: continue

            table_name = None
            schema = {}
            for name, sch in TABLE_SCHEMA.items():
                if any(fp in headers for fp in sch.get("fingerprint", [])):
                    table_name, schema = name, sch
                    break

            if not table_name:
                if "24" in headers and len(headers) == 1: continue
                unknown_table_count += 1
                table_name = f"unknown_{unknown_table_count}"
                schema = {"useful_fields": headers}

            table_entries = []
            for row in reader:
                raw_entry = {}
                for field in schema.get("useful_fields", []):
                    val = _safe_b64_decode(row.get(field, ""))
                    if not val: continue
                    
                    if field in schema.get("json_fields", []): raw_entry[field] = _parse_json_field(val)
                    elif field in schema.get("multi_b64_fields", []): raw_entry[field] = _parse_multi_b64_field(val)
                    elif field == "origin_url": raw_entry[field] = clean_android_url(val)
                    else: raw_entry[field] = val

                if raw_entry:
                    # 转换并存储为字典格式
                    unified_obj = _to_unified_model(raw_entry, table_name)
                    table_entries.append(unified_obj.to_dict())

            if table_entries:
                all_tables[table_name] = table_entries

        except Exception as e:
            print(f"Warning: Parsing error: {e}", file=sys.stderr)
            continue

    return all_tables

def decrypt_and_parse(file_content_bytes: bytes, password: str) -> Dict[str, List[Dict[str, Any]]]:
    try:
        binary_data = base64.b64decode(file_content_bytes.decode("utf-8").strip())
        salt, iv, encrypted_data = binary_data[:20], binary_data[20:36], binary_data[36:]

        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size, style="pkcs7")

        return parse_decrypted_content(decrypted_data.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Decryption or Parsing Failed: {str(e)}")