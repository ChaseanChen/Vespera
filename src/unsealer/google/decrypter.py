import base64
import urllib.parse
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

# --- Protobuf 解析逻辑 ---

def _parse_varint(data: bytes, pos: int):
    """从字节流中解析 Protobuf Varint"""
    res = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        res |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            return res, pos
        shift += 7
    return res, pos

def _parse_message(data: bytes):
    """简单的 Protobuf 解析器，将二进制流映射为 Tag 字典"""
    pos = 0
    res = {}
    while pos < len(data):
        curr_pos = pos
        try:
            tag_and_type, pos = _parse_varint(data, pos)
        except IndexError:
            break

        if pos == curr_pos: break
        
        tag = tag_and_type >> 3
        wire_type = tag_and_type & 0x07
        
        if wire_type == 0:  # Varint
            val, pos = _parse_varint(data, pos)
        elif wire_type == 1:  # 64-bit
            val = data[pos:pos+8]
            pos += 8
        elif wire_type == 2:  # Length-delimited
            l, pos = _parse_varint(data, pos)
            val = data[pos:pos+l]
            pos += l
        elif wire_type == 5:  # 32-bit
            val = data[pos:pos+4]
            pos += 4
        else:
            continue
        
        if tag not in res:
            res[tag] = []
        res[tag].append(val)
    return res

def decrypt_google_auth_uri(uri: str) -> List[Dict[str, Any]]:
    """解析 Google Authenticator 迁移 URI"""
    try:
        parsed_uri = urlparse(uri)
        query_params = parse_qs(parsed_uri.query)
        encoded_data = query_params.get('data', [''])[0]
        
        # 1. Base64 解码，处理填充
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        binary_payload = base64.b64decode(encoded_data)

        # 2. 解析外层 MigrationPayload
        payload_dict = _parse_message(binary_payload)
        otp_params_list = payload_dict.get(1, [])

        # 3. 算法映射
        ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
        
        accounts = []
        for raw_otp in otp_params_list:
            otp_dict = _parse_message(raw_otp)
            
            # 字段定义: 1:secret, 2:name, 3:issuer, 4:algorithm, 5:digits
            secret = otp_dict.get(1, [b''])[0]
            name = otp_dict.get(2, [b'Unknown'])[0].decode('utf-8')
            issuer = otp_dict.get(3, [b''])[0].decode('utf-8')
            algo_idx = otp_dict.get(4, [1])[0]
            digit_idx = otp_dict.get(5, [1])[0]

            # 将二进制密钥转换为 Base32
            b32_secret = base64.b32encode(secret).decode('utf-8').rstrip('=')
            
            if not issuer and ":" in name:
                issuer = name.split(":", 1)[0].strip()
                name = name.split(":", 1)[1].strip()

            accounts.append({
                "issuer": issuer or "Unknown",
                "name": name,
                "totp_secret": b32_secret,
                "algorithm": ALGO_MAP.get(algo_idx, "SHA1"),
                "digits": "8" if digit_idx == 2 else "6"
            })

        return accounts
    except Exception as e:
        raise ValueError(f"Failed to parse migration data: {str(e)}")