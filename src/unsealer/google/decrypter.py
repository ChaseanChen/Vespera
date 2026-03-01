# src/unsealer/google/decrypter.py

import base64
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

from unsealer.common.models import Credential

# --- Protobuf 解析逻辑 (轻量级实现) ---

def _parse_varint(data: bytes, pos: int):
    """从字节流中安全地解析 Protobuf Varint"""
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

def _parse_message(data: bytes) -> Dict[int, List[Any]]:
    """
    将原始 Protobuf 二进制流映射为 Tag 字典。
    Google 迁移格式主要使用 Wire Type 0 (Varint) 和 2 (Length-delimited)。
    """
    pos = 0
    res = {}
    while pos < len(data):
        try:
            tag_and_type, pos = _parse_varint(data, pos)
        except (IndexError, ValueError):
            break
        
        tag = tag_and_type >> 3
        wire_type = tag_and_type & 0x07
        
        if wire_type == 0:  # Varint
            val, pos = _parse_varint(data, pos)
        elif wire_type == 1:  # 64-bit
            val = data[pos:pos+8]
            pos += 8
        elif wire_type == 2:  # Length-delimited (String/Bytes/Nested)
            length, pos = _parse_varint(data, pos)
            val = data[pos:pos+length]
            pos += length
        elif wire_type == 5:  # 32-bit
            val = data[pos:pos+4]
            pos += 4
        else:
            # 遇到未知 Wire Type 时停止解析以防止死循环
            break
        
        if tag not in res:
            res[tag] = []
        res[tag].append(val)
    return res

def decrypt_google_auth_uri(uri: str) -> List[Credential]:
    """
    解析 Google Authenticator 迁移 URI (otpauth-migration://)。
    该 URI 包含一个 Base64 编码的 Protobuf 载荷。
    """
    try:
        parsed_uri = urlparse(uri)
        if parsed_uri.scheme != "otpauth-migration":
            raise ValueError("非法的协议头部，预期的协议为 'otpauth-migration://'")

        query_params = parse_qs(parsed_uri.query)
        encoded_data = query_params.get('data', [''])[0]
        
        if not encoded_data:
            return []

        # 1. Base64 解码：修复因 QR 扫描器可能丢失的填充符 '='
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        
        # 针对 URL 安全的 Base64 替换（虽然 Google 默认使用标准 Base64，但增加健壮性）
        binary_payload = base64.b64decode(encoded_data.replace(' ', '+'))

        # 2. 解析外层迁移载荷 (MigrationPayload)
        # Tag 1: otp_parameters (repeated message)
        payload_dict = _parse_message(binary_payload)
        otp_params_list = payload_dict.get(1, [])

        # 3. 协议映射常量
        # 算法映射 (Google 协议定义: 1=SHA1, 2=SHA256, 3=SHA512)
        ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
        
        results = []
        for raw_otp in otp_params_list:
            # 解析内层 OTP 参数
            # Tag 1: Secret, 2: Name, 3: Issuer, 4: Algorithm, 5: Digits
            otp_dict = _parse_message(raw_otp)
            
            raw_secret = otp_dict.get(1, [b''])[0]
            name = otp_dict.get(2, [b'Unknown'])[0].decode('utf-8', 'ignore')
            issuer = otp_dict.get(3, [b''])[0].decode('utf-8', 'ignore')
            
            # 默认值处理：Google 默认算法为 SHA1 (idx 1)，默认长度为 6 (idx 1)
            algo_idx = otp_dict.get(4, [1])[0]
            digit_idx = otp_dict.get(5, [1])[0]

            # 关键：将二进制密钥转换为 TOTP 标准的 Base32 编码（移除末尾填充）
            b32_secret = base64.b32encode(raw_secret).decode('utf-8').rstrip('=')
            
            # 处理 Google 常见的 "Issuer:Account" 复合命名格式
            if not issuer and ":" in name:
                parts = name.split(":", 1)
                issuer = parts[0].strip()
                name = parts[1].strip()

            # 映射至统一领域模型 Credential
            results.append(Credential(
                title=issuer or name or "Google Authenticator",
                username=name,
                secret=b32_secret,
                issuer=issuer,
                category="totp",
                extra={
                    "algorithm": ALGO_MAP.get(algo_idx, "SHA1"),
                    "digits": "8" if digit_idx == 2 else "6",
                    "original_type": "TOTP"
                }
            ))
            
        return results

    except Exception as e:
        # 捕获解析过程中的任何异常并包装，防止 CLI 崩溃
        raise ValueError(f"Google 迁移数据解析失败: {str(e)}")