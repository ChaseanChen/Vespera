import base64
import urllib.parse
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

def _parse_varint(data: bytes, pos: int):
    """
    Parse a Protobuf Varint from the byte stream.
    
    :param data: The binary data to parse.
    :param pos: The current position in the data stream.
    :return: A tuple containing the parsed integer and the new position.
    """
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
    """
    Simple Protobuf parser that maps binary streams to Tag dictionaries.
    
    :param data: The binary data to decode.
    :return: A dictionary where keys are tags and values are lists of items.
    """
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
        elif wire_type in [3, 4]:
            continue
        else:
            raise ValueError(f"Unsupported wire type: {wire_type} at pos {pos}")
        
        if tag not in res:
            res[tag] = []
        res[tag].append(val)
    return res

def decrypt_google_auth_uri(uri: str) -> List[Dict[str, Any]]:
    """
    Parses a Google Authenticator migration URI without requiring .pb2 files.
    
    :param uri: The 'otpauth-migration://' string.
    :return: A list of account dictionaries containing secrets and metadata.
    """
    try:
        parsed_uri = urlparse(uri)
        query_params = parse_qs(parsed_uri.query)
        encoded_data = query_params.get('data', [''])[0]
        
        # 1. Base64 Decoding with padding fix
        missing_padding = len(encoded_data) % 4
        if missing_padding:
            encoded_data += '=' * (4 - missing_padding)
        binary_payload = base64.b64decode(encoded_data)

        # 2. Parse outer MigrationPayload
        # Tag 1 represents the 'otp_parameters' repeated message
        payload_dict = _parse_message(binary_payload)
        otp_params_list = payload_dict.get(1, [])

        # 3. Algorithm Mapping based on Google Auth spec
        ALGO_MAP = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
        
        accounts = []
        for raw_otp in otp_params_list:
            # Parse inner OtpParameters message
            otp_dict = _parse_message(raw_otp)
            
            # Fields based on Protobuf definition:
            # 1: secret, 2: name, 3: issuer, 4: algorithm, 5: digits
            secret = otp_dict.get(1, [b''])[0]
            name = otp_dict.get(2, [b'Lost'])[0].decode('utf-8')
            issuer = otp_dict.get(3, [b''])[0].decode('utf-8')
            algo_idx = otp_dict.get(4, [1])[0]
            digit_idx = otp_dict.get(5, [1])[0]

            # Convert binary Secret to Base32 (standard for TOTP)
            b32_secret = base64.b32encode(secret).decode('utf-8').rstrip('=')
            
            # Extract issuer from name if issuer field is empty
            if not issuer and ":" in name:
                issuer = name.split(":", 1)[0].strip()
                name = name.split(":", 1)[1].strip()

            accounts.append({
                "issuer": issuer or "Lost",
                "name": name,
                "totp_secret": b32_secret,
                "algorithm": ALGO_MAP.get(algo_idx, "SHA1"),
                "digits": "8" if digit_idx == 2 else "6"
            })

        return accounts
    except Exception as e:
        raise ValueError(f"Failed to parse migration data: {str(e)}")
    
    
def _encode_varint(value: int) -> bytes:
    """将整数编码为 Protobuf Varint"""
    res = bytearray()
    while value > 127:
        res.append((value & 0x7f) | 0x80)
        value >>= 7
    res.append(value)
    return bytes(res)

def _encode_message(tag: int, wire_type: int, payload: bytes) -> bytes:
    """简易 Protobuf 消息封装"""
    header = (tag << 3) | wire_type
    return _encode_varint(header) + payload

def create_google_migration_uri(accounts: List[Dict]) -> str:
    """
    将账户列表打包成 Google 迁移 URI。
    支持版本号、动态算法和位数映射。
    """
    # 逆向映射表
    ALGO_REVERSE_MAP = {"SHA1": 1, "SHA256": 2, "SHA512": 3, "MD5": 4}
    
    all_params_bin = bytearray()
    
    for acc in accounts:
        # --- 编码内部 OtpParameters 消息 ---
        otp_param_bin = bytearray()
        
        # 1. Secret (Tag 1, Wire Type 2)
        # 确保 Base32 填充正确
        secret_b32 = acc['totp_secret'].upper().replace(" ", "")
        missing_padding = len(secret_b32) % 8
        if missing_padding:
            secret_b32 += '=' * (8 - missing_padding)
        secret_bytes = base64.b32decode(secret_b32)
        otp_param_bin += _encode_message(1, 2, _encode_varint(len(secret_bytes)) + secret_bytes)
        
        # 2. Name (Tag 2, Wire Type 2)
        name_bytes = acc.get('name', 'Unknown').encode('utf-8')
        otp_param_bin += _encode_message(2, 2, _encode_varint(len(name_bytes)) + name_bytes)
        
        # 3. Issuer (Tag 3, Wire Type 2)
        issuer_bytes = acc.get('issuer', '').encode('utf-8')
        otp_param_bin += _encode_message(3, 2, _encode_varint(len(issuer_bytes)) + issuer_bytes)
        
        # 4. Algorithm (Tag 4, Wire Type 0)
        algo_val = ALGO_REVERSE_MAP.get(acc.get('algorithm', 'SHA1'), 1)
        otp_param_bin += _encode_message(4, 0, _encode_varint(algo_val))
        
        # 5. Digits (Tag 5, Wire Type 0)
        # Google Spec: 1 = 6 digits, 2 = 8 digits
        digit_val = 2 if str(acc.get('digits')) == "8" else 1
        otp_param_bin += _encode_message(5, 0, _encode_varint(digit_val))

        # 将编码好的单个账户放入外层列表 (Tag 1, Wire Type 2)
        all_params_bin += _encode_message(1, 2, _encode_varint(len(otp_param_bin)) + otp_param_bin)
        
    # --- 编码外部 MigrationPayload 消息 ---
    # Tag 2: Version (通常设为 1)
    all_params_bin += _encode_message(2, 0, _encode_varint(1))
    # Tag 3: Batch Size (总数)
    all_params_bin += _encode_message(3, 0, _encode_varint(1))
    # Tag 4: Batch Index (索引，从 0 开始)
    all_params_bin += _encode_message(4, 0, _encode_varint(0))
    
    # 最终序列化
    encoded_data = base64.b64encode(all_params_bin).decode('utf-8')
    # 使用 quote 对数据进行 URL 编码是个好习惯（虽然在这个格式里通常不需要）
    return f"otpauth-migration://offline?data={urllib.parse.quote(encoded_data)}"