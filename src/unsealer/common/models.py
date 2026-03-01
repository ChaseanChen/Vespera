# src/unsealer/common/models.py
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

@dataclass
class Credential:
    # 核心字段：所有凭据通用的最简集
    title: str               # 显示名称 (如: "Google", "Facebook")
    username: str = ""       # 登录账号名 / 2FA 账号名
    password: str = ""       # 密码 (如果有)
    secret: str = ""         # 2FA 密钥 / TOTP Secret
    url: str = ""            # 网站地址 / App 包名
    issuer: str = ""         # 2FA 发行者
    note: str = ""           # 备注 / Memo
    category: str = "login"  # 类别: login, totp, card, identity, note
    
    # 元数据：保留原始模块的一些特殊字段
    extra: Optional[Dict[str, Any]] = None

    def to_dict(self):
        # 先获取基础字段字典
        base = {k: v for k, v in asdict(self).items() if k != 'extra'}
        if self.extra:
            for k, v in self.extra.items():
                # 只有当基础字段中没有该键，或者基础字段值为空时，才合并
                if k not in base or not base[k]:
                    base[k] = v
        return base