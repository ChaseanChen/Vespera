import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

class DataExporter:
    """统一数据导出引擎：解决格式不一、嵌套难读的问题"""
    
    def __init__(self, banner: str = ""):
        self.banner = banner.strip() if banner else ""
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def export(self, data: Dict[str, List[Dict]], output_path: Path, fmt: str):
        """导出分发器"""
        if not data:
            return
            
        fmt = fmt.lower()
        if fmt == "json": self._to_json(data, output_path)
        elif fmt == "csv": self._to_csv(data, output_path)
        elif fmt == "md": self._to_markdown(data, output_path)
        elif fmt == "txt": self._to_text(data, output_path)

    def _to_json(self, data: Dict, path: Path):
        meta = {"metadata": {"generated_at": self.timestamp, "version": "2.0.8"}}
        path.write_text(json.dumps({**meta, **data}, indent=4, ensure_ascii=False), encoding='utf-8')

    def _to_csv(self, data: Dict, path: Path):
        # CSV 处理逻辑：如果是文件路径，则创建一个同名文件夹存放多张表
        export_dir = path if not path.suffix else path.parent / f"{path.stem}_export"
        export_dir.mkdir(parents=True, exist_ok=True)
            
        for table_name, rows in data.items():
            if not rows: continue
            file_path = export_dir / f"{table_name}.csv"
            # 自动获取所有行中出现过的所有 key 作为表头
            headers = sorted(set().union(*(d.keys() for d in rows)))
            with open(file_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

    def _to_markdown(self, data: Dict, path: Path):
        lines = [f"```\n{self.banner}\n```\n" if self.banner else "# Unsealer Decryption Report"]
        lines.append(f"> **Export Time**: `{self.timestamp}`  \n> **Status**: ✅ Decrypted & Flattened\n")
        
        for table_name, rows in data.items():
            lines.append(f"\n## 📂 {table_name.upper()} ({len(rows)} items)")
            for i, entry in enumerate(rows, 1):
                title = self._get_title(entry)
                lines.append(f"\n### {i}. {title}")
                for k, v in entry.items():
                    # 跳过作为标题的字段，避免重复显示
                    if not v or k in ["title", "name", "note_title", "issuer", "full_name", "bank_name"]: 
                        continue
                    
                    label = k.replace('_', ' ').title()
                    # 针对敏感字段添加防护图标和代码块
                    sensitive_keys = ["password", "secret", "cvv", "pin", "id_number", "card_number"]
                    if any(x in k.lower() for x in sensitive_keys):
                        lines.append(f"- **{label}**: 🔐 `{v}`")
                    else:
                        lines.append(f"- **{label}**: {v}")
                lines.append("\n---")
        path.write_text("\n".join(lines), encoding='utf-8')

    def _to_text(self, data: Dict, path: Path):
        lines = [self.banner if self.banner else "UNSEALER REPORT"]
        lines.append(f"Export Time: {self.timestamp}\n" + "="*40)
        for table_name, rows in data.items():
            lines.append(f"\n[{table_name.upper()}]")
            for entry in rows:
                lines.append("-" * 30)
                for k, v in entry.items():
                    label = k.replace('_', ' ').title()
                    lines.append(f"{label:<18}: {v}")
        path.write_text("\n".join(lines), encoding='utf-8')

    def _get_title(self, entry: Dict) -> str:
        """智能标题识别"""
        priority_keys = ["title", "name", "issuer", "note_title", "full_name", "bank_name", "account"]
        for key in priority_keys:
            if entry.get(key): return str(entry[key])
        return "Unnamed Record"