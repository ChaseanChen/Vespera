# src/unsealer/google/cli.py

import sys
import argparse
import json
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

# 核心解密与扫描逻辑
from .decrypter import decrypt_google_auth_uri
from .scanner import extract_uris_from_path
from unsealer.common.exporter import DataExporter
from unsealer.common.models import Credential

# 初始化控制台（错误流输出，保持标准输出纯净供管道使用）
console = Console(stderr=True)

def main():
    parser = argparse.ArgumentParser(
        description="Google Authenticator Migration Tool - Reclaim your 2FA tokens."
    )
    parser.add_argument(
        "inputs", 
        nargs="*",
        help="Google migration URIs, paths to QR screenshots, or directories of images."
    )
    parser.add_argument(
        "-o", 
        "--output", 
        type=Path, 
        help="Destination path for export (supports .md, .csv, .txt, .json)"
    )
    parser.add_argument(
        "--preview", 
        action="store_true", 
        help="Display the decrypted accounts in terminal without exporting."
    )

    # 适配 unsealer <command> 结构的参数分发
    args = parser.parse_args(sys.argv[2:])
    
    all_creds: List[Credential] = []

    def ingest(item: str):
        """
        统一的数据摄入函数：
        自动识别 URI、JSON 备份、单张图片或图片目录。
        """
        item = item.strip().strip("'").strip('"')
        if not item:
            return

        # 1. 直接处理迁移 URI
        if item.startswith("otpauth-migration://"):
            try:
                all_creds.extend(decrypt_google_auth_uri(item))
            except Exception as e:
                console.print(f"[bold red]解析失败:[/] {item[:30]}... 错误: {e}")
            return

        # 2. 处理文件系统路径
        path = Path(item)
        if not path.exists():
            console.print(f"[bold yellow]警告:[/] 路径不存在: {item}")
            return

        # 2a. 处理统一模型导出的 JSON 文件（实现闭环加载）
        # 建议改为更 Pythonic 的方式，并确保字段类型安全
        if path.is_file() and path.suffix == ".json":
            data = json.loads(path.read_text(encoding='utf-8'))
            entries = data.get("google_authenticator", data)
            try:
                if isinstance(entries, list):
                    for e in entries:
                        # 使用字典解包创建对象
                        # 但要注意过滤掉多余的键，防止构造函数报错
                        valid_keys = Credential.__dataclass_fields__.keys()
                        base_data = {k: v for k, v in e.items() if k in valid_keys}
                        extra_data = {k: v for k, v in e.items() if k not in valid_keys}
                        all_creds.append(Credential(**base_data, extra=extra_data))
            except Exception as e:
                console.print(f"[bold red]JSON 加载失败:[/] {e}")
            return

        # 2b. 调用扫描器处理图片文件或目录中的 QR 码
        try:
            uris = extract_uris_from_path(str(path))
            if not uris:
                console.print(f"[yellow]未在路径中发现有效的 QR 码: {path}[/]")
            for uri in uris:
                all_creds.extend(decrypt_google_auth_uri(uri))
        except Exception as e:
            console.print(f"[bold red]扫描失败:[/] {e}")

    # --- 执行逻辑 ---

    # 1. 处理命令行提供的所有输入
    if args.inputs:
        with console.status("[bold green]Processing inputs..."):
            for item in args.inputs:
                ingest(item)

    # 2. 交互模式：如果命令行没有输入或没解析到数据，引导用户交互
    if not all_creds:
        console.print(Panel(
            "[bold cyan]Google Authenticator Unsealer[/]\n\n"
            "请粘贴 [bold yellow]otpauth-migration://[/bold yellow] 链接\n"
            "或者直接拖入 [bold green]QR 码截图/图片文件夹[/bold green]。",
            title="Waiting for Input"
        ))
        while True:
            val = Prompt.ask("[yellow]输入 URI 或 路径 (留空结束)[/]").strip()
            if not val:
                break
            ingest(val)

    if not all_creds:
        console.print("[red]未发现任何账户数据，程序退出。[/red]")
        return

    # 3. 数据处理：去重 (根据 secret) 并按发行商排序
    unique_map = {c.secret: c for c in all_creds if c.secret}
    final_creds = sorted(unique_map.values(), key=lambda x: (x.issuer or x.title).lower())

    # 4. 终端展示
    table = Table(
        title=f"Decrypted [bold green]{len(final_creds)}[/bold green] Accounts",
        border_style="cyan",
        show_header=True,
        header_style="bold magenta"
    )
    table.add_column("Issuer (发行商)", style="cyan", no_wrap=True)
    table.add_column("Account (账号)", style="green")
    table.add_column("Type", style="dim")

    for cred in final_creds:
        table.add_row(
            cred.issuer or cred.title, 
            cred.username,
            cred.category.upper()
        )
    console.print(table)

    # 5. 数据导出
    if args.output:
        # 转换为字典列表供 Exporter 使用
        payload = {"google_authenticator": [c.to_dict() for c in final_creds]}
        
        # 自动识别格式
        fmt = args.output.suffix[1:].lower() if args.output.suffix else "md"
        if fmt not in ["md", "csv", "json", "txt"]:
            fmt = "md"
            
        exporter = DataExporter(banner="GOOGLE AUTHENTICATOR RECOVERY REPORT")
        try:
            exporter.export(payload, args.output, fmt)
            console.print(f"\n[bold green]✓ 导出成功:[/] [magenta]{args.output}[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ 导出失败:[/] {e}")
    elif not args.preview:
        console.print("\n[dim]提示: 使用 -o 参数可将结果保存为文件 (例如: -o backup.md)[/]")

if __name__ == "__main__":
    main()