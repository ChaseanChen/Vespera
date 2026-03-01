# src/unsealer/google/cli.py

import sys
import argparse
import json

from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

# 注意：请确保同目录下的 decrypter.py 已同步更新
from .decrypter import decrypt_google_auth_uri
from .scanner import extract_uris_from_path
from unsealer.common.exporter import DataExporter 

# 初始化控制台，用于标准错误输出
console = Console(stderr=True)

def main():
    parser = argparse.ArgumentParser(
        description="Google Authenticator Migrator"
        )
    parser.add_argument(
        "inputs", 
        nargs="*",
        help="URIs, QR images, or a JSON file to parse"
        )
    parser.add_argument(
        "-o", 
        "--output", 
        type=Path, 
        help="Export result (supports .md, .json)")
    args = parser.parse_args(sys.argv[2:])
    all_accounts_map = {}

    # 1. 处理输入
    if args.inputs:
        with console.status("[bold green]Processing inputs..."):
            for item in args.inputs:
                p = Path(item)
                if item.startswith("otpauth-migration://"):
                    for acc in decrypt_google_auth_uri(item): all_accounts_map[acc['totp_secret']] = acc
                elif p.suffix == ".json" and p.exists():
                    data = json.loads(p.read_text(encoding='utf-8'))
                    accounts = data.get("google", data) if isinstance(data, dict) else data
                    for acc in accounts: all_accounts_map[acc['totp_secret']] = acc
                elif p.exists():
                    uris = extract_uris_from_path(item)
                    for u in uris:
                        for acc in decrypt_google_auth_uri(u): all_accounts_map[acc['totp_secret']] = acc

    # 2. 交互模式
    if not all_accounts_map:
        console.print(Panel("No data found. Paste a URI or Drag & Drop a JSON file.", title="Google Migrator"))
        while True:
            val = Prompt.ask("[yellow]Enter URI/Path (Empty to finish)[/]").strip()
            if not val: break
            if val.startswith("otpauth-migration://"):
                for acc in decrypt_google_auth_uri(val): all_accounts_map[acc['totp_secret']] = acc
            else:
                uris = extract_uris_from_path(val)
                for u in uris:
                    for acc in decrypt_google_auth_uri(u): all_accounts_map[acc['totp_secret']] = acc

    final_accounts = sorted(all_accounts_map.values(), key=lambda x: x['issuer'].lower())
    if not final_accounts:
        console.print("[red]No accounts to process.[/red]")
        return

    processed_accounts = []
    
    for acc in final_accounts:
        processed_accounts.append({
            "issuer": acc['issuer'],
            "account": acc['name'],
            "secret": acc['totp_secret'],
            "algorithm": acc['algorithm'],
            "digits": acc['digits'],
            "type": "TOTP"
        })
    
    payload = {"google_authenticator": processed_accounts}

    table = Table(title=f"Decrypted {len(processed_accounts)} Accounts")
    table.add_column("Issuer", style="cyan")
    table.add_column("Account", style="green")
    for row in processed_accounts:
        table.add_row(row['issuer'], row['name'])
    console.print(table)

    if args.output:
        fmt = args.output.suffix[1:] if args.output.suffix else "md"
        exporter = DataExporter(banner="GOOGLE AUTHENTICATOR EXPORT")
        exporter.export(payload, args.output, fmt)
        console.print(f"[bold green]✓ Export Success:[/] [magenta]{args.output}[/]")

if __name__ == "__main__":
    main()