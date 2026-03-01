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

# 初始化控制台，用于标准错误输出
console = Console(stderr=True)

def _save_report(accounts: list, output_path: Path):
    """
    将提取的账户信息保存为 Markdown 报告。
    """
    content = [
        "# Google Authenticator Export Report",
        f"- **Generated at**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "\n| No. | Issuer | Account Name | Secret (Base32) | Algorithm | Digits |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for i, acc in enumerate(accounts, 1):
        content.append(
            f"| {i} | {acc['issuer']} | {acc['name']} | `{acc['totp_secret']}` | "
            f"{acc['algorithm']} | {acc['digits']} |"
        )
    
    try:
        output_path.write_text("\n".join(content), encoding="utf-8")
        console.print(f"\n[bold green]✓[/] Report successfully saved to: [bold magenta]{output_path}[/]")
    except Exception as e:
        console.print(f"[bold red]✗ Failed to save file:[/bold red] {e}")

def main():
    parser = argparse.ArgumentParser(description="Google Authenticator Migrator")
    parser.add_argument("inputs", nargs="*", help="URIs, QR images, or a JSON file to parse")
    parser.add_argument("-o", "--output", type=Path, help="Export result (supports .md, .json)")
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

    # 3. 显示概览表格
    table = Table(title=f"Detected {len(final_accounts)} Accounts", header_style="bold magenta")
    table.add_column("Issuer", style="cyan")
    table.add_column("Account", style="green")
    table.add_column("Algorithm")
    for acc in final_accounts:
        table.add_row(acc['issuer'], acc['name'], acc['algorithm'])
    console.print(table)

    # 4. 检查输出格式
    if args.output:
        suffix = args.output.suffix.lower()
        if suffix == ".json":
            args.output.write_text(json.dumps(final_accounts, indent=4, ensure_ascii=False), encoding='utf-8')
            console.print(f"[green]✓ Exported JSON to {args.output}[/green]")
        else:
            # 默认导出为 markdown，不再判断是否为图片
            _save_report(final_accounts, args.output)

if __name__ == "__main__":
    main()