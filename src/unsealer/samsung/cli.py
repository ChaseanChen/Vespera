# src/unsealer/samsung/cli.py

import argparse
import sys

import csv
import re
import traceback
import json
from pathlib import Path

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
import pyfiglet

from .decrypter import decrypt_and_parse
from typing import Dict, List, Any, Optional


from unsealer.common.exporter import DataExporter


# --- Initialize the rich console ---
console = Console(stderr=True)

def _format_logins_txt(data: List[Dict]) -> str:
    content = [
        f"====================\n [Logins] Credentials ({len(data)} items)\n===================="
    ]
    for i, entry in enumerate(data, 1):
        content.append(f"\n--- [ {i}. {entry.get('title', 'Unknown Entry')} ] ---")
        content.append(f"{'Username:':<12} {entry.get('username_value', 'N/A')}")
        content.append(f"{'Password:':<12} {entry.get('password_value', 'N/A')}")
        if url := entry.get("origin_url"):
            content.append(f"{'URL/App:':<12} {url}")
        if memo := entry.get("credential_memo"):
            content.append(f"{'Memo:':<12} {memo}")
        if isinstance(otp := entry.get("otp"), dict) and otp.get("secret"):
            content.append(f"\n  [!!] 2FA/OTP Secret:")
            content.append(f"    {'Secret:':<10} {otp.get('secret')}")
            content.append(f"    {'Account:':<10} {otp.get('name', 'N/A')}")
    return "\n".join(content)


def _format_identities_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n=======================\n [Identities] Info ({len(data)} items)\n======================="
    ]
    for i, entry in enumerate(data, 1):
        content.append(f"\n--- [ {i}. {entry.get('name', 'Unknown Identity')} ] ---")
        if isinstance(id_card := entry.get("id_card_detail"), dict):
            content.append(f"{'ID Number:':<12} {id_card.get('mIDCardNumber', 'N/A')}")
            content.append(f"{'Full Name:':<12} {id_card.get('mUsername', 'N/A')}")
            content.append(f"{'Birth Date:':<12} {id_card.get('mBirthDay', 'N/A')}")
        if phones := entry.get("telephone_number_list"):
            content.append(f"{'Phone:':<12} {', '.join(phones)}")
        if emails := entry.get("email_address_list"):
            content.append(f"{'Email:':<12} {', '.join(emails)}")
    return "\n".join(content)


def _format_addresses_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n=====================\n [Addresses] Info ({len(data)} items)\n====================="
    ]
    for i, entry in enumerate(data, 1):
        name = entry.get("full_name", f"Address {i}")
        if name == "Add Address/Name":
            name = f"Address {i} (Template)"
        content.append(f"\n--- [ {i}. {name} ] ---")
        addr_parts = [
            entry.get(k)
            for k in ["street_address", "city", "state", "zipcode", "country_code"]
        ]
        full_address = ", ".join(filter(None, addr_parts))
        if full_address:
            content.append(f"{'Address:':<12} {full_address}")
        if phone := entry.get("phone_number"):
            content.append(f"{'Phone:':<12} {phone}")
        if email := entry.get("email"):
            content.append(f"{'Email:':<12} {email}")
    return "\n".join(content)


def _format_notes_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n======================\n [Notes] Secure Memos ({len(data)} items)\n======================"
    ]
    for i, entry in enumerate(data, 1):
        content.append(
            f"\n--- [ {i}. {entry.get('note_title', 'Untitled Memo')} ] ---\n"
        )
        content.append(f"{entry.get('note_detail', '')}")
    return "\n".join(content)


# --- Markdown Formatters ---
def _format_logins_md(data: List[Dict]) -> str:
    content = [f"## [Logins] Credentials - Total {len(data)} items\n"]
    for i, entry in enumerate(data, 1):
        content.append(f"### {i}. {entry.get('title', 'Unknown Entry')}")
        content.append(f"- **Username**: `{entry.get('username_value', 'N/A')}`")
        content.append(f"- **Password**: `{entry.get('password_value', 'N/A')}`")
        if url := entry.get("origin_url"):
            content.append(f"- **URL/App**: `{url}`")
        if memo := entry.get("credential_memo"):
            content.append(f"- **Memo**: {memo}")
        if isinstance(otp := entry.get("otp"), dict) and otp.get("secret"):
            content.append("- **[!] 2FA/OTP Secret**: ")
            content.append(f"  - **Secret**: `{otp.get('secret')}`")
            content.append(f"  - **Account**: `{otp.get('name', 'N/A')}`")
        content.append("\n---\n")
    return "\n".join(content)


def _format_identities_md(data: List[Dict]) -> str:
    content = [f"## [Identities] Information - Total {len(data)} items\n"]
    for i, entry in enumerate(data, 1):
        content.append(f"### {i}. {entry.get('name', 'Unknown Identity')}")
        if isinstance(id_card := entry.get("id_card_detail"), dict):
            content.append(f"- **ID Number**: `{id_card.get('mIDCardNumber', 'N/A')}`")
            content.append(f"- **Full Name**: `{id_card.get('mUsername', 'N/A')}`")
            content.append(f"- **Birth Date**: `{id_card.get('mBirthDay', 'N/A')}`")
        if phones := entry.get("telephone_number_list"):
            content.append(f"- **Phone**: {', '.join([f'`{p}`' for p in phones])}")
        if emails := entry.get("email_address_list"):
            content.append(f"- **Email**: {', '.join([f'`{e}`' for e in emails])}")
        content.append("\n---\n")
    return "\n".join(content)


def _format_addresses_md(data: List[Dict]) -> str:
    content = [f"## [Addresses] Information - Total {len(data)} items\n"]
    for i, entry in enumerate(data, 1):
        name = entry.get("full_name", f"Address {i}")
        if name == "Add Address/Name":
            name = f"Address {i} (Template)"
        content.append(f"### {i}. {name}")
        addr_parts = [
            entry.get(k)
            for k in ["street_address", "city", "state", "zipcode", "country_code"]
        ]
        full_address = ", ".join(filter(None, addr_parts))
        if full_address:
            content.append(f"- **Full Address**: {full_address}")
        if phone := entry.get("phone_number"):
            content.append(f"- **Phone**: `{phone}`")
        if email := entry.get("email"):
            content.append(f"- **Email**: `{email}`")
        content.append("\n---\n")
    return "\n".join(content)


def _format_notes_md(data: List[Dict]) -> str:
    content = [f"## [Notes] Secure Memos - Total {len(data)} items\n"]
    for i, entry in enumerate(data, 1):
        content.append(f"### {i}. {entry.get('note_title', 'Untitled Memo')}")
        content.append(f"```\n{entry.get('note_detail', '')}\n```")
        content.append("\n---\n")
    return "\n".join(content)


def save_as_md(data: Dict[str, List[Any]], output_file: Path, banner: str):
    MD_FORMATTERS = {
        "logins": _format_logins_md,
        "identities": _format_identities_md,
        "addresses": _format_addresses_md,
        "notes": _format_notes_md,
        "cards": _format_cards_md,
    }
    
    ORDER = ["logins", "cards", "identities", "addresses", "notes"]
    
    with open(output_file, "w", encoding="utf-8") as f:
        if banner:
            clean_banner = banner.strip()
            lines = clean_banner.split('\n')
            if lines:
                lines[0] = "   " + lines[0]
            modified_banner = "\n".join(lines)
            f.write(f"```\n{modified_banner}\n```\n\n")
            
        f.write("# Unsealer Comprehensive Decryption Report\n\n")
        
        # 1. Write known modules in order
        for key in ORDER:
            if key in data and key in MD_FORMATTERS:
                f.write(MD_FORMATTERS[key](data[key]))
                
        # 2. Write unrecognized but potentially important data
        for table_name, table_entries in data.items():
            if table_name in ORDER:
                continue
            
            # Filter metadata: ignore tables containing only numeric ID keys
            sample_entry = table_entries[0] if table_entries else {}
            meaningful_keys = [k for k in sample_entry.keys() if not k.isdigit()]
            
            if not meaningful_keys:
                continue
                
            f.write(_format_unknown_md(table_name, table_entries))

        f.write(f"\n*Report generated by Unsealer*")
        
        
def save_as_json(
    data: Dict[str, List[Any]],
    output_file: Path,
    banner: Optional[str] = None):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def save_as_txt(data: Dict[str, List[Any]], output_file: Path, banner: str):
    TXT_FORMATTERS = {
        "logins": _format_logins_txt,
        "identities": _format_identities_txt,
        "addresses": _format_addresses_txt,
        "notes": _format_notes_txt,
        "cards": _format_cards_txt,
    }
    ORDER = ["logins", "cards", "identities", "addresses", "notes"]
    
    with open(output_file, "w", encoding="utf-8") as f:
        if banner:
            f.write(f"{banner}\n")
        f.write("Unsealer Comprehensive Decryption Report\n")
        f.write("------------------------------------------\n")
        f.write(f"Generation Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 1. Write known modules in order
        for key in ORDER:
            if key in data and key in TXT_FORMATTERS:
                f.write(TXT_FORMATTERS[key](data[key]))
                
        # 2. Write unrecognized tables (sync with MD filtering logic)
        for table_name, table_entries in data.items():
            if table_name in ORDER: continue
            
            sample_entry = table_entries[0] if table_entries else {}
            meaningful_keys = [k for k in sample_entry.keys() if not k.isdigit()]
            if not meaningful_keys: continue
            
            f.write(_format_unknown_txt(table_name, table_entries))

        f.write(f"\n\n--- END OF REPORT ---\n*Generated by Unsealer*")

def _format_cards_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n=====================\n [Cards] Payment Cards ({len(data)} items)\n====================="
    ]
    for i, entry in enumerate(data, 1):
        bank = entry.get("reserved_5", "Unknown Bank")
        brand = entry.get("reserved_4", "")
        content.append(f"\n--- [ {i}. {bank} {brand} ] ---".strip())
        content.append(f"{'Cardholder:':<12} {entry.get('name_on_card', 'N/A')}")
        content.append(f"{'Card Number:':<12} {entry.get('card_number_encrypted', 'N/A')}")
        expiry = f"{entry.get('expiration_month', '??')}/{entry.get('expiration_year', '??')}"
        content.append(f"{'Expiry:':<12} {expiry}")
    return "\n".join(content)

def _format_unknown_txt(table_name: str, data: List[Dict]) -> str:
    content = [
        f"\n\n========================================\n [Unknown] Raw Data: {table_name}\n========================================"
    ]
    content.append("(!) This table was not recognized by fingerprints. Displaying raw JSON metadata:\n")
    content.append(json.dumps(data, indent=2, ensure_ascii=False))
    return "\n".join(content)

def _format_unknown_md(table_name: str, data: List[Dict]) -> str:
    content = [f"## [Unknown] Unrecognized Data Table - {table_name} ({len(data)} items)\n"]
    content.append("> This data could not be parsed automatically via fingerprints. It has been converted to raw JSON.\n")
    content.append("```json\n")
    content.append(json.dumps(data, indent=2, ensure_ascii=False))
    content.append("\n```\n\n---\n")
    return "\n".join(content)

def _format_cards_md(data: List[Dict]) -> str:
    content = [f"## [Cards] Payment Cards - Total {len(data)} items\n"]
    for i, entry in enumerate(data, 1):
        bank = entry.get("reserved_5", "Unknown Bank")
        brand = entry.get("reserved_4", "")
        content.append(f"### {i}. {bank} {brand}".strip())
        content.append(f"- **Cardholder**: `{entry.get('name_on_card', 'N/A')}`")
        content.append(f"- **Card Number**: `{entry.get('card_number_encrypted', 'N/A')}`")
        expiry = f"{entry.get('expiration_month', '??')}/{entry.get('expiration_year', '??')}"
        content.append(f"- **Expiry**: `{expiry}`")
        content.append("\n---\n")
    return "\n".join(content)

def save_as_csv(data: dict, output_path: Path):
    """
    Save each data category as an independent CSV file and flatten nested data.
    """
    output_path.mkdir(exist_ok=True, parents=True)

    for table_name, entries in data.items():
        if not entries:
            continue

        # 1. Skip metadata tables containing only numeric ID keys
        sample_entry = entries[0]
        meaningful_keys = [k for k in sample_entry.keys() if not k.isdigit()]
        if not meaningful_keys:
            continue

        all_headers = set()
        flat_data = []
        
        # 2. Process data only for identified valid tables
        for entry in entries:
            flat_entry = {}
            for key, value in entry.items():
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        flat_entry[f"{key}_{sub_key}"] = sub_value
                elif isinstance(value, list):
                    flat_entry[key] = "|".join(map(str, value))
                else:
                    flat_entry[key] = value
            
            all_headers.update(flat_entry.keys())
            flat_data.append(flat_entry)

        if not flat_data:
            continue

        file_path = output_path / f"{table_name}.csv"
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(list(all_headers)))
            writer.writeheader()
            writer.writerows(flat_data)


def _sanitize_filename(name: str) -> str:
    """
    Remove or replace illegal characters in filenames/directories.
    """
    return re.sub(r'[\\/*?:"<>|]', "_", name)


def _display_banner() -> str:
    plain_banner = pyfiglet.figlet_format("Unsealer", font="slant")
    console.print(
        Panel(
            plain_banner,
            title="[bold white] Vespera [/bold white]",
            subtitle="[cyan] -amber aurora- [/cyan]",
            border_style="cyan",
            expand=False,
        )
    )
    return plain_banner


def _setup_arg_parser() -> argparse.ArgumentParser:
    """回归精简的参数解析器"""
    parser = argparse.ArgumentParser(
        description="Unsealer Samsung Pass (.spass) 解密工具 - 专注于数据提取"
    )
    # 恢复为原来的位置参数
    parser.add_argument("input_file", type=Path, help="输入的 .spass 文件路径")
    
    parser.add_argument("-f", "--format", choices=["md", "txt", "csv", "json"], default="md", help="输出格式")
    parser.add_argument("-o", "--output", type=Path, help="目标输出路径")
    parser.add_argument("--preview", action="store_true", help="仅预览摘要")
    parser.add_argument("-y", "--force", action="store_true", help="强制覆盖已存在文件")
    
    return parser


def _process_decryption(args, password, plain_banner):
    """核心处理流程"""
    try:
        if not args.input_file.exists():
            raise FileNotFoundError(f"File not found: {args.input_file}")

        file_content = args.input_file.read_bytes()
        
        with console.status("[bold green]Decrypting Samsung Pass data..."):
            all_tables = decrypt_and_parse(file_content, password)

        # 打印简要概览
        summary = Text()
        for name, data in all_tables.items():
            summary.append(f"✓ {name.upper()}: {len(data)} entries\n")
        console.print(Panel(summary, title="Decryption Successful", border_style="green"))

        if args.preview:
            return

        # 使用统一导出引擎
        exporter = DataExporter(banner=plain_banner)
        exporter.export(all_tables, args.output, args.format)
        console.print(f"[bold green]✓[/] Data exported to [bold magenta]{args.output}[/]")

    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {str(e)}")
        sys.exit(1)


def main():
    banner = _display_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    parser.add_argument("-f", "--format", choices=["md", "csv", "txt", "json"], default="md")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--preview", action="store_true")
    
    # 注意：这里适配了 __main__.py 的二级分发
    args = parser.parse_args(sys.argv[2:])
    
    if not args.input_file.exists():
        console.print(f"[bold red]Error:[/] File {args.input_file} not found.")
        sys.exit(1)

    if not args.output and not args.preview:
        args.output = args.input_file.with_suffix(f".{args.format}")
        

    password = Prompt.ask("[yellow]Enter Samsung Account Password[/]", password=True)
    
    try:
        file_content = args.input_file.read_bytes()
        with console.status("[bold green]Decrypting & Processing..."):
            all_tables = decrypt_and_parse(file_content, password)

        if args.preview:
            summary = Text()
            for table, rows in all_tables.items():
                summary.append(f"✓ {table.upper()}: {len(rows)} items\n")
            console.print(Panel(summary, title="Decryption Successful"))
            return

        exporter = DataExporter(banner=banner)
        exporter.export(all_tables, args.output, args.format)
        console.print(f"\n[bold green]✓ Export Success:[/] [magenta]{args.output}[/]")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()