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
        content.append(f"{'Username:':<12} {entry.get('username', 'N/A')}")
        content.append(f"{'Password:':<12} {entry.get('password', 'N/A')}")
        if url := entry.get("url"):
            content.append(f"{'URL/App:':<12} {url}")
        if note := entry.get("note"):
            content.append(f"{'Memo:':<12} {note}")
        if secret := entry.get("secret"):
            content.append(f"\n  [!!] 2FA/OTP Secret:")
            content.append(f"    {'Secret:':<10} {secret}")
    return "\n".join(content)


def _format_identities_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n=======================\n [Identities] Info ({len(data)} items)\n======================="
    ]
    for i, entry in enumerate(data, 1):
        content.append(f"\n--- [ {i}. {entry.get('name', 'Unknown Identity')} ] ---")
        # 统一模型会保留原始字段在 extra 中并展平
        if id_num := entry.get("mIDCardNumber"):
            content.append(f"{'ID Number:':<12} {id_num}")
            content.append(f"{'Full Name:':<12} {entry.get('mUsername', 'N/A')}")
            content.append(f"{'Birth Date:':<12} {entry.get('mBirthDay', 'N/A')}")
        if phones := entry.get("telephone_number_list"):
            content.append(f"{'Phone:':<12} {phones}")
        if emails := entry.get("email_address_list"):
            content.append(f"{'Email:':<12} {emails}")
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
            f"\n--- [ {i}. {entry.get('title', 'Untitled Memo')} ] ---\n"
        )
        content.append(f"{entry.get('note', '')}")
    return "\n".join(content)


def _format_cards_txt(data: List[Dict]) -> str:
    content = [
        f"\n\n=====================\n [Cards] Payment Cards ({len(data)} items)\n====================="
    ]
    for i, entry in enumerate(data, 1):
        title = entry.get("title", "Unknown Bank")
        brand = entry.get("brand", "")
        content.append(f"\n--- [ {i}. {title} {brand} ] ---".strip())
        content.append(f"{'Cardholder:':<12} {entry.get('username', 'N/A')}")
        content.append(f"{'Card Number:':<12} {entry.get('password', 'N/A')}")
        content.append(f"{'Expiry:':<12} {entry.get('expiry', '??/??')}")
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
        
        for key in ORDER:
            if key in data and key in TXT_FORMATTERS:
                f.write(TXT_FORMATTERS[key](data[key]))
                
        for table_name, table_entries in data.items():
            if table_name in ORDER: continue
            sample_entry = table_entries[0] if table_entries else {}
            meaningful_keys = [k for k in sample_entry.keys() if not k.isdigit()]
            if not meaningful_keys: continue
            f.write(_format_unknown_txt(table_name, table_entries))

        f.write(f"\n\n--- END OF REPORT ---\n*Generated by Unsealer*")


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


def main():
    banner = _display_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    parser.add_argument("-f", "--format", choices=["md", "csv", "txt", "json"], default="md")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--preview", action="store_true")
    
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