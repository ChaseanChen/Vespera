import argparse
import sys
import csv
import os
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
from typing import Dict, List, Any

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
    banner: str = None):
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


def _process_decryption(
    args: argparse.Namespace, password: str, plain_banner: str
):
    try:
        file_content = args.input_file.read_bytes()
        with console.status(
            "[bold green]Decrypting and refining data...[/bold green]", spinner="dots"
        ):
            all_tables = decrypt_and_parse(file_content, password)

        TABLE_NAMES = {
            "logins": "Login Credentials",
            "identities": "Identity Info",
            "addresses": "Address Info",
            "notes": "Secure Memos",
        }
        summary = Text()
        for name, data in all_tables.items():
            display_name = TABLE_NAMES.get(name, "Other Data")
            summary.append(f"✓ [cyan]{display_name}[/cyan]: Found {len(data)} entries\n")

        console.print(
            Panel(
                summary,
                title="[bold green]✓ Decryption Successful[/bold green]",
                border_style="green",
            )
        )

        if args.preview:
            console.print("[dim]> Preview mode: No files will be saved. Use -f and -o to export data.[/dim]")
            return

        console.print(
            f"[cyan]> [/cyan]Saving to [bold magenta]{args.output}[/bold magenta] (Format: [yellow]{args.format.upper()}[/yellow])..."
        )

        save_dispatch = {
            "md": lambda data, path, banner: save_as_md(data, path, banner),
            "txt": lambda data, path, banner: save_as_txt(data, path, banner),
            "csv": lambda data, path, banner: save_as_csv(data, path),
            "json": lambda data, path, banner: save_as_json(data, path),
        }
        save_dispatch[args.format](all_tables, args.output, plain_banner)

        console.print(
            f"\n[bold green]✓ Success![/bold green] Data exported to [bold magenta]{args.output}[/bold magenta]"
        )

    except (FileNotFoundError, ValueError) as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        sys.exit(1)
    except Exception:
        console.print(
            f"[bold red]✗ An unexpected internal error occurred.[/bold red] Details saved to `unsealer_error.log`."
        )
        with open("unsealer_error.log", "a", encoding="utf-8") as f:
            f.write(f"--- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            traceback.print_exc(file=f)
            f.write("\n")
        sys.exit(1)


def _process_packing(args, password):
    """处理 JSON 到 .spass 的转换过程"""
    try:
        # 1. 尝试以 UTF-8 读取 JSON
        if not args.input_file.exists():
            raise FileNotFoundError(f"找不到输入文件: {args.input_file}")
            
        with open(args.input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # 2. 调用加密函数
        with console.status("[bold green]正在生成三星加密备份文件...", spinner="bouncingBar"):
            # 延迟导入以提高启动速度
            from .decrypter import encrypt_and_seal
            sealed_data = encrypt_and_seal(data, password)
        
        # 3. 写入二进制数据
        args.output.write_bytes(sealed_data)
        console.print(f"\n[bold green]✓ 封印成功！[/bold green]")
        console.print(f"[cyan]> [/cyan]备份文件已保存至: [bold magenta]{args.output}[/bold magenta]")
        console.print(f"[dim]提示: 你现在可以将此文件通过三星换机助手或三星云导入手机。[/dim]")

    except json.JSONDecodeError:
        console.print(f"[bold red]✗ 错误:[/] 输入文件不是有效的 JSON 格式。")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]✗ 打包失败:[/] {str(e)}")
        # 记录详细错误以便调试
        with open("unsealer_pack_error.log", "a", encoding="utf-8") as f:
            f.write(f"--- {datetime.now()} ---\n{traceback.format_exc()}\n")
        sys.exit(1)

# main 函数建议保持你目前设计的“先计算路径、再统一询问密码、再分发任务”的流程。
# 那个流程是非常清晰且正确的。

def main():
    plain_banner = _display_banner()
    parser = _setup_arg_parser()
    
    # 适配二级分发
    args = parser.parse_args(sys.argv[2:])

    # 1. 自动计算路径
    if not args.output and not args.preview:
        if args.format == "csv":
            sanitized_stem = _sanitize_filename(args.input_file.stem)
            args.output = Path(f"{sanitized_stem}_csv_export")
        else:
            args.output = args.input_file.with_suffix(f".{args.format}")

    # 2. 检查冲突
    if args.output and not args.preview and not args.force:
        if args.output.exists():
            console.print(f"[bold red]✗ 错误:[/bold red] 输出目标已存在。使用 '-y' 强制覆盖。")
            sys.exit(1)

    # 3. 获取密码
    password = Prompt.ask("[bold yellow]> [/bold yellow]输入三星账号主密码", password=True)

    # 4. 执行解密提取
    _process_decryption(args, password, plain_banner)


if __name__ == "__main__":
    main()