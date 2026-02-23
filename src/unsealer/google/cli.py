import sys
import argparse
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from .decrypter import decrypt_google_auth_uri
from .scanner import extract_uris_from_path

# Initialize console for standard error to keep stdout clean for piping
console = Console(stderr=True)

def _save_report(accounts: list, output_path: Path):
    """
    Saves the extracted account information to a Markdown report.
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
    parser = argparse.ArgumentParser(
        description="Google Authenticator Data Extractor (Protobuf-free version)"
    )
    
    parser.add_argument("inputs", nargs="*", help="Migration URIs, QR image paths, or directories")
    parser.add_argument("-o", "--output", type=Path, help="Path to export the Markdown report")
    
    # Slice sys.argv to skip the 'google' command when parsing sub-arguments
    args = parser.parse_args(sys.argv[2:])

    final_uris = set()

    # 1. Process command-line inputs
    if args.inputs:
        with console.status("[bold green]Scanning input sources..."):
            for item in args.inputs:
                if item.startswith("otpauth-migration://"):
                    final_uris.add(item)
                else:
                    # Treat input as a file path for QR scanning
                    uris_found = extract_uris_from_path(item)
                    final_uris.update(uris_found)
    
    # 2. Interactive Mode if no input provided
    if not final_uris:
        console.print(Panel(
            "No input data detected. You can:\n"
            "1. Paste a URI starting with [bold cyan]otpauth-migration://[/]\n"
            "2. Drag and drop [bold cyan]image files[/] or [bold cyan]folders[/] containing QR codes\n"
            "\nPress [bold yellow]Enter[/] without input to start processing.", 
            title="[bold cyan]Google Authenticator Extractor", 
            border_style="cyan"
        ))
        
        while True:
            val = Prompt.ask("[bold yellow]Enter URI/Path (Leave empty to finish)[/]").strip()
            if not val:
                break
            if val.startswith("otpauth-migration://"):
                final_uris.add(val)
            else:
                uris_found = extract_uris_from_path(val)
                if uris_found:
                    final_uris.update(uris_found)
                    console.print(f"[dim]Extracted {len(uris_found)} URI(s) from path.[/dim]")
                else:
                    console.print("[red]No valid QR codes or URIs found at the specified path.[/red]")

    if not final_uris:
        console.print("[bold red]Error: No Google Migration data found to process.[/]")
        return

    # 3. Decryption and Deduplication
    all_accounts_map = {}
    try:
        with console.status("[bold green]Decrypting data batches..."):
            for uri in final_uris:
                accounts = decrypt_google_auth_uri(uri)
                for acc in accounts:
                    # Use totp_secret as unique key for deduplication
                    all_accounts_map[acc['totp_secret']] = acc

        # Sort accounts by issuer name for the final display
        final_accounts = sorted(all_accounts_map.values(), key=lambda x: x['issuer'].lower())

        # 4. Display Result Table
        if not final_accounts:
            console.print("[yellow]Parsing complete, but no valid accounts were found.[/yellow]")
            return

        table = Table(
            title=f"\nSuccessfully extracted {len(final_accounts)} 2FA account(s)", 
            header_style="bold magenta",
            border_style="dim"
        )
        table.add_column("Issuer", style="cyan", no_wrap=True)
        table.add_column("Account Name", style="green")
        table.add_column("Secret (Base32)", style="bold yellow")
        table.add_column("Algorithm", justify="center")
        
        for acc in final_accounts:
            table.add_row(
                acc['issuer'], 
                acc['name'], 
                acc['totp_secret'], 
                acc['algorithm']
            )
        
        console.print("\n", table)

        # 5. Export Report
        if args.output:
            _save_report(final_accounts, args.output)
        else:
            console.print("\n[dim]Hint: Use the '-o' flag to export results to a Markdown file.[/dim]")

    except Exception as e:
        console.print(f"[bold red]Fatal parsing error: [/] {e}")
        console.print("[dim]This may be caused by corrupted URIs or incompatible protocol versions.[/dim]")

if __name__ == "__main__":
    main()