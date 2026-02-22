# src/unsealer/__main__.py

import sys
import argparse

try:
    from unsealer.samsung import cli as samsung_cli
    from unsealer.google import cli as google_cli
except ImportError as e:
    print(
        f"Fatal Error: Could not import a required submodule.\n"
        f"Please ensure your project structure is correct.\nDetails: {e}",
        file=sys.stderr
    )
    sys.exit(1)
    
def main():
    # 1. Create the top-level parser
    parser = argparse.ArgumentParser(
        prog="unsealer",
        description="A powerful, multi-module tool to reclaim your digital credentials.",
        epilog="Use 'unsealer <command> --help' for more information on a specific command."
    )

    # 2. Create a subparser object to handle the commands
    subparsers = parser.add_subparsers(
        title="Available Modules",
        dest="command",
        required=True,
        metavar="<command>"
    )

    # 3. Register the 'samsung' command
    # We don't re-define all the arguments here. We just register the command
    # and its help text. The actual argument parsing is still done by the submodule.
    subparsers.add_parser(
        "samsung",
        help="Decrypt and export data from Samsung Pass (.spass) backups.",
        description="A tool for decrypting and exporting Samsung Pass (.spass) backup files."
    )

    # 4. Register the 'google' command
    subparsers.add_parser(
        "google",
        help="Decrypt and extract 2FA accounts from a Google Authenticator export URI.",
        description="A tool for decrypting Google Authenticator 'otpauth-migration://' URIs."
    )