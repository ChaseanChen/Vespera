# src/unsealer/__main__.py

import sys
import argparse
import traceback

# --- Import Handling ---
try:
    # Attempt to import sub-modules for command dispatching
    from unsealer.samsung import cli as samsung_cli
    from unsealer.google import cli as google_cli
except ImportError as e:
    # Print detailed debugging information to stderr if imports fail
    print("--- Debug Information ---", file=sys.stderr)
    traceback.print_exc()
    print("-------------------------", file=sys.stderr)
    
    print(
        f"Fatal Error: Could not import a required submodule.\n"
        f"Please ensure the project structure is correct and dependencies are installed.\n"
        f"Details: {e}",
        file=sys.stderr
    )
    sys.exit(1)

def main():
    # 1. Initialize the primary ArgumentParser
    parser = argparse.ArgumentParser(
        prog="unsealer",
        description="A powerful, multi-module tool to reclaim your digital credentials.",
        epilog="Use 'unsealer <command> --help' for more information on a specific command."
    )

    # 2. Define subparsers for different modules
    subparsers = parser.add_subparsers(
        title="Available Modules",
        dest="command",
        required=True,
        metavar="<command>"
    )

    # 3. Register the 'samsung' module command
    subparsers.add_parser(
        "samsung",
        help="Decrypt and export data from Samsung Pass (.spass) backups.",
        description="A specialized module for decrypting and parsing Samsung Pass (.spass) backup files."
    )

    # 4. Register the 'google' module command
    subparsers.add_parser(
        "google",
        help="Decrypt and extract 2FA accounts from Google Authenticator export URIs.",
        description="Extract and decrypt 2FA accounts from Google Authenticator export data to human-readable formats."
    )

    # --- Command Dispatching Logic ---

    # Only parse the first argument to determine which module to invoke.
    # The remaining arguments will be handled by the respective module's CLI.
    args = parser.parse_args(sys.argv[1:2])

    if args.command == "samsung":
        samsung_cli.main()
    elif args.command == "google":
        google_cli.main()
    else:
        # Fallback: display help if an invalid command is reached
        parser.print_help()

if __name__ == "__main__":
    main()