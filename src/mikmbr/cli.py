"""CLI interface for Mikmbr scanner."""

import argparse
import sys
from pathlib import Path

from .scanner import Scanner
from .formatters import get_formatter
from .config import MikmbrConfig


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="mikmbr",
        description="Mikmbr - Detect security vulnerabilities in Python code"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan Python code for security issues")
    scan_parser.add_argument(
        "path",
        help="Path to file or directory to scan"
    )
    scan_parser.add_argument(
        "--format",
        choices=["human", "json"],
        default=None,
        help="Output format (default: from config or human)"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=None,
        help="Show detailed output with code snippets, CWE IDs, and references"
    )
    scan_parser.add_argument(
        "--config", "-c",
        help="Path to configuration file (default: search for .mikmbr.yaml)"
    )

    args = parser.parse_args()

    if args.command == "scan":
        try:
            # Load configuration
            config = None
            if args.config:
                # Explicit config file provided
                config_path = Path(args.config)
                if not config_path.exists():
                    print(f"Error: Config file not found: {args.config}", file=sys.stderr)
                    sys.exit(2)
                config = MikmbrConfig.from_file(config_path)
            else:
                # Try to find config file automatically
                config_path = MikmbrConfig.find_config_file(Path(args.path))
                if config_path:
                    config = MikmbrConfig.from_file(config_path)
                else:
                    config = MikmbrConfig()

            # CLI arguments override config file settings
            if args.format is not None:
                config.output.format = args.format
            if args.verbose is not None and args.verbose:
                config.output.verbose = args.verbose

            # Create scanner with configuration
            scanner = Scanner(config=config)
            findings = scanner.scan_path(args.path)

            # Use configuration for formatter
            formatter = get_formatter(config.output.format, verbose=config.output.verbose)
            output = formatter.format(findings)
            print(output)

            # Exit with non-zero if findings were found
            sys.exit(1 if findings else 0)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
