"""Demo script to showcase verbose mode with enhanced output."""

import sys
from pathlib import Path

# Add src to path so we can import mikmbr
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mikmbr.scanner import Scanner
from mikmbr.formatters import HumanFormatter

def main():
    print("=== mikmbr Scanner Demo - VERBOSE MODE ===\n")

    # Scan the vulnerable test fixture
    print("Scanning vulnerable_code.py with --verbose output...\n")
    scanner = Scanner()

    vulnerable_file = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_code.py"
    findings = scanner.scan_file(str(vulnerable_file))

    # Display results in verbose human-readable format
    formatter = HumanFormatter(verbose=True)
    print(formatter.format(findings))

    print("\n" + "="*80)
    print("Comparison: Non-verbose vs Verbose")
    print("="*80 + "\n")

    print("WITHOUT --verbose (default):")
    print("-" * 40)
    formatter_normal = HumanFormatter(verbose=False)
    # Show just first finding
    if findings:
        print(formatter_normal.format([findings[0]]))

    print("\nWITH --verbose flag:")
    print("-" * 40)
    # Show same finding in verbose mode
    if findings:
        print(formatter.format([findings[0]]))

if __name__ == "__main__":
    main()
