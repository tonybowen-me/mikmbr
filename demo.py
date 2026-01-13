"""Demo script to test mikmbr scanner without installing."""

import sys
from pathlib import Path

# Add src to path so we can import mikmbr
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mikmbr.scanner import Scanner
from mikmbr.formatters import HumanFormatter, JSONFormatter

def main():
    print("=== mikmbr Scanner Demo ===\n")

    # Scan the vulnerable test fixture
    print("Scanning vulnerable_code.py...\n")
    scanner = Scanner()

    vulnerable_file = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_code.py"
    findings = scanner.scan_file(str(vulnerable_file))

    # Display results in human-readable format
    formatter = HumanFormatter()
    print(formatter.format(findings))

    print("\n" + "="*60 + "\n")

    # Scan the safe test fixture
    print("Scanning safe_code.py...\n")
    safe_file = Path(__file__).parent / "tests" / "fixtures" / "safe_code.py"
    findings = scanner.scan_file(str(safe_file))

    print(formatter.format(findings))

if __name__ == "__main__":
    main()
