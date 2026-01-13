"""Demo script showcasing all 10 detection rules."""

import sys
from pathlib import Path

# Add src to path so we can import mikmbr
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mikmbr.scanner import Scanner
from mikmbr.formatters import HumanFormatter

def main():
    print("=" * 80)
    print("mikmbr Scanner - Complete Detection Capabilities Demo")
    print("=" * 80)
    print()

    scanner = Scanner()

    # Scan vulnerable code
    vulnerable_file = Path(__file__).parent / "tests" / "fixtures" / "vulnerable_code.py"
    new_vulns_file = Path(__file__).parent / "tests" / "fixtures" / "new_vulnerabilities.py"

    print("📊 Scanning original vulnerabilities (5 categories)...")
    findings1 = scanner.scan_file(str(vulnerable_file))
    print(f"   Found {len(findings1)} issues")

    print()
    print("📊 Scanning new vulnerabilities (5 new categories)...")
    findings2 = scanner.scan_file(str(new_vulns_file))
    print(f"   Found {len(findings2)} issues")

    all_findings = findings1 + findings2

    print()
    print("=" * 80)
    print(f"TOTAL: {len(all_findings)} Security Issues Found")
    print("=" * 80)
    print()

    # Group findings by rule_id
    by_rule = {}
    for finding in all_findings:
        if finding.rule_id not in by_rule:
            by_rule[finding.rule_id] = []
        by_rule[finding.rule_id].append(finding)

    # Display summary
    print("Summary by Category:")
    print("-" * 80)
    for rule_id in sorted(by_rule.keys()):
        count = len(by_rule[rule_id])
        severity = by_rule[rule_id][0].severity.value
        print(f"  [{severity:^4}] {rule_id:30} {count} issue(s)")

    print()
    print("=" * 80)
    print("Detailed Report (First 3 Issues)")
    print("=" * 80)

    # Show detailed output for first 3 findings
    formatter = HumanFormatter(verbose=True)
    print(formatter.format(all_findings[:3]))

    print()
    print("=" * 80)
    print("✅ Demo Complete!")
    print()
    print("mikmbr now detects 10 categories of security vulnerabilities:")
    print("  1. DANGEROUS_EXEC       - Code injection (eval/exec)")
    print("  2. COMMAND_INJECTION    - OS command injection")
    print("  3. SQL_INJECTION        - SQL injection")
    print("  4. WEAK_CRYPTO          - Weak cryptographic algorithms")
    print("  5. HARDCODED_SECRET     - Hardcoded credentials")
    print("  6. INSECURE_DESERIALIZATION - Unsafe pickle/YAML")
    print("  7. PATH_TRAVERSAL       - Path traversal attacks")
    print("  8. INSECURE_RANDOM      - Weak random for security")
    print("  9. REGEX_DOS            - ReDoS vulnerabilities")
    print(" 10. XXE                  - XML external entities")
    print()
    print("Run: py -m mikmbr.cli scan tests/fixtures/ --verbose")
    print("=" * 80)

if __name__ == "__main__":
    main()
