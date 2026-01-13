"""Demo script showcasing smart secret detection."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mikmbr.scanner import Scanner
from mikmbr.formatters import HumanFormatter
from mikmbr.utils.secret_detection import calculate_entropy, detect_secret_pattern

def main():
    print("=" * 80)
    print("mikmbr Smart Secret Detection Demo")
    print("=" * 80)
    print()

    # Show entropy analysis
    print("📊 Entropy Analysis Examples:")
    print("-" * 80)

    test_strings = [
        ("aaaaaaa", "Low entropy (repeated chars)"),
        ("password123", "Medium entropy (dictionary word + numbers)"),
        ("aK9$mP2xQw7vBn5t", "High entropy (random-looking)"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS Key"),
    ]

    for string, description in test_strings:
        entropy = calculate_entropy(string)
        print(f"  {description:40} Entropy: {entropy:.2f}")

    print()
    print("=" * 80)
    print("🔍 Known Pattern Detection Examples:")
    print("-" * 80)

    known_secrets = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456",
        "xoxb-1234567890-1234567890-abcdefghijklmnop",
        "sk_live_1234567890abcdefghijklmn",
    ]

    for secret in known_secrets:
        pattern = detect_secret_pattern(secret)
        if pattern:
            print(f"  ✅ Detected: {pattern[1]}")
            print(f"     Value: {secret[:20]}...")
        else:
            print(f"  ❌ Not detected: {secret}")

    print()
    print("=" * 80)
    print("📁 Scanning Example File (Non-Test):")
    print("=" * 80)
    print()

    scanner = Scanner()
    formatter = HumanFormatter(verbose=True)

    # Scan the secrets demo example (NOT in test directory)
    example_file = Path(__file__).parent / "examples" / "secrets_demo.py"

    if example_file.exists():
        print(f"Scanning: {example_file}")
        print()

        findings = scanner.scan_file(str(example_file))

        print(f"Found {len(findings)} secret(s) using smart detection:\n")

        # Group by confidence
        high_conf = [f for f in findings if f.confidence.value == "HIGH"]
        med_conf = [f for f in findings if f.confidence.value == "MEDIUM"]
        low_conf = [f for f in findings if f.confidence.value == "LOW"]

        print(f"  • HIGH confidence:   {len(high_conf)} (known patterns)")
        print(f"  • MEDIUM confidence: {len(med_conf)} (entropy or variable name)")
        print(f"  • LOW confidence:    {len(low_conf)}")

        print()
        print("=" * 80)
        print("Detailed Report (First 3):")
        print("=" * 80)

        print(formatter.format(findings[:3]))

    print()
    print("=" * 80)
    print("✅ Smart Secret Detection Features:")
    print("=" * 80)
    print()
    print("1. Known Pattern Detection (HIGH confidence)")
    print("   • AWS Access Keys (AKIA...)")
    print("   • GitHub Tokens (ghp_...)")
    print("   • Slack Tokens (xoxb-...)")
    print("   • Stripe Keys (sk_live_...)")
    print("   • Google API Keys (AIza...)")
    print("   • JWT Tokens")
    print("   • And more!")
    print()
    print("2. Entropy Analysis (MEDIUM confidence)")
    print("   • Detects high-randomness strings")
    print("   • Configurable thresholds")
    print()
    print("3. Variable Name Patterns (MEDIUM confidence)")
    print("   • api_key, password, secret, token, etc.")
    print()
    print("4. Smart Filtering")
    print("   • Skips test files automatically")
    print("   • Ignores obvious placeholders")
    print("   • Reduces false positives")
    print()
    print("=" * 80)

if __name__ == "__main__":
    main()
