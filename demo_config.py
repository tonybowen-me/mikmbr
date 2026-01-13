"""Demo script showcasing mikmbr configuration system."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mikmbr.scanner import Scanner
from mikmbr.formatters import HumanFormatter
from mikmbr.config import AiriskConfig

def main():
    print("=" * 80)
    print("mikmbr Configuration System Demo")
    print("=" * 80)
    print()

    # Demo 1: Default Configuration
    print("1. DEFAULT CONFIGURATION")
    print("-" * 80)
    print("Without any config file, mikmbr uses sensible defaults:")
    print()

    default_config = AiriskConfig()
    print(f"  • Version: {default_config.version}")
    print(f"  • Output format: {default_config.output.format}")
    print(f"  • Verbose: {default_config.output.verbose}")
    print(f"  • Secret detection enabled: {default_config.secret_detection.enabled}")
    print(f"  • Entropy min threshold: {default_config.secret_detection.entropy['min_entropy']}")
    print(f"  • Max file size: {default_config.scan.max_file_size_kb} KB")
    print()

    # Demo 2: Load Configuration from YAML
    print("=" * 80)
    print("2. LOADING CONFIGURATION FROM YAML")
    print("-" * 80)

    config_file = Path(__file__).parent / "examples" / ".mikmbr.yaml"
    if config_file.exists():
        print(f"Loading config from: {config_file}")
        print()

        config = AiriskConfig.from_file(config_file)

        print("Loaded settings:")
        print(f"  • Version: {config.version}")
        print(f"  • Output format: {config.output.format}")
        print(f"  • Verbose: {config.output.verbose}")
        print()

        # Show rule configurations
        print("Rule settings:")
        if 'REGEX_DOS' in config.rules:
            print(f"  • REGEX_DOS enabled: {config.rules['REGEX_DOS'].enabled}")

        print()
        print(f"Secret detection entropy threshold: {config.secret_detection.entropy.get('min_entropy', 3.5)}")
        print()
    else:
        print(f"  ⚠ Config file not found: {config_file}")
        print()

    # Demo 3: Configuration Discovery
    print("=" * 80)
    print("3. AUTOMATIC CONFIG DISCOVERY")
    print("-" * 80)
    print("mikmbr automatically searches for .mikmbr.yaml in parent directories")
    print()

    found_config = AiriskConfig.find_config_file(Path.cwd())
    if found_config:
        print(f"  ✓ Found config at: {found_config}")
    else:
        print("  • No config file found in directory tree")
    print()

    # Demo 4: Scanning with Configuration
    print("=" * 80)
    print("4. SCANNING WITH CUSTOM CONFIGURATION")
    print("-" * 80)
    print()

    # Create custom configuration
    custom_config = AiriskConfig.from_dict({
        'secret_detection': {
            'entropy': {
                'min_entropy': 3.0,  # More sensitive
                'min_length': 16
            },
            'custom_placeholders': ['my_test_key']
        },
        'output': {
            'verbose': True
        }
    })

    print("Custom configuration:")
    print(f"  • Entropy threshold: {custom_config.secret_detection.entropy['min_entropy']}")
    print(f"  • Minimum length: {custom_config.secret_detection.entropy['min_length']}")
    print(f"  • Custom placeholders: {custom_config.secret_detection.custom_placeholders}")
    print()

    # Scan example file with custom config
    example_file = Path(__file__).parent / "examples" / "secrets_demo.py"

    if example_file.exists():
        print(f"Scanning {example_file.name} with custom configuration...")
        print()

        scanner = Scanner(config=custom_config)
        findings = scanner.scan_file(str(example_file))

        print(f"Found {len(findings)} secret(s)")
        print()

        # Group by confidence
        high_conf = [f for f in findings if f.confidence.value == "HIGH"]
        med_conf = [f for f in findings if f.confidence.value == "MEDIUM"]

        print(f"  • HIGH confidence:   {len(high_conf)}")
        print(f"  • MEDIUM confidence: {len(med_conf)}")
        print()

    # Demo 5: Disabling Rules
    print("=" * 80)
    print("5. DISABLING SPECIFIC RULES")
    print("-" * 80)
    print()

    disabled_config = AiriskConfig.from_dict({
        'rules': {
            'DANGEROUS_EXEC': False,
            'COMMAND_INJECTION': False,
            'REGEX_DOS': False
        }
    })

    print("Rules disabled in configuration:")
    for rule_id in ['DANGEROUS_EXEC', 'COMMAND_INJECTION', 'REGEX_DOS']:
        enabled = disabled_config.is_rule_enabled(rule_id)
        status = "✓ Enabled" if enabled else "✗ Disabled"
        print(f"  {status}: {rule_id}")
    print()

    print("Rules not mentioned in config (default to enabled):")
    for rule_id in ['SQL_INJECTION', 'HARDCODED_SECRETS']:
        enabled = disabled_config.is_rule_enabled(rule_id)
        status = "✓ Enabled" if enabled else "✗ Disabled"
        print(f"  {status}: {rule_id}")
    print()

    # Demo 6: Example Configuration File
    print("=" * 80)
    print("6. EXAMPLE CONFIGURATION FILE")
    print("-" * 80)
    print()
    print("Create .mikmbr.yaml in your project root:")
    print()
    print("""
# .mikmbr.yaml
version: "1.4"

# Disable specific rules
rules:
  REGEX_DOS: false
  INSECURE_RANDOM: false

# Configure secret detection
secret_detection:
  entropy:
    min_entropy: 3.0     # More sensitive
    min_length: 16
  custom_placeholders:
    - "my_test_key"
    - "company_placeholder"

# Output settings
output:
  format: human
  verbose: true
  color: true

# Scan settings
scan:
  exclude_patterns:
    - "*.pyc"
    - "build/*"
    - "dist/*"
  max_file_size_kb: 2048
    """.strip())
    print()

    print("=" * 80)
    print("Configuration Features:")
    print("=" * 80)
    print()
    print("✓ Rule enable/disable")
    print("✓ Severity overrides")
    print("✓ Entropy thresholds")
    print("✓ Custom placeholders")
    print("✓ Path exclusions")
    print("✓ Output formatting")
    print("✓ File size limits")
    print("✓ Automatic discovery")
    print("✓ CLI overrides")
    print()
    print("For more info, see: .mikmbr.yaml in the project root")
    print()

if __name__ == "__main__":
    main()
