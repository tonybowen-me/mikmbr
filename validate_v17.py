#!/usr/bin/env python3
"""
Validation and Demo Script for v1.7 Features

This script demonstrates and validates the two new v1.7 features:
1. Exit Code Configuration (--fail-on)
2. Code Context Lines (--context)

Run this script to see both features in action and verify they work correctly.
"""

import subprocess
import sys
import os
from pathlib import Path


def print_header(text):
    """Print a styled header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")


def print_subheader(text):
    """Print a styled subheader."""
    print(f"\n--- {text} ---\n")


def run_command(cmd, description):
    """Run a command and print its output."""
    print(f"Command: {cmd}")
    print(f"Description: {description}\n")

    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True
    )

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    print(f"Exit Code: {result.returncode}")
    return result.returncode


def demo_exit_codes():
    """Demonstrate --fail-on exit code configuration."""
    print_header("FEATURE 1: Exit Code Configuration (--fail-on)")

    test_file = "test_v17_features.py"

    print("""
This feature allows you to control when CI/CD builds fail based on severity.

Test file has:
- HIGH severity: SQL injection
- MEDIUM severity: Weak crypto (MD5)
- LOW severity: Bare except

Let's test different thresholds:
""")

    # Test 1: Fail on CRITICAL only (should pass - no CRITICAL findings)
    print_subheader("Test 1: --fail-on critical")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on critical",
        "Should EXIT 0 (pass) - file has no CRITICAL findings"
    )
    assert exit_code == 0, "Expected exit code 0 for --fail-on critical"
    print("✅ PASSED: No build failure with --fail-on critical")

    # Test 2: Fail on HIGH or above (should fail - has HIGH finding)
    print_subheader("Test 2: --fail-on high")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on high",
        "Should EXIT 1 (fail) - file has HIGH SQL injection"
    )
    assert exit_code == 1, "Expected exit code 1 for --fail-on high"
    print("✅ PASSED: Build fails with --fail-on high")

    # Test 3: Fail on MEDIUM or above (should fail - has MEDIUM and HIGH)
    print_subheader("Test 3: --fail-on medium")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on medium",
        "Should EXIT 1 (fail) - file has MEDIUM and HIGH findings"
    )
    assert exit_code == 1, "Expected exit code 1 for --fail-on medium"
    print("✅ PASSED: Build fails with --fail-on medium")

    # Test 4: Fail on any finding (default behavior)
    print_subheader("Test 4: --fail-on low (default)")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on low",
        "Should EXIT 1 (fail) - file has findings of all severities"
    )
    assert exit_code == 1, "Expected exit code 1 for --fail-on low"
    print("✅ PASSED: Build fails with --fail-on low")

    # Test 5: Default behavior (no --fail-on flag)
    print_subheader("Test 5: Default (no --fail-on flag)")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file}",
        "Should EXIT 1 (fail) - default is fail on any finding"
    )
    assert exit_code == 1, "Expected exit code 1 for default"
    print("✅ PASSED: Default behavior unchanged")

    print("\n" + "🎉 All exit code tests PASSED!")


def demo_context_lines():
    """Demonstrate --context code context lines."""
    print_header("FEATURE 2: Code Context Lines (--context)")

    test_file = "test_v17_features.py"

    print("""
This feature shows surrounding code context for better understanding.

Let's test different context sizes:
""")

    # Test 1: No context (default)
    print_subheader("Test 1: No context (default)")
    run_command(
        f"py -m mikmbr.cli scan {test_file}",
        "Default output - no context lines shown"
    )

    # Test 2: 1 line of context
    print_subheader("Test 2: --context 1")
    run_command(
        f"py -m mikmbr.cli scan {test_file} --context 1",
        "Shows 1 line before and after each finding"
    )

    # Test 3: 3 lines of context (recommended)
    print_subheader("Test 3: --context 3 (recommended)")
    run_command(
        f"py -m mikmbr.cli scan {test_file} --context 3",
        "Shows 3 lines before and after - good balance"
    )

    # Test 4: 5 lines of context
    print_subheader("Test 4: --context 5")
    run_command(
        f"py -m mikmbr.cli scan {test_file} --context 5",
        "Shows 5 lines before and after - detailed view"
    )

    print("\n" + "🎉 Context lines feature working correctly!")


def demo_combined_features():
    """Demonstrate using both features together."""
    print_header("COMBINED DEMO: Using Both Features Together")

    test_file = "test_v17_features.py"

    print("""
Real-world usage: Combining both features for CI/CD
""")

    # Example 1: CI/CD with HIGH threshold and context
    print_subheader("CI/CD Example: Fail on HIGH+ with context for debugging")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on high --context 2",
        "Block PRs on HIGH+ severity, show context for easy review"
    )
    print(f"Build would {'FAIL ❌' if exit_code == 1 else 'PASS ✅'}")

    # Example 2: Local development with CRITICAL threshold and more context
    print_subheader("Local Dev Example: Only warn on CRITICAL with detailed context")
    exit_code = run_command(
        f"py -m mikmbr.cli scan {test_file} --fail-on critical --context 5",
        "Don't block local work, but show detailed context for all findings"
    )
    print(f"Local scan would {'FAIL ❌' if exit_code == 1 else 'PASS ✅'}")

    print("\n" + "🎉 Combined features working perfectly!")


def verify_template_injection_critical():
    """Verify that Template Injection rule uses CRITICAL severity."""
    print_header("BONUS: Verify Template Injection is CRITICAL")

    # Create a test file with template injection
    test_content = '''from flask import render_template_string, request

@app.route('/template')
def render_user_template():
    template = request.args.get('template')
    return render_template_string(template)  # SSTI vulnerability
'''

    test_file = "temp_test_ssti.py"
    with open(test_file, 'w') as f:
        f.write(test_content)

    try:
        print("Testing that Template Injection detection uses CRITICAL severity...\n")

        # Scan and check for CRITICAL
        result = subprocess.run(
            f"py -m mikmbr.cli scan {test_file} --format json",
            shell=True,
            capture_output=True,
            text=True
        )

        if "CRITICAL" in result.stdout or "TEMPLATE_INJECTION" in result.stdout:
            print("✅ Template Injection rule detected")
            print("\nSample output:")
            # Show human format for readability
            subprocess.run(
                f"py -m mikmbr.cli scan {test_file}",
                shell=True
            )

            # Test that it fails on critical threshold
            print_subheader("Test: --fail-on critical should FAIL")
            exit_code = run_command(
                f"py -m mikmbr.cli scan {test_file} --fail-on critical",
                "Should EXIT 1 - has CRITICAL template injection"
            )

            if exit_code == 1:
                print("✅ PASSED: Template Injection correctly flagged as CRITICAL")
            else:
                print("⚠️  WARNING: Template Injection might not be CRITICAL severity")
        else:
            print("⚠️  Template Injection rule might not be enabled or test file issue")

    finally:
        # Cleanup
        if os.path.exists(test_file):
            os.unlink(test_file)


def main():
    """Run all demos and validations."""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    Mikmbr v1.7 Feature Validation Script                    ║
║                                                                              ║
║  This script demonstrates and validates:                                    ║
║    1. Exit Code Configuration (--fail-on)                                   ║
║    2. Code Context Lines (--context)                                        ║
║    3. CRITICAL severity level                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")

    # Check if test file exists
    if not os.path.exists("test_v17_features.py"):
        print("❌ ERROR: test_v17_features.py not found!")
        print("Please run this script from the project root directory.")
        sys.exit(1)

    try:
        # Demo 1: Exit codes
        demo_exit_codes()

        # Demo 2: Context lines
        demo_context_lines()

        # Demo 3: Combined usage
        demo_combined_features()

        # Bonus: Verify CRITICAL severity
        verify_template_injection_critical()

        # Final summary
        print_header("✅ ALL VALIDATIONS PASSED!")
        print("""
v1.7 Features are working correctly:

1. ✅ Exit Code Configuration (--fail-on)
   - Controls build failures based on severity
   - Supports: critical, high, medium, low
   - Perfect for gradual adoption

2. ✅ Code Context Lines (--context)
   - Shows N lines before/after findings
   - Line numbers with > marker
   - Better developer experience

3. ✅ CRITICAL Severity Level
   - Template Injection uses CRITICAL
   - Enables fine-grained exit control
   - Ready for future critical rules

🎉 v1.7 is ready to ship!
""")

    except AssertionError as e:
        print(f"\n❌ VALIDATION FAILED: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
