"""Output formatters for scan results."""

import json
from typing import List

from .models import Finding


class Formatter:
    """Base formatter class."""

    def __init__(self, verbose: bool = False):
        """Initialize formatter with verbosity setting."""
        self.verbose = verbose

    def format(self, findings: List[Finding]) -> str:
        """Format findings for output."""
        raise NotImplementedError


class HumanFormatter(Formatter):
    """Human-readable output formatter."""

    def format(self, findings: List[Finding]) -> str:
        """Format findings in a human-readable format."""
        if not findings:
            return "No security issues found."

        lines = []
        lines.append(f"\nFound {len(findings)} security issue(s):\n")

        for finding in findings:
            lines.append(f"[{finding.severity.value}] {finding.file}:{finding.line or '?'}")
            lines.append(f"  Rule: {finding.rule_id}")

            if self.verbose and finding.confidence:
                lines.append(f"  Confidence: {finding.confidence.value}")

            if self.verbose and finding.cwe_id:
                lines.append(f"  CWE: {finding.cwe_id}")

            if self.verbose and finding.owasp_category:
                lines.append(f"  OWASP: {finding.owasp_category}")

            lines.append(f"  Issue: {finding.message}")
            lines.append(f"  Fix: {finding.remediation}")

            # Show code snippet in verbose mode
            if self.verbose and finding.code_snippet:
                lines.append(f"  Code:")
                for snippet_line in finding.code_snippet.split('\n'):
                    lines.append(f"    {snippet_line}")

            # Show references in verbose mode
            if self.verbose and finding.references:
                lines.append(f"  References:")
                for ref in finding.references:
                    lines.append(f"    - {ref}")

            lines.append("")

        return "\n".join(lines)


class JSONFormatter(Formatter):
    """JSON output formatter."""

    def format(self, findings: List[Finding]) -> str:
        """Format findings as JSON."""
        data = {
            "findings": [f.to_dict() for f in findings],
            "total": len(findings),
        }
        return json.dumps(data, indent=2)


def get_formatter(format_type: str, verbose: bool = False) -> Formatter:
    """Get formatter by type."""
    if format_type == "json":
        return JSONFormatter(verbose=verbose)
    elif format_type == "human":
        return HumanFormatter(verbose=verbose)
    else:
        raise ValueError(f"Unknown format: {format_type}")
