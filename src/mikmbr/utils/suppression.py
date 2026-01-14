"""Suppression comment parsing utilities."""

import re
from typing import Set, Optional


class SuppressionParser:
    """Parse and manage inline suppression comments."""

    # Supported formats:
    # # mikmbr: ignore
    # # mikmbr: ignore[RULE_ID]
    # # mikmbr: ignore[RULE_ID,OTHER_RULE]
    INLINE_PATTERN = re.compile(
        r'#\s*mikmbr:\s*ignore(?:\[([^\]]+)\])?',
        re.IGNORECASE
    )

    # Block suppression:
    # # mikmbr: disable
    # # mikmbr: enable
    DISABLE_PATTERN = re.compile(r'#\s*mikmbr:\s*disable', re.IGNORECASE)
    ENABLE_PATTERN = re.compile(r'#\s*mikmbr:\s*enable', re.IGNORECASE)

    def __init__(self, source: str):
        """
        Initialize suppression parser with source code.

        Args:
            source: Source code text
        """
        self.source = source
        self.lines = source.splitlines()
        self._parse_suppressions()

    def _parse_suppressions(self):
        """Parse all suppression comments in source."""
        self.inline_suppressions = {}  # line -> set of rule_ids (or None for all)
        self.block_disabled_ranges = []  # List of (start_line, end_line) tuples

        # Track block disable/enable
        disabled_start = None

        for line_num, line in enumerate(self.lines, start=1):
            # Check for block disable/enable
            if self.DISABLE_PATTERN.search(line):
                if disabled_start is None:
                    disabled_start = line_num
            elif self.ENABLE_PATTERN.search(line):
                if disabled_start is not None:
                    self.block_disabled_ranges.append((disabled_start, line_num))
                    disabled_start = None

            # Check for inline suppression
            match = self.INLINE_PATTERN.search(line)
            if match:
                rule_ids_str = match.group(1)
                if rule_ids_str:
                    # Specific rules to ignore
                    rule_ids = {r.strip().upper() for r in rule_ids_str.split(',')}
                    self.inline_suppressions[line_num] = rule_ids
                else:
                    # Ignore all rules on this line
                    self.inline_suppressions[line_num] = None

        # If disable without enable, treat rest of file as disabled
        if disabled_start is not None:
            self.block_disabled_ranges.append((disabled_start, len(self.lines) + 1))

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        """
        Check if a finding should be suppressed.

        Args:
            line: Line number (1-indexed)
            rule_id: Rule identifier (e.g., 'SQL_INJECTION')

        Returns:
            True if the finding should be suppressed
        """
        if line is None:
            return False

        rule_id = rule_id.upper()

        # Check inline suppression on the same line
        if line in self.inline_suppressions:
            suppressed_rules = self.inline_suppressions[line]
            # None means suppress all rules on this line
            if suppressed_rules is None:
                return True
            # Check if this specific rule is suppressed
            if rule_id in suppressed_rules:
                return True

        # Check inline suppression on the previous line (common pattern)
        prev_line = line - 1
        if prev_line in self.inline_suppressions:
            suppressed_rules = self.inline_suppressions[prev_line]
            if suppressed_rules is None:
                return True
            if rule_id in suppressed_rules:
                return True

        # Check if line is in a disabled block
        for start, end in self.block_disabled_ranges:
            if start <= line <= end:
                return True

        return False

    def get_suppression_stats(self) -> dict:
        """
        Get statistics about suppressions in the source.

        Returns:
            Dictionary with suppression statistics
        """
        return {
            "inline_suppressions": len(self.inline_suppressions),
            "block_suppressions": len(self.block_disabled_ranges),
            "total_lines_suppressed": sum(
                end - start + 1 for start, end in self.block_disabled_ranges
            ),
        }
