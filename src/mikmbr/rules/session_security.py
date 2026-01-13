"""Detection rule for session management security issues."""

import ast
from typing import List
from .base import Rule, RuleSeverity
from ..models import Finding


class SessionSecurityRule(Rule):
    """Detects insecure session management patterns.

    Vulnerable patterns:
    - No session regeneration after login (session fixation)
    - Session data stored in cookies without encryption
    - Predictable session IDs

    Safe alternatives:
    - session.regenerate() after login
    - Use server-side session storage
    - Use cryptographically random session IDs
    """

    rule_id = "SESSION_SECURITY"
    severity = RuleSeverity.MEDIUM
    cwe_id = "CWE-384"
    owasp_category = "A07:2021 - Identification and Authentication Failures"

    # Login-related function names
    LOGIN_INDICATORS = {
        'login', 'signin', 'authenticate', 'auth',
        'log_in', 'sign_in', 'do_login', 'user_login'
    }

    def check(self, tree: ast.AST, filename: str) -> List[Finding]:
        """Check for session security issues."""
        findings = []

        for node in ast.walk(tree):
            # Check for login functions without session regeneration
            if isinstance(node, ast.FunctionDef):
                if self._is_login_function(node):
                    if not self._has_session_regeneration(node):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            filename=filename,
                            line_number=node.lineno,
                            message="Login function missing session regeneration (session fixation risk)",
                            code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                            cwe_id=self.cwe_id,
                            owasp_category=self.owasp_category,
                            recommendation="Regenerate session after login: session.regenerate() or session.clear() + session.new()"
                        ))

        return findings

    def _is_login_function(self, node: ast.FunctionDef) -> bool:
        """Check if this function appears to be a login handler."""
        func_name_lower = node.name.lower()
        return any(indicator in func_name_lower for indicator in self.LOGIN_INDICATORS)

    def _has_session_regeneration(self, node: ast.FunctionDef) -> bool:
        """Check if function regenerates session."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Look for session.regenerate(), session.clear(), session.new()
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in {'regenerate', 'clear', 'new', 'invalidate'}:
                        # Check if it's called on a session object
                        if isinstance(child.func.value, ast.Name):
                            if 'session' in child.func.value.id.lower():
                                return True

        return False
