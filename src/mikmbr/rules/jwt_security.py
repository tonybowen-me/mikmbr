"""Detection rule for JWT security issues."""

import ast
from typing import List
from .base import Rule
from ..models import Finding, Severity


class JWTSecurityRule(Rule):
    """Detects insecure JWT configurations.

    Vulnerable patterns:
    - jwt.encode(payload, algorithm='none')  # No signing
    - jwt.encode(payload, 'weak_secret')  # Weak secret
    - jwt.decode(token, verify=False)  # No verification
    - jwt.decode(token, algorithms=['HS256', 'none'])  # Algorithm confusion

    Safe alternatives:
    - jwt.encode(payload, strong_secret, algorithm='HS256')
    - jwt.decode(token, secret, algorithms=['HS256'])
    """

    rule_id = "JWT_SECURITY"
    severity = Severity.HIGH
    cwe_id = "CWE-347"
    owasp_category = "A02:2021 - Cryptographic Failures"

    WEAK_ALGORITHMS = {'none', 'HS256'}  # HS256 can be vulnerable to algorithm confusion
    WEAK_SECRETS = {'secret', 'password', '123456', 'test', 'key', 'jwt_secret'}

    def check(self, tree: ast.AST, filename: str) -> List[Finding]:
        """Check for JWT security issues."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check jwt.encode() calls
                if self._is_jwt_encode(node):
                    finding = self._check_jwt_encode(node, filename)
                    if finding:
                        findings.append(finding)

                # Check jwt.decode() calls
                elif self._is_jwt_decode(node):
                    finding = self._check_jwt_decode(node, filename)
                    if finding:
                        findings.append(finding)

        return findings

    def _is_jwt_encode(self, node: ast.Call) -> bool:
        """Check if this is a jwt.encode() call."""
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'jwt' and
                node.func.attr == 'encode'):
                return True
        return False

    def _is_jwt_decode(self, node: ast.Call) -> bool:
        """Check if this is a jwt.decode() call."""
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'jwt' and
                node.func.attr == 'decode'):
                return True
        return False

    def _check_jwt_encode(self, node: ast.Call, filename: str) -> Finding:
        """Check jwt.encode() for security issues."""
        kwargs = {kw.arg: kw.value for kw in node.keywords}

        # Check for 'none' algorithm
        if 'algorithm' in kwargs:
            if isinstance(kwargs['algorithm'], ast.Constant):
                if kwargs['algorithm'].value in self.WEAK_ALGORITHMS:
                    return Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        filename=filename,
                        line_number=node.lineno,
                        message=f"JWT uses insecure algorithm: {kwargs['algorithm'].value}",
                        code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                        cwe_id=self.cwe_id,
                        owasp_category=self.owasp_category,
                        recommendation="Use a strong algorithm like RS256 or ES256 for production"
                    )

        # Check for weak secret (if it's a string literal)
        if len(node.args) >= 2:
            secret_arg = node.args[1]
            if isinstance(secret_arg, ast.Constant) and isinstance(secret_arg.value, str):
                if secret_arg.value.lower() in self.WEAK_SECRETS or len(secret_arg.value) < 32:
                    return Finding(
                        rule_id=self.rule_id,
                        severity=Severity.HIGH,
                        filename=filename,
                        line_number=node.lineno,
                        message="JWT uses weak or hardcoded secret",
                        code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                        cwe_id=self.cwe_id,
                        owasp_category=self.owasp_category,
                        recommendation="Use a strong secret from environment variables (>= 32 chars): secret = os.getenv('JWT_SECRET')"
                    )

        return None

    def _check_jwt_decode(self, node: ast.Call, filename: str) -> Finding:
        """Check jwt.decode() for security issues."""
        kwargs = {kw.arg: kw.value for kw in node.keywords}

        # Check for verify=False
        if 'verify' in kwargs:
            if isinstance(kwargs['verify'], ast.Constant):
                if not kwargs['verify'].value:  # verify=False
                    return Finding(
                        rule_id=self.rule_id,
                        severity=Severity.CRITICAL,
                        filename=filename,
                        line_number=node.lineno,
                        message="JWT signature verification disabled",
                        code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                        cwe_id=self.cwe_id,
                        owasp_category=self.owasp_category,
                        recommendation="Always verify JWT signatures: jwt.decode(token, secret, algorithms=['HS256'])"
                    )

        # Check for algorithm confusion (allowing 'none')
        if 'algorithms' in kwargs:
            if isinstance(kwargs['algorithms'], ast.List):
                for alg in kwargs['algorithms'].elts:
                    if isinstance(alg, ast.Constant) and alg.value == 'none':
                        return Finding(
                            rule_id=self.rule_id,
                            severity=Severity.CRITICAL,
                            filename=filename,
                            line_number=node.lineno,
                            message="JWT allows 'none' algorithm - algorithm confusion vulnerability",
                            code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                            cwe_id=self.cwe_id,
                            owasp_category=self.owasp_category,
                            recommendation="Explicitly whitelist only strong algorithms: algorithms=['HS256'] or ['RS256']"
                        )

        return None
