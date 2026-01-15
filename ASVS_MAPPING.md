# OWASP ASVS 4.0 Coverage Mapping

**Last Updated:** 2025-01-14
**Mikmbr Version:** 1.8.0
**ASVS Version:** 4.0.3

---

## Overview

Mikmbr's detection rules are mapped to [OWASP Application Security Verification Standard (ASVS) 4.0](https://owasp.org/www-project-application-security-verification-standard/) requirements. ASVS provides a comprehensive framework with **286 verification requirements** across **14 categories**.

**Current Coverage:** 24 rules covering **35+ ASVS requirements** (~12% coverage)

---

## Rule to ASVS Mapping

### ✅ V2: Authentication Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| HARDCODED_SECRET | HIGH | V2.1.1 | Verify user passwords are at least 12 characters |
| HARDCODED_SECRET | HIGH | V2.10.4 | Verify service accounts use key-based authentication |
| WEAK_PASSWORD_HASH | HIGH | V2.4.1 | Verify passwords are stored with approved hash function |
| JWT_SECURITY | HIGH | V2.8.7 | Verify JWT, OAuth tokens properly validated |
| SESSION_SECURITY | MEDIUM | V3.2.1 | Verify sessions bind to user context |

**Coverage:** 5 rules → 5+ requirements

---

### ✅ V3: Session Management Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| SESSION_SECURITY | MEDIUM | V3.3.1 | Verify logout and session expiration |
| INSECURE_COOKIE | MEDIUM | V3.4.1 | Verify cookie-based session tokens have Secure flag |
| INSECURE_COOKIE | MEDIUM | V3.4.2 | Verify cookie-based session tokens have HttpOnly flag |
| TIMING_ATTACK | MEDIUM | V3.7.1 | Verify session token comparisons constant-time |

**Coverage:** 3 rules → 4+ requirements

---

### ✅ V4: Access Control Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| PATH_TRAVERSAL | HIGH | V4.1.3 | Verify principle of least privilege enforced |
| DJANGO_SECURITY | MEDIUM | V4.2.1 | Verify access control enforced on server |
| FLASK_SECURITY | MEDIUM | V4.2.1 | Verify access control enforced on server |
| FASTAPI_SECURITY | MEDIUM | V4.2.1 | Verify access control enforced on server |

**Coverage:** 4 rules → 2+ requirements

---

### ✅ V5: Validation, Sanitization and Encoding

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| SQL_INJECTION | HIGH | V5.3.4 | Verify SQL queries use parameterized queries |
| COMMAND_INJECTION | HIGH | V5.3.8 | Verify OS command execution escapes arguments |
| TEMPLATE_INJECTION | CRITICAL | V5.2.2 | Verify application sanitizes user input |
| XXE | HIGH | V5.5.2 | Verify XML parsers configured securely |
| INSECURE_DESERIALIZATION | HIGH | V5.5.3 | Verify deserialization not used on untrusted data |
| LOG_INJECTION | MEDIUM | V5.3.1 | Verify output encoding for log statements |
| OPEN_REDIRECT | MEDIUM | V5.1.5 | Verify URL redirects/forwards validated |
| DANGEROUS_EXEC | HIGH | V5.2.8 | Verify dynamic code execution disabled |

**Coverage:** 8 rules → 8+ requirements

---

### ✅ V6: Stored Cryptography Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| WEAK_CRYPTO | MEDIUM | V6.2.1 | Verify approved cryptographic algorithms |
| WEAK_CRYPTO | MEDIUM | V6.2.2 | Verify strong random number generation |
| INSECURE_RANDOM | HIGH | V6.3.1 | Verify cryptographically secure random values |
| INSECURE_RANDOM | HIGH | V6.3.2 | Verify GUIDs use cryptographic PRNG |
| HARDCODED_SECRET | HIGH | V6.4.1 | Verify secrets stored securely |
| HARDCODED_SECRET | HIGH | V6.4.2 | Verify secret keys not hardcoded |

**Coverage:** 3 rules → 6+ requirements

---

### ✅ V7: Error Handling and Logging

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| LOG_INJECTION | MEDIUM | V7.1.1 | Verify log injection attacks prevented |
| DEBUG_CODE | MEDIUM | V7.4.1 | Verify debug code removed from production |
| DEBUG_CODE | MEDIUM | V7.4.2 | Verify exception handling doesn't disclose sensitive info |
| BARE_EXCEPT | LOW | V7.4.1 | Verify generic error messages |
| DJANGO_SECURITY | MEDIUM | V7.4.3 | Verify DEBUG mode disabled in production |
| FLASK_SECURITY | MEDIUM | V7.4.3 | Verify DEBUG mode disabled in production |

**Coverage:** 4 rules → 4+ requirements

---

### ✅ V8: Data Protection Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| HARDCODED_SECRET | HIGH | V8.3.4 | Verify sensitive data not logged |
| TIMING_ATTACK | MEDIUM | V8.3.7 | Verify sensitive comparisons are time-constant |

**Coverage:** 2 rules → 2+ requirements

---

### ✅ V9: Communications Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| (Future: SSL_VERIFICATION) | HIGH | V9.1.2 | Verify TLS used for all connections |
| (Future: SSL_VERIFICATION) | HIGH | V9.2.1 | Verify TLS properly configured |

**Coverage:** 0 rules → 0 requirements (Gap identified)

---

### ✅ V10: Malicious Code Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| DANGEROUS_EXEC | HIGH | V10.2.1 | Verify application doesn't execute unsanitized code |
| INSECURE_DESERIALIZATION | HIGH | V10.2.2 | Verify application protected from template injection |

**Coverage:** 2 rules → 2+ requirements

---

### ✅ V11: Business Logic Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| REGEX_DOS | MEDIUM | V11.1.4 | Verify business logic flows protected from automated attacks |

**Coverage:** 1 rule → 1 requirement

---

### ✅ V12: File and Resources Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| PATH_TRAVERSAL | HIGH | V12.1.1 | Verify file upload validates filename |
| PATH_TRAVERSAL | HIGH | V12.1.2 | Verify uploaded files not directly executable |
| FLASK_SECURITY | HIGH | V12.5.1 | Verify file download prevents path traversal |
| DJANGO_SECURITY | HIGH | V12.5.1 | Verify file download prevents path traversal |
| SSRF | HIGH | V12.6.1 | Verify URL passed to system protected from SSRF |

**Coverage:** 3 rules → 5+ requirements

---

### ✅ V13: API and Web Service Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| DJANGO_SECURITY | HIGH | V13.1.1 | Verify API authentication applied |
| FLASK_SECURITY | MEDIUM | V13.1.3 | Verify RESTful services protected from CSRF |
| FASTAPI_SECURITY | HIGH | V13.2.1 | Verify API input validation |

**Coverage:** 3 rules → 3+ requirements

---

### ✅ V14: Configuration Verification

| Rule ID | Severity | ASVS Requirement | Description |
|---------|----------|------------------|-------------|
| VULN_DEPENDENCY | varies | V14.2.1 | Verify components, libraries up to date |
| DEBUG_CODE | MEDIUM | V14.3.3 | Verify debug modes disabled |
| DJANGO_SECURITY | HIGH | V14.4.1 | Verify HTTP security headers present |
| DJANGO_SECURITY | HIGH | V14.5.3 | Verify allowed hosts configured |

**Coverage:** 2 rules (+ dep scanning) → 4+ requirements

---

## Coverage Summary

| ASVS Category | Rules | Requirements Covered | Status |
|---------------|-------|---------------------|---------|
| V1: Architecture | 0 | 0/14 subsections | ❌ Gap |
| V2: Authentication | 5 | ~5 requirements | ✅ Partial |
| V3: Session Management | 3 | ~4 requirements | ✅ Partial |
| V4: Access Control | 4 | ~2 requirements | ⚠️ Limited |
| V5: Validation & Encoding | 8 | ~8 requirements | ✅ Good |
| V6: Cryptography | 3 | ~6 requirements | ✅ Good |
| V7: Error Handling | 4 | ~4 requirements | ✅ Partial |
| V8: Data Protection | 2 | ~2 requirements | ⚠️ Limited |
| V9: Communications | 0 | 0 requirements | ❌ Gap |
| V10: Malicious Code | 2 | ~2 requirements | ✅ Partial |
| V11: Business Logic | 1 | ~1 requirement | ⚠️ Limited |
| V12: Files & Resources | 3 | ~5 requirements | ✅ Partial |
| V13: API Security | 3 | ~3 requirements | ✅ Partial |
| V14: Configuration | 2 | ~4 requirements | ✅ Partial |

**Total:** 24 rules covering ~35-40 of 286 ASVS requirements (**~14% coverage**)

---

## Priority Gaps (Roadmap)

### 🔴 Critical Gaps

1. **V9: Communications** - No TLS/SSL verification rules
2. **V1: Architecture** - No architectural security verification
3. **V4: Access Control** - Limited IDOR/authorization checking

### 🟡 Important Gaps

4. **V5.1: Input Validation** - Missing comprehensive input validation
5. **V5.3: Output Encoding** - Limited XSS detection
6. **V8: Data Protection** - Missing client-side data protection

### 🟢 Enhancement Opportunities

7. **V11: Business Logic** - Rate limiting, anti-automation
8. **V13: API Security** - GraphQL, REST API security
9. **V2: Authentication** - MFA, OAuth flows

---

## Roadmap to 50% ASVS Coverage

**Target:** 143 of 286 requirements (50% coverage) by v2.0

### Phase 1: Communications & TLS (v1.9)
- Add SSL/TLS verification rules
- HTTPS enforcement detection
- Certificate validation checks
- **+10 requirements** → 18% coverage

### Phase 2: XSS & Output Encoding (v1.9)
- Comprehensive XSS detection
- HTML/JavaScript output encoding
- DOM-based XSS patterns
- **+8 requirements** → 21% coverage

### Phase 3: Access Control & IDOR (v1.10)
- Direct object reference detection
- Authorization bypass patterns
- Privilege escalation checks
- **+15 requirements** → 26% coverage

### Phase 4: API Security (v1.10)
- GraphQL injection
- REST API enumeration
- API rate limiting
- **+12 requirements** → 30% coverage

### Continue with systematic coverage expansion...

---

## Using ASVS in Mikmbr

### Future: ASVS IDs in Output

```python
[HIGH] app.py:42
  Rule: SQL_INJECTION
  CWE: CWE-89
  OWASP: A03:2021 - Injection
  ASVS: V5.3.4  # Coming soon!
```

### Future: ASVS Coverage Reports

```bash
mikmbr scan . --asvs-report
# Generates ASVS coverage report showing which requirements are verified
```

---

## References

- [OWASP ASVS Project](https://owasp.org/www-project-application-security-verification-standard/)
- [ASVS 4.0.3 on GitHub](https://github.com/OWASP/ASVS)
- [ASVS Index - OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/IndexASVS.html)
- [OWASP ASVS Explained - Aikido](https://www.aikido.dev/learn/compliance/compliance-frameworks/owasp-asvs)

---

**Note:** This mapping will be continuously updated as new rules are added and ASVS evolves (v5.0 was released in 2025).
