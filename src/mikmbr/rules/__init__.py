"""Detection rules for security vulnerabilities."""

from .base import Rule
from .dangerous_exec import DangerousExecRule
from .command_injection import CommandInjectionRule
from .sql_injection import SQLInjectionRule
from .weak_crypto import WeakCryptoRule
from .hardcoded_secrets import HardcodedSecretsRule
from .insecure_deserialization import InsecureDeserializationRule
from .path_traversal import PathTraversalRule
from .insecure_random import InsecureRandomRule
from .regex_dos import RegexDosRule
from .xxe import XXERule
from .ssrf import SSRFRule
from .open_redirect import OpenRedirectRule
from .log_injection import LogInjectionRule
from .template_injection import TemplateInjectionRule
from .timing_attack import TimingAttackRule
from .bare_except import BareExceptRule
from .debug_code import DebugCodeRule

# Registry of all available rules
ALL_RULES = [
    DangerousExecRule(),
    CommandInjectionRule(),
    SQLInjectionRule(),
    WeakCryptoRule(),
    HardcodedSecretsRule(),
    InsecureDeserializationRule(),
    PathTraversalRule(),
    InsecureRandomRule(),
    RegexDosRule(),
    XXERule(),
    SSRFRule(),
    OpenRedirectRule(),
    LogInjectionRule(),
    TemplateInjectionRule(),
    TimingAttackRule(),
    BareExceptRule(),
    DebugCodeRule(),
]

__all__ = [
    "Rule",
    "ALL_RULES",
    "DangerousExecRule",
    "CommandInjectionRule",
    "SQLInjectionRule",
    "WeakCryptoRule",
    "HardcodedSecretsRule",
    "InsecureDeserializationRule",
    "PathTraversalRule",
    "InsecureRandomRule",
    "RegexDosRule",
    "XXERule",
    "SSRFRule",
    "OpenRedirectRule",
]
