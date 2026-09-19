"""Redaction and pseudonymization for anything bound for a hosted LLM.

Policy (also documented in docs/EVIDENCE_CONTEXT_ENGINE.md):

1. SECRETS are destroyed, never transformed back: passwords, tokens, secret
   keys, private keys, session tokens, bearer/JWT tokens, API keys, and
   credentials embedded in URLs. They become `[REDACTED_<KIND>]`. Nothing on
   the server can reverse them, because nothing needs to.

2. IDENTIFIERS that link evidence together but are personal or sensitive
   are PSEUDONYMIZED consistently: the same input always maps to the same
   token within one context, so the model can still follow an attacker
   across events.
       usernames / emails        -> USER_001, USER_002, ...
       AWS access key IDs        -> ACCESS_KEY_001, ...   (key ID never sent)
       AWS account IDs           -> AWS_ACCOUNT_001, ...
   The reverse map stays on the server (`Redactor.reverse`) and is NEVER
   serialized into the LLM payload. It exists only so a model recommendation
   such as "revoke ACCESS_KEY_002" can be turned back into a real, policy-
   gated response target.

3. Operational identifiers the investigation depends on are KEPT: hostnames,
   IP addresses (all synthetic RFC 5737 here), domains, process names, file
   hashes, role names, security-group / instance / bucket identifiers. Blindly
   deleting these would destroy the correlation the analysis rests on.

Every transformation increments a counter, so the context can report exactly
how many fields were redacted or pseudonymized.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

# Field names whose *values* are secrets regardless of content.
SECRET_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "password", "passwd", "pwd", "secret", "client_secret", "secret_access_key",
        "secretaccesskey", "aws_secret_access_key", "session_token", "sessiontoken",
        "token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
        "private_key", "privatekey", "credentials_secret", "authorization", "cookie",
    }
)

# Field names whose values are identifiers to pseudonymize (by kind).
PSEUDONYM_FIELDS: Final[dict[str, str]] = {
    "access_key_id": "ACCESS_KEY",
    "accesskeyid": "ACCESS_KEY",
    "new_access_key_id": "ACCESS_KEY",
    "account_id": "AWS_ACCOUNT",
    "email": "USER",
}

# (kind, pattern) for secrets found inside free text. When a pattern has a
# named group `secret`, only that span is replaced and the surrounding context
# ("password=", "Bearer ") is kept; otherwise the whole match is the secret.
# `(?!\[REDACTED)` stops an already-redacted marker from matching again.
_SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)),
    ("URL_CREDENTIAL", re.compile(r"://(?P<secret>(?!\[REDACTED)[^\s:/@\[]+:[^\s@/]+)@")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{12,})")),
    ("AWS_SECRET_KEY", re.compile(r"(?i)aws_secret_access_key[\s:=\"']+(?P<secret>[A-Za-z0-9/+=]{30,})")),
    ("API_KEY", re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})")),
    ("SECRET_ASSIGNMENT", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|client_secret)\s*[=:]\s*[\"']?"
        r"(?P<secret>(?!\[REDACTED)[^\s\"',;&]{3,})"
    )),
    ("CLI_PASSWORD", re.compile(r"(?i)(?:^|\s)(?:-p|--password|-password)\s+(?P<secret>(?!\[REDACTED)[^\s\"']{3,})")),
)


def _replace_secret(kind: str, match: re.Match[str]) -> str:
    marker = f"[REDACTED_{kind}]"
    if "secret" in match.re.groupindex and match.group("secret") is not None:
        start, end = match.span("secret")
        whole_start = match.start()
        text = match.group(0)
        return text[: start - whole_start] + marker + text[end - whole_start:]
    return marker


# Real AWS key IDs inside free text are pseudonymized, not destroyed, so a
# key mentioned in a command line still links to the same ACCESS_KEY_nnn.
_AWS_KEY_ID: Final[re.Pattern[str]] = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_EMAIL: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_ACCOUNT_IN_ARN: Final[re.Pattern[str]] = re.compile(r"(?<=arn:aws:)([a-z0-9-]*):([a-z0-9-]*):(\d{12})")


@dataclass
class Redactor:
    """Stateful, per-context redactor. One instance per context build, so
    pseudonyms are consistent within a context and never shared across them."""

    pseudonyms: dict[str, dict[str, str]] = field(default_factory=dict)
    reverse: dict[str, str] = field(default_factory=dict)
    redacted_count: int = 0
    pseudonymized_count: int = 0
    kinds: dict[str, int] = field(default_factory=dict)

    # -- identifiers ------------------------------------------------------

    def pseudonym(self, kind: str, value: str | None) -> str | None:
        """Consistent token for an identifier, e.g. USER_003."""
        if value is None or value == "":
            return value
        table = self.pseudonyms.setdefault(kind, {})
        if value not in table:
            table[value] = f"{kind}_{len(table) + 1:03d}"
            self.reverse[table[value]] = value
        self.pseudonymized_count += 1
        return table[value]

    def user(self, value: str | None) -> str | None:
        return self.pseudonym("USER", value)

    # -- free text ----------------------------------------------------------

    def text(self, value: str | None) -> str | None:
        """Destroy secrets and pseudonymize identifiers inside free text."""
        if not value:
            return value
        out = value
        for kind, pattern in _SECRET_PATTERNS:
            out, n = pattern.subn(lambda m, k=kind: _replace_secret(k, m), out)
            if n:
                self._count(kind, n)
        out = _AWS_KEY_ID.sub(lambda m: self.pseudonym("ACCESS_KEY", m.group(0)) or "", out)
        out = _EMAIL.sub(lambda m: self.user(m.group(0)) or "", out)
        out = _ACCOUNT_IN_ARN.sub(
            lambda m: f"{m.group(1)}:{m.group(2)}:{self.pseudonym('AWS_ACCOUNT', m.group(3))}", out
        )
        for real, token in self._known_values():
            # Any value already pseudonymized in a structured field must not
            # survive in free text: a username inside "C:\\Users\\<name>\\...",
            # an account ID inside an incident title, a key ID in a command.
            if real in out:
                out = out.replace(real, token)
                self.pseudonymized_count += 1
        return out

    def _known_values(self) -> list[tuple[str, str]]:
        # Longest first so "svc_backup" is replaced before "svc". Very short
        # values are skipped to avoid mangling unrelated text.
        pairs = [
            (real, token)
            for table in self.pseudonyms.values()
            for real, token in table.items()
            if real and len(real) >= 3
        ]
        return sorted(pairs, key=lambda kv: -len(kv[0]))

    def _count(self, kind: str, n: int = 1) -> None:
        self.redacted_count += n
        self.kinds[kind] = self.kinds.get(kind, 0) + n

    # -- structures -----------------------------------------------------------

    def value(self, key: str, value: Any) -> Any:
        """Redact one field by name, recursing into containers."""
        lowered = key.lower().replace("-", "_")
        if isinstance(value, dict):
            return {k: self.value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.value(key, v) for v in value]
        if not isinstance(value, str):
            return value
        if lowered in SECRET_FIELD_NAMES or lowered.endswith(("_password", "_secret", "_token")):
            self._count("SECRET_FIELD")
            return "[REDACTED_SECRET_FIELD]"
        if lowered in PSEUDONYM_FIELDS:
            return self.pseudonym(PSEUDONYM_FIELDS[lowered], value)
        return self.text(value)

    def stats(self) -> dict[str, Any]:
        return {
            "redacted_field_count": self.redacted_count,
            "pseudonymized_value_count": self.pseudonymized_count,
            "distinct_pseudonyms": len(self.reverse),
            "redactions_by_kind": dict(sorted(self.kinds.items())),
        }


def contains_secret(text: str) -> bool:
    """True if `text` still contains anything the secret patterns match.

    Used as an outbound tripwire: the Claude provider refuses to send a
    payload for which this returns True.
    """
    return any(p.search(text) for _, p in _SECRET_PATTERNS) or bool(_AWS_KEY_ID.search(text))
