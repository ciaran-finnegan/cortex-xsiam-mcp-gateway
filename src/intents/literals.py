"""Replace the literals in an XQL query with type tokens before a model can see it.

Anyone with XQL access writes query text, and a failed query can hold anything, including a
pasted sentence, so this works from an allow list. A word survives only where XQL syntax puts a
field, dataset, function or keyword. A value survives only when its type is in ``keep``, and only
two types are recognised well enough to keep by default: an IP address by its format, and a
hostname by the field it filters on plus its format. Everything else becomes a token, and what
cannot be classified becomes ``<term>``, so an unrecognised value is never sent.

Comments are dropped. A stage that does not start with an XQL stage word becomes ``<term>`` whole,
whatever ``keep`` says, because it is not a value that could be cleared.

Field names, dataset names and aliases stay as written: they are what is being labelled.
"""

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass

from usecase.learned_store import IDENTIFIER_RE
from usecase.learning_observers import parse_xql

LITERAL_TYPES = ("ip", "host", "user", "email", "hash", "uuid", "number", "duration", "time", "term")
DEFAULT_KEEP = ("ip", "host")
MAX_PAREN_WALK = 200

_STAGES = frozenset(
    {
        "alter", "arrayexpand", "bin", "call", "comp", "config", "dataset", "datamodel", "dedup", "fields",
        "filter", "iploc", "join", "limit", "pivot", "preset", "replacenull", "search", "sort", "switch",
        "tag", "target", "top", "transaction", "transpose", "union", "view", "windowcomp",
    }
)
# Stages where a bare word after the stage word is a field, as in ``fields a, b``.
_FIELD_LIST_STAGES = frozenset({"arrayexpand", "bin", "comp", "dedup", "fields", "iploc", "sort", "top", "union"})
_KEYWORDS = _STAGES | {
    "and", "as", "asc", "between", "by", "contains", "desc", "false", "in", "inner", "left", "not", "null",
    "or", "right", "true",
}
_VALUE_OPS = frozenset({"=", "!=", "~=", "!~=", "<", ">", "<=", ">=", "contains"})
_BEFORE_FIELD = frozenset({"(", ",", "and", "or", "not", "by", "asc", "desc", "+", "-", "*", "/", "%", "[", "{"})
_AFTER_FIELD = frozenset({None, ",", ")", "as", "by", "asc", "desc", "->", "+", "-", "*", "/", "%", "[", "]", "{", "}"})
_LEFT_OF_VALUE = _VALUE_OPS | {"between", "in", "not"}

# ``parse_xql`` blanks string contents with x in the masked text, so this runs on that text.
_LEXEME_RE = re.compile(
    r"""
    (?P<string>"x*"|'x*'|`x*`|["'`]x*\Z)
    |(?P<op>->|!~=|!=|<=|>=|~=|=|<|>|!|~)
    |(?P<punct>[(),\[\]{}+*/%:;])
    |(?P<blob>(?:(?!->)[^\s"'`(),=!<>~+*/%\[\]{}:;])+)
    """,
    re.VERBOSE,
)
_IP_CHARS_RE = re.compile(r"[0-9A-Fa-f:./]+")
_ENUM_RE = re.compile(r"ENUM\.[A-Z0-9_]+")
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_DOMAIN_USER_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._$-]{1,64}")
_HASH_RE = re.compile(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{128}")
_UUID_RE = re.compile(r"[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}")
_NUMBER_RE = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")
_DURATION_RE = re.compile(r"[0-9]+(?:ms|mo|[smhdwy])", re.IGNORECASE)
_TIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[ T][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:\s*(?:Z|[+-][0-9]{2}:?[0-9]{2}))?)?"
)
_HOSTNAME_RE = re.compile(r"(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
# The last segment must name a host: host_owner holds a person, and host_ip an address.
_HOST_FIELD_RE = re.compile(
    r"(?:^|[._])(?:host|hostname|host_name|fqdn|computer_name|computername|device_name|devicename|endpoint_name"
    r"|machine_name|machinename|server_name|servername|workstation|workstation_name)$",
    re.IGNORECASE,
)
_USER_FIELD_RE = re.compile(
    r"(?:^|[._])(?:user|users|username|userid|upn|account|actor|principal|owner|identity|email|mail)(?:$|[._])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TokenisedQuery:
    text: str
    datasets: tuple[str, ...]
    fields: tuple[str, ...]
    literals: dict[str, int]


def _is_ip(value: str) -> bool:
    # ip_network accepts any text after a percent sign, as an IPv6 zone, which would keep free text.
    if not _IP_CHARS_RE.fullmatch(value):
        return False
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _is_hostname(value: str) -> bool:
    return len(value) <= 253 and _HOSTNAME_RE.fullmatch(value) is not None


def classify_value(value: str, field: str | None) -> str:
    """The literal type of a value, given the field it is compared with. ``term`` means not classified."""
    if _is_ip(value):
        return "ip"
    if _EMAIL_RE.fullmatch(value):
        return "email"
    if field and _HOST_FIELD_RE.search(field) and _is_hostname(value):
        return "host"
    if _DOMAIN_USER_RE.fullmatch(value) or (field and _USER_FIELD_RE.search(field) and "user_agent" not in field.lower()):
        return "user"
    if _HASH_RE.fullmatch(value):
        return "hash"
    if _UUID_RE.fullmatch(value):
        return "uuid"
    if _NUMBER_RE.fullmatch(value):
        return "number"
    if _DURATION_RE.fullmatch(value):
        return "duration"
    if _TIME_RE.fullmatch(value):
        return "time"
    return "term"


def _word(lexeme: tuple[str, str] | None) -> str | None:
    """The lower-case text of a lexeme, a sentinel for a string, and None at either end of a stage."""
    if lexeme is None:
        return None
    return "<string>" if lexeme[0] == "string" else lexeme[1].lower()


def _field_left_of(lexemes: list[tuple[str, str]], operator: int) -> str | None:
    """The field an operator compares, including ``lowercase(field) = ...`` and ``field not in (...)``."""
    index = operator - 1
    if index >= 0 and _word(lexemes[index]) == "not":
        index -= 1
    if index >= 0 and lexemes[index][1] == ")":
        depth = 0
        lowest = max(index - MAX_PAREN_WALK, -1)
        while index > lowest:
            depth += {")": 1, "(": -1}.get(lexemes[index][1], 0)
            if depth == 0:
                break
            index -= 1
        if depth != 0:
            return None
        index += 1
    if not 0 <= index < len(lexemes):
        return None
    kind, text = lexemes[index]
    return text if kind == "blob" and IDENTIFIER_RE.match(text) else None


def _field_of_value(lexemes: list[tuple[str, str]], index: int, parens: list[dict | None]) -> str | None:
    """The field a value at this position is compared with, when a plain reading finds one."""
    previous = _word(lexemes[index - 1]) if index else None
    if previous in _VALUE_OPS:
        return _field_left_of(lexemes, index - 1)
    if parens and parens[-1] is not None and previous in {"(", ","}:
        return parens[-1]["field"]
    return None


class _Tokeniser:
    def __init__(self, keep: frozenset[str]):
        self.keep = keep
        self.literals: Counter = Counter()
        self.datasets: dict[str, None] = {}
        self.fields: dict[str, None] = {}

    def _value(self, value: str, field: str | None, *, bare: bool = False) -> str:
        stripped = value.strip()
        if not stripped:
            return '""'
        kind = classify_value(stripped, field)
        self.literals[kind] += 1
        if kind not in self.keep:
            return f"<{kind}>"
        return stripped if bare and kind in {"number", "duration"} else f'"{stripped}"'

    def _word_token(self, lexemes, index: int, word_index: int, stage: str, parens: list[dict | None]) -> str:
        text = lexemes[index][1]
        previous = _word(lexemes[index - 1]) if index else None
        following = _word(lexemes[index + 1]) if index + 1 < len(lexemes) else None
        value_list = parens[-1] if parens else None
        field = _field_of_value(lexemes, index, parens)
        if text == "-":
            return text
        if not IDENTIFIER_RE.match(text) or _HASH_RE.fullmatch(text):
            return self._value(text, field, bare=True)
        # A value that looks like a call is still a value on the right of a filter comparison.
        compared = stage == "filter" and (previous in _VALUE_OPS or value_list is not None)
        if text.lower() in _KEYWORDS or _ENUM_RE.fullmatch(text) or (following == "(" and not compared):
            return text
        is_source = (
            (previous == "=" and _word(lexemes[index - 2]) in {"dataset", "preset"} and following in {None, ")"})
            or (value_list is not None and field == "dataset" and following in {",", ")"})
            or (stage == "union" and index == word_index + 1 and following is None)
        )
        if is_source:
            self.datasets.setdefault(text)
            return text
        if previous in {"as", "->"} or (following == "->" and value_list is None):
            self.fields.setdefault(text)
            return text
        if value_list is not None or previous in _VALUE_OPS:
            return self._value(text, field, bare=True)
        at_stage_start = index == word_index + 1
        if at_stage_start or previous in _BEFORE_FIELD:
            in_list_position = following in _AFTER_FIELD and (stage in _FIELD_LIST_STAGES or bool(parens))
            if following in _LEFT_OF_VALUE or in_list_position:
                self.fields.setdefault(text)
                return text
        return self._value(text, None, bare=True)

    def stage(self, masked: str, stripped: str) -> str:
        lexemes: list[tuple[str, str]] = []
        spans = []
        for match in _LEXEME_RE.finditer(masked):
            lexemes.append((match.lastgroup or "blob", stripped[match.start() : match.end()]))
            spans.append(match.group())
        if not lexemes:
            return ""
        word_index = next((index for index, lexeme in enumerate(lexemes) if lexeme[1] != "("), None)
        stage = lexemes[word_index][1].lower() if word_index is not None and lexemes[word_index][0] == "blob" else ""
        if stage not in _STAGES:
            self.literals["term"] += 1
            return "<term>"
        tokens: list[str] = []
        parens: list[dict | None] = []
        for index, (kind, text) in enumerate(lexemes):
            if index == word_index:
                tokens.append(text)
            elif kind == "string":
                terminated = len(spans[index]) >= 2 and spans[index][-1] == spans[index][0]
                value = text[1:-1] if terminated else text[1:]
                tokens.append(self._value(value, _field_of_value(lexemes, index, parens)))
            elif kind == "blob":
                tokens.append(self._word_token(lexemes, index, word_index, stage, parens))
            else:
                if text == "(":
                    in_list = index > 0 and _word(lexemes[index - 1]) == "in"
                    parens.append({"field": _field_left_of(lexemes, index - 1)} if in_list else None)
                elif text == ")" and parens:
                    parens.pop()
                tokens.append(text)
        return " ".join(tokens).replace("( ", "(").replace(" )", ")").replace(" ,", ",")


def tokenise_query(query: str, keep: frozenset[str]) -> TokenisedQuery:
    """Query text with comments dropped and literals replaced, for ``keep`` a subset of ``LITERAL_TYPES``."""
    parsed = parse_xql(query)
    tokeniser = _Tokeniser(keep)
    stages = [tokeniser.stage(parsed.masked[start:end], parsed.stripped[start:end]) for start, end in parsed.stages]
    return TokenisedQuery(
        text=" | ".join(stage for stage in stages if stage),
        datasets=tuple(tokeniser.datasets),
        fields=tuple(tokeniser.fields),
        literals=dict(tokeniser.literals),
    )
