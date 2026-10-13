"""Conservative, offset-preserving PII detection for business documents."""
from __future__ import annotations
import re
from typing import Any

_NAME = r"(?!(?-i:at|on|in|for|from|with|and|is|was|has|will|to|by|of)\b)[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+(?:[-'][A-ZÀ-ÖØ-Þ]?[a-zà-öø-ÿ]+)*"
_INITIAL = r"[A-ZÀ-ÖØ-Þ]\."
_PERSON_NAME = rf"{_NAME}(?:\s+{_INITIAL})?(?:\s+{_NAME}){{1,2}}"
_DATE = (r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2}|"
         r"\d{1,2}\s+[A-Za-z]+\s+\d{4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})")
_ACCOUNT_LABEL = r"(?:account\s*(?:number|no\.?|#)|acct\s*(?:number|no\.?|#))"
_ADDRESS_LABEL = r"(?:home|residential|mailing|billing|street|postal)\s+address"
_EMAIL_LOCAL = r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+"
_EMAIL_DOMAIN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\s*\.\s*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"

PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL_ADDRESS": re.compile(rf"(?<![\w.+-]){_EMAIL_LOCAL}\s*@\s*{_EMAIL_DOMAIN}", re.I),
    "EMP_ID": re.compile(r"\bEMP[-_. ]\d{3,12}\b", re.I),
    "PHONE_NUMBER": re.compile(
        r"(?<!\w)(?:\+\s?\d{1,3}[\s().-]*)?(?:\(\s?\d{2,5}\s?\)|\d{2,5})"
        r"(?:[\s().-]*\d{2,5}){1,4}(?:\s*(?:x|ext\.?)\s*\d{1,6})?(?!\w)", re.I),
    "ACCOUNT_NUMBER": re.compile(
        rf"\b{_ACCOUNT_LABEL}\s*[:#=-]?\s*(?:[Xx*•-]{{0,4}}\s*)?"
        r"(?:\d[ \t-]?){6,19}\d\b", re.I),
    "DATE_OF_BIRTH": re.compile(
        rf"\b(?:DOB|D\.O\.B\.?|date\s+of\s+birth|birth\s+date)\s*[:#=-]?\s*{_DATE}\b", re.I),
    "SSN": re.compile(
        r"\b(?:SSN|social\s+security(?:\s+number)?)\s*[:#=-]?\s*\d{3}[- ]?\d{2}[- ]?\d{4}\b", re.I),
    "PAYMENT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I),
    "ADDRESS": re.compile(
        rf"\b{_ADDRESS_LABEL}\s*[:#=-]?\s*\d{{1,6}}\s+[\w.'#/-]+"
        r"(?:\s+[\w.'#/-]+){0,8}(?:,\s*[\w.' -]{2,50}){1,3}"
        r"(?:\s+\d{5}(?:-\d{4})?)?", re.I),
    "IP_ADDRESS": re.compile(
        r"\b(?:IP(?:v4)?(?:\s+address)?|client\s+IP)\s*[:#=-]?\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.I),
    "PAN": re.compile(
        r"\b(?:PAN(?:\s*(?:number|no\.?))?|permanent\s+account\s+number)\s*[:#=-]?\s*([A-Z]{5}\d{4}[A-Z])\b", re.I),
    "PESEL": re.compile(r"\b(?:PESEL(?:\s*(?:number|no\.?))?)\s*[:#=-]?\s*(\d{11})\b", re.I),
    "TIN": re.compile(
        r"\b(?:TIN|tax\s+identification(?:\s+number)?|taxpayer\s+ID)\s*[:#=-]?\s*([A-Z0-9][A-Z0-9-]{5,19})\b", re.I),
}

_CONTEXT_PERSON_PATTERNS = [
    re.compile(
        rf"\b(?:customer\s+name|full\s+name|contact(?:\s+name)?|employee\s+name|patient\s+name|"
        rf"account\s+holder|policy\s+holder|prepared\s+by|submitted\s+by|requested\s+by|"
        rf"applicant\s+name|escalation\s+contact|assessed\s+by)\s*[:=-]\s*(?P<value>{_PERSON_NAME})\b", re.I),
    re.compile(rf"\bContact\s+(?P<value>{_PERSON_NAME})\b(?!\s+(?:at|on|in|for|from|with|and|is|was|has|will|to)\b)", re.I),
    re.compile(
        rf"(?m)(?:^|[.!?]\s+|\bInternal note:\s*)(?P<value>{_PERSON_NAME})\s+"
        r"(?:is|was|has|will be|serves as)\s+(?:an?\s+)?"
        r"(?:employee|customer|patient|applicant|officer|assessor|owner|manager|contact)\b", re.I),
    re.compile(rf"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(?P<value>{_PERSON_NAME})\b", re.I),
    re.compile(
        rf"(?im)^\s*(?:name|contact|employee|customer|patient|assessor)\s*[:|]\s*"
        rf"(?P<value>{_PERSON_NAME})\s*(?:\||$)"),
]

def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0

def _valid_ipv4(value: str) -> bool:
    try:
        octets = [int(part) for part in value.split(".")]
        return len(octets) == 4 and all(0 <= part <= 255 for part in octets)
    except ValueError:
        return False

def _valid_pesel(value: str) -> bool:
    if len(value) != 11 or not value.isdigit():
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    checksum = (10 - sum(int(d) * w for d, w in zip(value[:10], weights)) % 10) % 10
    return checksum == int(value[10])

def _valid_pan(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", value.upper()))

def detect_pii_entities(block_text: str, file_meta: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return non-overlapping PII spans with exact offsets and explainable methods."""
    if not isinstance(block_text, str) or not block_text:
        return []
    candidates: list[dict[str, Any]] = []

    def add(kind: str, start: int, end: int, confidence: float, method: str) -> None:
        if 0 <= start < end <= len(block_text):
            candidates.append({"type": kind, "start": start, "end": end,
                               "confidence": confidence, "method": method})

    metadata = {
        "EMAIL_ADDRESS": (1.0, "regex_email_ocr_tolerant"),
        "EMP_ID": (0.99, "employee_identifier_only"),
        "ACCOUNT_NUMBER": (0.98, "labelled_account_number"),
        "DATE_OF_BIRTH": (0.98, "labelled_date_of_birth"),
        "SSN": (0.98, "labelled_ssn"),
        "IBAN": (0.97, "iban_pattern"),
        "ADDRESS": (0.96, "labelled_address"),
        "IP_ADDRESS": (0.95, "labelled_ip_address"),
        "PAYMENT_CARD": (0.95, "luhn_valid_payment_card"),
        "PHONE_NUMBER": (0.88, "international_phone_pattern"),
        "PAN": (0.98, "labelled_pan_format"),
        "PESEL": (0.98, "labelled_pesel_checksum"),
        "TIN": (0.96, "labelled_tin"),
    }
    for kind, (confidence, method) in metadata.items():
        for match in PATTERNS[kind].finditer(block_text):
            value = match.group(1) if kind in {"IP_ADDRESS", "PAN", "PESEL", "TIN"} else match.group(0)
            if kind == "PAYMENT_CARD":
                digits = re.sub(r"\D", "", value)
                if not 13 <= len(digits) <= 19 or not _luhn_valid(digits):
                    continue
            if kind == "IP_ADDRESS" and not _valid_ipv4(value):
                continue
            if kind == "PAN" and not _valid_pan(value):
                continue
            if kind == "PESEL" and not _valid_pesel(value):
                continue
            add(kind, match.start(), match.end(), confidence, method)

    for pattern in _CONTEXT_PERSON_PATTERNS:
        for match in pattern.finditer(block_text):
            start, end = match.span("value")
            add("PERSON", start, end, 0.91, "contextual_person_name")

    candidates.sort(key=lambda item: (-item["confidence"], -(item["end"] - item["start"]), item["start"]))
    accepted: list[dict[str, Any]] = []
    for item in candidates:
        if any(item["start"] < prior["end"] and prior["start"] < item["end"] for prior in accepted):
            continue
        accepted.append(item)
    return sorted(accepted, key=lambda item: (item["start"], item["end"]))
