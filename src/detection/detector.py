"""Conservative, offset-preserving PII detection for business documents."""
from __future__ import annotations
import re
from typing import Any

_NAME_WORD = r"[A-Z][a-zÀ-ÖØ-öø-ÿ]+(?:[-'][A-Z]?[a-zÀ-ÖØ-öø-ÿ]+)*"
_PERSON_NAME = rf"{_NAME_WORD}(?:\s+(?:[A-Z]\.\s+)?{_NAME_WORD}){{1,3}}"
_DATE_VALUE = (r"(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2}|\d{1,2}\s+[A-Za-z]+\s+\d{4}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})")
_LABEL = r"(?:account\s*(?:number|no\.?|#)|acct\s*(?:number|no\.?|#))"

PATTERNS: dict[str, re.Pattern[str]] = {
 "EMAIL_ADDRESS": re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"),
 "EMP_ID": re.compile(r"\b(?:EMP(?:LOYEE)?[-_ ]?(?:ID)?[-_:# ]*)[A-Z0-9]{3,12}\b", re.I),
 "PHONE_NUMBER": re.compile(r"(?<![\w])(?:\+\s?\d{1,3}[\s.-]*)?(?:\(\s?\d{2,4}\s?\)|\d{2,4})[\s.-]*\d{3,4}[\s.-]*\d{3,4}(?:\s*(?:x|ext\.?)\s*\d{1,6})?(?!\w)"),
 "ACCOUNT_NUMBER": re.compile(rf"\b{_LABEL}\s*[:#-]?\s*(?:[Xx*•-]{{0,4}}\s*)?\d(?:[\s-]?\d){{5,19}}\b", re.I),
 "DATE_OF_BIRTH": re.compile(rf"\b(?:DOB|D\.O\.B\.?|date\s+of\s+birth|birth\s+date)\s*[:#=-]?\s*{_DATE_VALUE}\b", re.I),
 "SSN": re.compile(r"\b(?:SSN|social\s+security(?:\s+number)?)\s*[:#=-]?\s*\d{3}[- ]?\d{2}[- ]?\d{4}\b|\b(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b", re.I),
 "PAYMENT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
 "IBAN": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I),
 "ADDRESS": re.compile(r"\b(?:home|residential|mailing|billing|street|postal)\s+address\s*[:#=-]\s*\d{1,6}\s+[\w.'# -]{2,60}(?:,\s*[\w.' -]{2,50}){1,3}(?:\s+\d{5}(?:-\d{4})?)?", re.I),
 "IP_ADDRESS": re.compile(r"\b(?:IP(?:v4)?(?:\s+address)?|client\s+IP)\s*[:#=-]?\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.I),
}
_CONTEXT_PERSON_PATTERNS = [
 re.compile(rf"\b(?:customer\s+name|full\s+name|contact(?:\s+name)?|employee\s+name|patient\s+name|account\s+holder|policy\s+holder|prepared\s+by|submitted\s+by|requested\s+by|applicant\s+name)\s*[:=-]\s*(?P<value>{_PERSON_NAME})\b", re.I),
 re.compile(rf"\bContact\s+(?P<value>{_PERSON_NAME})\b"),
 re.compile(rf"(?m)^\s*(?P<value>{_PERSON_NAME})\s+(?:is|was)\s+(?:an?\s+)?(?:employee|customer|patient|applicant)\b", re.I),
 re.compile(rf"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+(?P<value>{_PERSON_NAME})\b"),
]

def _luhn_valid(digits: str) -> bool:
 total = 0
 parity = len(digits) % 2
 for index, char in enumerate(digits):
  value = int(char)
  if index % 2 == parity:
   value *= 2
   if value > 9: value -= 9
  total += value
 return total % 10 == 0

def _valid_ipv4(value: str) -> bool:
 try:
  octets = [int(part) for part in value.split(".")]
  return len(octets) == 4 and all(0 <= part <= 255 for part in octets)
 except ValueError:
  return False

def detect_pii_entities(block_text: str, file_meta: dict[str, Any] | None = None) -> list[dict[str, Any]]:
 """Return non-overlapping PII spans with exact offsets and explainable methods."""
 if not isinstance(block_text, str) or not block_text: return []
 candidates: list[dict[str, Any]] = []
 def add(kind: str, start: int, end: int, confidence: float, method: str) -> None:
  if 0 <= start < end <= len(block_text):
   candidates.append({"type": kind, "start": start, "end": end, "confidence": confidence, "method": method})
 priority = {
  "EMAIL_ADDRESS": (1.0, "regex_email"), "EMP_ID": (0.98, "labelled_employee_id"),
  "ACCOUNT_NUMBER": (0.98, "labelled_account_number"), "DATE_OF_BIRTH": (0.98, "labelled_date_of_birth"),
  "SSN": (0.98, "labelled_or_formatted_ssn"), "IBAN": (0.97, "iban_pattern"),
  "ADDRESS": (0.95, "labelled_address"), "IP_ADDRESS": (0.95, "labelled_ip_address"),
  "PAYMENT_CARD": (0.94, "luhn_valid_payment_card"), "PHONE_NUMBER": (0.88, "phone_pattern"),
 }
 for kind, (confidence, method) in priority.items():
  for match in PATTERNS[kind].finditer(block_text):
   if kind == "PAYMENT_CARD":
    digits = re.sub(r"\D", "", match.group())
    if not 13 <= len(digits) <= 19 or not _luhn_valid(digits): continue
   if kind == "IP_ADDRESS" and not _valid_ipv4(match.group(1)): continue
   add(kind, match.start(), match.end(), confidence, method)
 for pattern in _CONTEXT_PERSON_PATTERNS:
  for match in pattern.finditer(block_text):
   start, end = match.span("value")
   add("PERSON", start, end, 0.90, "contextual_person_name")
 # Prefer high-confidence/specific matches; never return overlapping spans.
 candidates.sort(key=lambda x: (-x["confidence"], -(x["end"] - x["start"]), x["start"]))
 accepted = []
 for item in candidates:
  if any(item["start"] < prev["end"] and prev["start"] < item["end"] for prev in accepted): continue
  accepted.append(item)
 return sorted(accepted, key=lambda x: (x["start"], x["end"]))
