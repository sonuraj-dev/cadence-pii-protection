import re
from typing import Dict, List


def detect_pii_entities(block_text: str, file_meta: dict = None) -> List[Dict]:
    """Detect labelled PII and conservative contextual person names."""
    if not isinstance(block_text, str) or not block_text:
        return []

    findings = []

    def add(kind, match, confidence, method):
        findings.append({
            "type": kind,
            "start": match.start(),
            "end": match.end(),
            "confidence": confidence,
            "method": method,
        })

    patterns = {
        "EMAIL_ADDRESS": re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        ),
        "EMP_ID": re.compile(r"\bEMP-\d{5}\b", re.I),
        "PHONE_NUMBER": re.compile(
            r"(?<!\d)(?:\+?1[\s.-]*)?"
            r"(?:\(\d{3}\)|\d{3})[\s.-]*\d{3}[\s.-]*\d{4}(?!\d)"
            r"|(?<!\d)\d{10}(?!\d)"
        ),
        "ACCOUNT_NUMBER": re.compile(
            r"\b(?:account\s*(?:number|no\.?|#)|acct\s*(?:number|no\.?|#))"
            r"\s*[:#-]?\s*\d{6,20}\b",
            re.I,
        ),
        "DATE_OF_BIRTH": re.compile(
            r"\b(?:DOB|date\s+of\s+birth)\s*[:#-]?\s*"
            r"(?:\d{1,2}\s+[A-Za-z]+\s+\d{4}"
            r"|[A-Za-z]+\s+\d{1,2},?\s+\d{4}"
            r"|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b",
            re.I,
        ),
    }

    type_confidence = {
        "EMAIL_ADDRESS": (1.0, "regex_email_address"),
        "EMP_ID": (0.9, "regex_emp_id"),
        "PHONE_NUMBER": (0.85, "regex_phone_number"),
        "ACCOUNT_NUMBER": (0.95, "labelled_account_number"),
        "DATE_OF_BIRTH": (0.95, "labelled_date_of_birth"),
    }

    for kind, pattern in patterns.items():
        confidence, method = type_confidence[kind]
        for match in pattern.finditer(block_text):
            add(kind, match, confidence, method)

    # Only identify names in clear contexts. Avoid treating arbitrary
    # capitalized heading/address words as person names.
    name = r"[A-Z][a-z]{1,}(?:[-'][A-Z]?[a-z]{1,})?"
    full_name = rf"{name}(?:\s+[A-Z]\.)?\s+{name}"

    contextual_patterns = [
        re.compile(
            rf"\b(?:customer\s+name|full\s+name|contact|employee\s+name)"
            rf"\s*:\s*({full_name})",
            re.I,
        ),
        re.compile(rf"\bContact\s+({full_name})\b"),
        re.compile(rf"(?m)^\s*({full_name})\s+is\s+an?\s+employee\b"),
    ]

    for pattern in contextual_patterns:
        for match in pattern.finditer(block_text):
            start, end = match.span(1)
            # Do not overlap an already identified email, phone, or other PII.
            if any(
                item["start"] < end and start < item["end"]
                for item in findings
            ):
                continue
            findings.append({
                "type": "PERSON",
                "start": start,
                "end": end,
                "confidence": 0.85,
                "method": "contextual_person_name",
            })

    # Remove exact duplicates; overlapping different entity types are left
    # for the pipeline's existing fail-closed span validation.
    unique = {}
    for item in findings:
        key = (item["type"], item["start"], item["end"])
        unique[key] = item

    return sorted(unique.values(), key=lambda item: (item["start"], item["end"]))
