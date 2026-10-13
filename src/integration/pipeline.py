"""Adapter joining extraction, PII detection, and fail-closed redaction."""

import re
from collections import defaultdict
from typing import Any

from src.detection.detector import detect_pii_entities
from src.redaction.document_pipeline import redact_document


TYPE_MAP = {
    "EMAIL_ADDRESS": "EMAIL",
    "EMP_ID": "EMPLOYEE_ID",
    "PHONE_NUMBER": "PHONE",
    "PERSON": "PERSON",
    "DATE_OF_BIRTH": "DATE_OF_BIRTH",
    "ACCOUNT_NUMBER": "ACCOUNT_NUMBER",
    "SSN": "SSN",
    "PAYMENT_CARD": "PAYMENT_CARD",
    "IBAN": "IBAN",
    "ADDRESS": "ADDRESS",
    "IP_ADDRESS": "IP_ADDRESS",
}

# This is a deliberately limited residual scan, not proof that all PII is gone.
RESIDUAL_PATTERNS = {
    "ADDRESS": re.compile(
        r"\b(?:mailing|home|residential|street)\s+address\s*:"
        r"\s*\d{1,6}\s+[^,\n]+(?:,\s*[^,\n]+){1,3}",
        re.I,
    ),
    "PERSON": re.compile(
        r"\b(?:customer\s+name|full\s+name|contact\s+name|employee\s+name)"
        r"\s*:\s*(?!\[REDACTED:)[A-Z][a-z]+"
        r"(?:\s+[A-Z]\.)?\s+[A-Z][a-z]+\b"
        r"|\b[A-Z][a-z]+\s+[A-Z][a-z]+\s+"
        r"(?:requested|asked|contacted|submitted|reported)\b"
    ),
    "ACCOUNT_NUMBER": re.compile(
        r"\b(?:account\s*(?:number|no\.?|#)|acct\s*(?:number|no\.?|#))"
        r"\s*[:#-]?\s*\d{6,20}\b", re.I
    ),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "EMPLOYEE_ID": re.compile(r"\bEMP-\d{5}\b", re.I),
    "PHONE": re.compile(
        r"(?<!\w)(?:\+?1[\s.-]*)?\(?\d{3}\)?[\s.-]*\d{3}[\s.-]*\d{4}(?!\w)"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:DOB|date\s+of\s+birth)\s*[:#-]?\s*"
        r"(?:\d{1,2}\s+[A-Za-z]+\s+\d{4}"
        r"|[A-Za-z]+\s+\d{1,2},?\s+\d{4}"
        r"|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b", re.I
    ),

    "SSN": re.compile(
        r"\b(?:SSN|social\s+security(?:\s+number)?)\s*[:#=-]?\s*"
        r"\d{3}[- ]?\d{2}[- ]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b", re.I
    ),
    "PAYMENT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b", re.I),
    "IP_ADDRESS": re.compile(
        r"\b(?:IP(?:v4)?(?:\s+address)?|client\s+IP)\s*[:#=-]?\s*"
        r"(?:\d{1,3}\.){3}\d{1,3}\b", re.I
    ),
}


def residual_validator(document: dict[str, Any]) -> list[dict[str, str]]:
    """Return findings without copying potentially sensitive matched values."""
    findings = []
    for unit in document.get("units", []):
        for block in unit.get("blocks", []):
            text = block.get("text", "")
            for label, pattern in RESIDUAL_PATTERNS.items():
                for match in pattern.finditer(text):
                    findings.append({
                        "block_id": str(block.get("block_id", "")),
                        "type": label,
                        "reason": "residual_pattern_match",
                    })
    return findings


def build_document(
    extracted_blocks: list[dict[str, Any]],
    *,
    document_id: str,
    source_file: str,
    file_type: str,
    extraction_errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Convert extractor blocks into the nested contract, preserving failure status."""
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    errors: list[dict[str, str]] = []

    for error in extraction_errors or []:
        errors.append({
            "code": "EXTRACTION_ERROR",
            "block_id": str(error.get("block_id", "unknown")),
            "message": "Extraction was incomplete; downstream processing is blocked.",
        })

    for index, item in enumerate(extracted_blocks):
        if item.get("extraction_error"):
            errors.append({
                "code": "EXTRACTION_ERROR",
                "block_id": str(item.get("id", f"block-{index}")),
                "message": "Extraction was incomplete; downstream processing is blocked.",
            })

        text = item.get("text", "")
        if not isinstance(text, str):
            raise ValueError(f"Block {index} has non-string text")

        raw_page = item.get("page_slide", 1)
        try:
            unit_number = int(raw_page)
        except (TypeError, ValueError):
            unit_number = 1

        entities = []
        for finding in detect_pii_entities(text, item):
            start, end = finding.get("start"), finding.get("end")
            if (
                not isinstance(start, int)
                or not isinstance(end, int)
                or start < 0
                or end <= start
                or end > len(text)
            ):
                raise ValueError(f"Invalid detector span in block {index}")

            label = TYPE_MAP.get(finding.get("type"), "OTHER_PII")
            entities.append({
                "type": label,
                "start": start,
                "end": end,
                "confidence": finding.get("confidence", 0.0),
                "method": finding.get("method", "unknown"),
            })

        # The redactor fails closed on overlaps; don't silently alter offsets.
        ordered = sorted(entities, key=lambda e: (e["start"], e["end"]))
        for previous, current in zip(ordered, ordered[1:]):
            if current["start"] < previous["end"]:
                raise ValueError(
                    f"Overlapping detector spans in block {index}"
                )

        grouped[unit_number].append({
            "block_id": str(item.get("id", f"block-{index}")),
            "type": item.get("block_type", "paragraph"),
            "order": index,
            "text": text,
            "entities": entities,
        })

    unit_type = "slide" if file_type.lower() in {"pptx", "ppt"} else "page"
    units = [
        {
            "unit_type": unit_type,
            "unit_number": number,
            "blocks": blocks,
        }
        for number, blocks in sorted(grouped.items())
    ]

    return {
        "schema_version": "1.0",
        "document_id": document_id,
        "source_file": source_file,
        "file_type": file_type.lower(),
        "status": "failed" if errors else "extracted",
        "units": units,
        "errors": errors,
    }


def process_extracted_blocks(
    extracted_blocks: list[dict[str, Any]],
    *,
    document_id: str,
    source_file: str,
    file_type: str,
    extraction_errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build, redact, and validate. Extraction errors block downstream processing."""
    document = build_document(
        extracted_blocks,
        document_id=document_id,
        source_file=source_file,
        file_type=file_type,
        extraction_errors=extraction_errors,
    )
    return redact_document(document, residual_validator=residual_validator)



def process_extraction_result(
    extraction_result: dict[str, Any],
    *,
    document_id: str,
    source_file: str,
    file_type: str,
) -> dict[str, Any]:
    """Process extraction output and fail closed on incomplete or malformed input."""
    malformed = not isinstance(extraction_result, dict)

    if malformed:
        extraction_result = {}

    blocks = extraction_result.get("blocks")
    errors = extraction_result.get("errors")
    complete = extraction_result.get("complete")

    if not isinstance(blocks, list) or not blocks:
        malformed = True
        blocks = []
    elif any(not isinstance(block, dict) for block in blocks):
        malformed = True

    if not isinstance(errors, list):
        malformed = True
        errors = []

    if complete is not True:
        malformed = True

    if malformed and not errors:
        errors = [{
            "block_id": "unknown",
            "error": "Extraction result is incomplete or malformed",
        }]

    # Return no extracted content when upstream processing failed.
    if errors:
        return {
            "schema_version": "1.0",
            "metadata": {
                "document_id": document_id,
                "source_file": source_file,
                "file_type": file_type,
            },
            "units": [],
            "errors": [{
                "code": "EXTRACTION_ERROR",
                "block_id": str(
                    error.get("block_id", "unknown")
                    if isinstance(error, dict) else "unknown"
                ),
                "message": "Extraction was incomplete; downstream processing is blocked.",
            } for error in errors],
            "audit_events": [],
            "validation": {
                "passed": False,
                "checks": [],
                "issues": [{
                    "code": "UPSTREAM_FAILURE",
                    "message": "An upstream processing stage failed.",
                }],
            },
            "status": "failed",
            "safe_to_process": False,
        }

    return process_extracted_blocks(
        blocks,
        document_id=document_id,
        source_file=source_file,
        file_type=file_type,
        extraction_errors=[],
    )
