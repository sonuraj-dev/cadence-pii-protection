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
}

# This is a deliberately limited residual scan, not proof that all PII is gone.
RESIDUAL_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "EMPLOYEE_ID": re.compile(r"\bEMP-\d{5}\b", re.I),
    "PHONE": re.compile(
        r"(?<!\w)(?:\+?1[\s.-]*)?\(?\d{3}\)?[\s.-]*\d{3}[\s.-]*\d{4}(?!\w)"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\bDOB\s+\d{1,2}\s+\w+\s+\d{4}\b", re.I
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
) -> dict[str, Any]:
    """Convert extractor blocks into the agreed nested document contract."""
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for index, item in enumerate(extracted_blocks):
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
        "status": "extracted",
        "units": units,
        "errors": [],
    }


def process_extracted_blocks(
    extracted_blocks: list[dict[str, Any]],
    *,
    document_id: str,
    source_file: str,
    file_type: str,
) -> dict[str, Any]:
    """Build, redact, and validate. Unsafe documents remain blocked."""
    document = build_document(
        extracted_blocks,
        document_id=document_id,
        source_file=source_file,
        file_type=file_type,
    )
    return redact_document(document, residual_validator=residual_validator)
