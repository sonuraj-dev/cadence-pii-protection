"""Isolated UI adapter for the existing Cadence extraction/redaction backend.

This module deliberately delegates extraction, detection, redaction, and residual
validation to ``src``. It never implements its own PII detector or redactor.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

from src.extraction.extraction_engine import extract_all_documents
from src.integration.pipeline import process_extraction_result

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".pptx"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MiB per file


class UploadValidationError(ValueError):
    """An upload was rejected before backend processing began."""


def _safe_filename(filename: str) -> str:
    # Normalize both POSIX and Windows separators, and remove control characters.
    # The supplied filename is metadata only and is never used as a disk path.
    raw = str(filename or "document").replace("\\", "/").split("/")[-1]
    cleaned = "".join(ch if ch >= " " and ch not in "\x7f" else " " for ch in raw)
    cleaned = " ".join(cleaned.split())[:180]
    return cleaned or "document"


def _failure_result(
    filename: str,
    size_bytes: int,
    file_type: str,
    message: str,
    *,
    gate_status: str = "processing_failed",
    document_id: str | None = None,
) -> dict[str, Any]:
    return {
        "document_id": document_id or f"doc-{uuid4().hex[:12]}",
        "filename": filename,
        "size_bytes": size_bytes,
        "file_type": file_type,
        "processed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "gate_status": gate_status,
        "safe_to_process": False,
        "backend_safe_to_process": None,
        "extraction": {
            "total_blocks": 0,
            "reports": [],
            "errors": [{"block_id": "input", "error": message}],
            "complete": False,
            "retention": None,
            "retention_status": "not_measured_no_reference_text",
            "block_summaries": [],
        },
        "units": [],
        "audit_events": [],
        "pii_counts": {},
        "pii_count": 0,
        "redaction_count": 0,
        "validation": {"passed": False, "checks": [], "issues": []},
        "processing_status": "failed",
        "message": message,
    }


def _public_extraction_error(item: Any) -> str:
    """Return a safe error summary without echoing potentially sensitive content."""
    if not isinstance(item, dict):
        return "An extraction issue was reported."
    raw = str(item.get("error", ""))
    # The current backend uses these generic messages; unknown messages are not
    # echoed because a future extractor might accidentally include source text.
    if raw.startswith("Document extraction failed:"):
        suffix = raw.split(":", 1)[-1].strip()
        if suffix and len(suffix) <= 80 and suffix.replace("_", "").isalnum():
            return f"Document extraction failed ({suffix})."
        return "Document extraction failed."
    approved = {
        "OCR dependencies unavailable",
        "OCR produced no text; page requires review",
        "Input directory is missing or invalid",
        "No supported PDF, DOCX, or PPTX documents were found",
    }
    if raw in approved:
        return raw
    if raw.startswith("OCR failed:"):
        return "OCR failed; this page requires review."
    return "An extraction issue was reported. Review the source document."


def _normalize_audit_events(events: Any) -> list[dict[str, Any]]:
    """Allow-list audit fields. Never include matched/original PII values."""
    if not isinstance(events, list):
        return []
    allowed = (
        "event_id", "document_id", "source_file", "unit_type", "unit_number",
        "block_id", "entity_type", "start", "end", "confidence", "method",
        "action", "replacement",
    )
    safe_events: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        safe_event = {key: event[key] for key in allowed if key in event}
        # Explicitly discard common raw-value fields even if the schema changes.
        for raw_key in ("value", "matched_text", "original_text", "raw_value", "text"):
            safe_event.pop(raw_key, None)
        safe_events.append(safe_event)
    return safe_events


def _normalized_units(processed: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    units = processed.get("units")
    if not isinstance(units, list):
        return output
    for unit in units:
        if not isinstance(unit, dict):
            continue
        safe_blocks = []
        for block in unit.get("blocks", []) if isinstance(unit.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if not isinstance(text, str):
                continue
            safe_blocks.append({
                "block_id": str(block.get("block_id", "unknown")),
                "type": str(block.get("type", "text")),
                "text": text,  # Backend-produced sanitized text only.
            })
        output.append({
            "unit_type": str(unit.get("unit_type", "unit")),
            "unit_number": unit.get("unit_number"),
            "blocks": safe_blocks,
        })
    return output


def _strict_gate(extraction: dict[str, Any], processed: dict[str, Any]) -> tuple[str, bool]:
    """Fail closed unless each explicit backend and extraction condition passes."""
    errors = extraction.get("errors")
    blocks = extraction.get("blocks")
    block_errors = (
        any(isinstance(block, dict) and bool(block.get("extraction_error")) for block in blocks)
        if isinstance(blocks, list) else True
    )
    extraction_ok = (
        extraction.get("complete") is True
        and isinstance(blocks, list)
        and len(blocks) > 0
        and isinstance(errors, list)
        and len(errors) == 0
        and not block_errors
    )

    validation = processed.get("validation")
    validation_known = isinstance(validation, dict) and isinstance(validation.get("passed"), bool)
    backend_safe = processed.get("safe_to_process")
    allowed = (
        extraction_ok
        and validation_known
        and validation.get("passed") is True
        and backend_safe is True
        and processed.get("status") != "failed"
    )
    if allowed:
        return "validated", True

    if not extraction_ok or not validation_known:
        return "review_required", False
    if validation.get("passed") is False or backend_safe is False:
        return "blocked", False
    return "review_required", False


def process_uploaded_document(
    filename: str,
    file_bytes: bytes,
    *,
    max_upload_bytes: int = MAX_UPLOAD_BYTES,
) -> dict[str, Any]:
    """Process one in-memory upload through the existing backend contract.

    Source bytes are written only into a temporary directory and cleaned up on
    success or failure. Original extracted text is not included in the return
    value. The returned unit text is the backend's post-redaction output.
    """
    safe_name = _safe_filename(filename)
    suffix = Path(safe_name).suffix.lower()
    file_type = suffix.lstrip(".") or "unknown"
    if suffix not in SUPPORTED_EXTENSIONS:
        raise UploadValidationError("Unsupported file format. Upload a PDF, DOCX, or PPTX file.")
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise UploadValidationError("The selected file could not be read. Please select it again.")
    data = bytes(file_bytes)
    if not data:
        return _failure_result(safe_name, 0, file_type, "The selected document is empty.", gate_status="review_required")
    if len(data) > max_upload_bytes:
        raise UploadValidationError("The file exceeds the 25 MiB upload limit.")

    document_id = f"doc-{uuid4().hex[:12]}"
    try:
        with TemporaryDirectory(prefix="cadence-upload-") as tmp:
            # Use a generated name so user-controlled paths never reach disk.
            temp_path = Path(tmp) / f"document{suffix}"
            temp_path.write_bytes(data)
            extraction = extract_all_documents(docs_path=tmp)
            if not isinstance(extraction, dict):
                extraction = {}
            # One temporary directory contains exactly one accepted upload.
            processed = process_extraction_result(
                extraction,
                document_id=document_id,
                source_file=safe_name,
                file_type=file_type,
            )
    except Exception as exc:
        # Do not surface exception messages or source text to the UI.
        return _failure_result(
            safe_name, len(data), file_type,
            f"Processing failed ({type(exc).__name__}). Check that the file is readable and required dependencies are installed.",
            gate_status="processing_failed", document_id=document_id,
        )

    if not isinstance(processed, dict):
        processed = {}

    # Extraction summaries contain no source text.
    raw_blocks = extraction.get("blocks", []) if isinstance(extraction.get("blocks"), list) else []
    block_summaries = []
    for index, block in enumerate(raw_blocks):
        if not isinstance(block, dict):
            continue
        block_error = block.get("extraction_error")
        block_summaries.append({
            "block_id": str(block.get("id", f"block-{index}")),
            "page_slide": block.get("page_slide"),
            "block_type": str(block.get("block_type", "text")),
            "char_count": int(block.get("char_count", 0) or 0),
            "has_error": bool(block_error),
            "error": _public_extraction_error({"error": block_error}) if block_error else "",
        })

    safe_errors = []
    raw_errors = extraction.get("errors", [])
    if isinstance(raw_errors, list):
        for item in raw_errors:
            safe_errors.append({
                "block_id": str(item.get("block_id", "unknown")) if isinstance(item, dict) else "unknown",
                "page_slide": item.get("page_slide") if isinstance(item, dict) else None,
                "error": _public_extraction_error(item),
            })

    gate_status, safe_to_process = _strict_gate(extraction, processed)
    audit_events = _normalize_audit_events(processed.get("audit_events"))
    counts = Counter(str(event.get("entity_type", "OTHER")) for event in audit_events)
    validation = processed.get("validation")
    if not isinstance(validation, dict):
        validation = {"passed": None, "checks": [], "issues": []}
    # Restrict validation output to simple, display-safe fields.
    checks = []
    for check in validation.get("checks", []) if isinstance(validation.get("checks"), list) else []:
        if isinstance(check, dict):
            checks.append({
                "name": str(check.get("name", "Validation check"))[:100],
                "passed": check.get("passed") if isinstance(check.get("passed"), bool) else None,
                "details": str(check.get("details", ""))[:240],
            })
    issues = []
    for issue in validation.get("issues", []) if isinstance(validation.get("issues"), list) else []:
        if isinstance(issue, dict):
            issues.append({
                "code": str(issue.get("code", "VALIDATION_ISSUE"))[:100],
                "message": str(issue.get("message", "A validation issue was reported."))[:240],
            })
        else:
            issues.append({"code": "VALIDATION_ISSUE", "message": "A validation issue was reported."})

    raw_reports = extraction.get("reports", []) if isinstance(extraction.get("reports"), list) else []
    safe_reports = []
    for report in raw_reports:
        if not isinstance(report, dict):
            continue
        safe_reports.append({
            "file": _safe_filename(report.get("file", safe_name)),
            "blocks": report.get("blocks", 0) if isinstance(report.get("blocks", 0), int) else 0,
            "type": str(report.get("type", "unknown"))[:100],
            "status": str(report.get("status", "unknown"))[:40],
        })

    return {
        "document_id": document_id,
        "filename": safe_name,
        "size_bytes": len(data),
        "file_type": file_type,
        "processed_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "gate_status": gate_status,
        "safe_to_process": safe_to_process,
        "backend_safe_to_process": processed.get("safe_to_process") if isinstance(processed.get("safe_to_process"), bool) else None,
        "extraction": {
            "total_blocks": extraction.get("total_blocks", len(raw_blocks)),
            "reports": safe_reports,
            "errors": safe_errors,
            "complete": extraction.get("complete") is True,
            "retention": extraction.get("retention"),
            "retention_status": str(extraction.get("retention_status", "unknown")),
            "block_summaries": block_summaries,
        },
        "units": _normalized_units(processed),
        "audit_events": audit_events,
        "pii_counts": dict(counts),
        "pii_count": len(audit_events),
        "redaction_count": sum(1 for event in audit_events if event.get("action") == "redacted"),
        "validation": {"passed": validation.get("passed"), "checks": checks, "issues": issues},
        "processing_status": str(processed.get("status", "unknown")),
        "message": "",
    }


def history_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Return minimal session-history fields; exclude document and unit text."""
    return {
        "document_id": result.get("document_id", "unknown"),
        "filename": result.get("filename", "document"),
        "processed_at": result.get("processed_at", ""),
        "extraction_status": "Complete" if result.get("extraction", {}).get("complete") else "Incomplete",
        "pii_findings": int(result.get("pii_count", 0) or 0),
        "redactions": int(result.get("redaction_count", 0) or 0),
        "decision": str(result.get("gate_status", "review_required")),
    }


def sanitized_text_export(result: dict[str, Any]) -> str:
    """Format sanitized backend output for a text-only export."""
    lines: list[str] = [
        "Cadence PII Protection — Sanitized Text Export",
        f"Source filename: {result.get('filename', 'document')}",
        f"Safety decision: {result.get('gate_status', 'review_required')}",
        "Export format: text only; original document layout is not reconstructed.",
        "",
    ]
    for unit in result.get("units", []):
        if not isinstance(unit, dict):
            continue
        label = unit.get("unit_type", "unit").title()
        number = unit.get("unit_number", "?")
        lines.append(f"--- {label} {number} ---")
        for block in unit.get("blocks", []):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                lines.append(block["text"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
