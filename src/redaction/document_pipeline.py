"""Document-level redaction, privacy-safe audit, and fail-closed validation."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable


class RedactionPipelineError(ValueError):
    """Raised when input spans or redaction operations are unsafe."""


def _redact_block(text: str, entities: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Validate and redact entity spans; audit events never contain matched text."""
    spans: list[dict[str, Any]] = []
    for entity in entities:
        try:
            start, end = entity["start"], entity["end"]
            kind = str(entity["type"]).upper()
        except (KeyError, TypeError) as exc:
            raise RedactionPipelineError("Malformed entity record.") from exc

        if not isinstance(start, int) or isinstance(start, bool):
            raise RedactionPipelineError("Entity start offset must be an integer.")
        if not isinstance(end, int) or isinstance(end, bool):
            raise RedactionPipelineError("Entity end offset must be an integer.")
        if not isinstance(kind, str) or not kind:
            raise RedactionPipelineError("Entity type must be non-empty.")
        if not (0 <= start < end <= len(text)):
            raise RedactionPipelineError("Entity span is outside block text bounds.")
        spans.append({
            "start": start,
            "end": end,
            "type": kind,
            "confidence": entity.get("confidence"),
            "method": str(entity.get("method", "unspecified")),
        })

    spans.sort(key=lambda x: (x["start"], x["end"]))
    for previous, current in zip(spans, spans[1:]):
        if current["start"] < previous["end"]:
            raise RedactionPipelineError("Overlapping entity spans are unresolved.")

    output = text
    for span in reversed(spans):
        output = output[:span["start"]] + f'[REDACTED:{span["type"]}]' + output[span["end"]:]
    return output, spans


def redact_document(
    document: dict[str, Any],
    *,
    residual_validator: Callable[[dict[str, Any]], list[dict[str, str]]] | None = None,
) -> dict[str, Any]:
    """
    Redact a normalized detected document.

    `residual_validator` receives the sanitized document and returns a list of
    sanitized issue objects (each may contain `code` and `message`). It must
    not return matched text. It is mandatory for a document to pass the gate.
    """
    result = deepcopy(document)
    audit_events: list[dict[str, Any]] = []
    issues: list[dict[str, str]] = []
    checks: list[dict[str, Any]] = []

    def fail(code: str, message: str) -> dict[str, Any]:
        result["status"] = "failed"
        result["audit_events"] = audit_events
        result["validation"] = {
            "passed": False,
            "checks": checks,
            "issues": issues + [{"code": code, "message": message}],
        }
        result["safe_to_process"] = False
        return result

    if not isinstance(document, dict) or not isinstance(document.get("units"), list):
        result = {"schema_version": "1.0", "document_id": "unknown", "source_file": "unknown",
                  "file_type": "unknown", "units": []}
        return fail("INVALID_DOCUMENT", "Document schema or units are invalid.")

    if document.get("status") == "failed":
        return fail("UPSTREAM_FAILURE", "An upstream processing stage failed.")

    try:
        for unit in result["units"]:
            if not isinstance(unit, dict) or not isinstance(unit.get("blocks"), list):
                raise RedactionPipelineError("A document unit has an invalid block list.")
            for block in unit["blocks"]:
                if not isinstance(block, dict) or not isinstance(block.get("text"), str):
                    raise RedactionPipelineError("A block has invalid text.")
                text = block["text"]
                entities = block.get("entities", [])
                if not isinstance(entities, list):
                    raise RedactionPipelineError("Block entities must be a list.")
                sanitized, spans = _redact_block(text, entities)
                for span in spans:
                    event = {
                        "event_id": f"audit-{len(audit_events) + 1:04d}",
                        "document_id": result.get("document_id", "unknown"),
                        "source_file": result.get("source_file", "unknown"),
                        "unit_type": unit.get("unit_type", "unknown"),
                        "unit_number": unit.get("unit_number"),
                        "block_id": block.get("block_id", "unknown"),
                        "entity_type": span["type"],
                        "start": span["start"],
                        "end": span["end"],
                        "confidence": span["confidence"],
                        "method": span["method"],
                        "action": "redacted",
                        "replacement": f'[REDACTED:{span["type"]}]',
                    }
                    audit_events.append(event)
                block["text"] = sanitized
                # Old spans apply to pre-redaction text and must not be reused.
                block.pop("entities", None)
        checks.append({"name": "span_integrity_and_redaction", "passed": True,
                       "details": "All supplied entity spans were validated and replaced."})
    except RedactionPipelineError as exc:
        return fail("REDACTION_VALIDATION_FAILED", str(exc))

    if residual_validator is None:
        checks.append({"name": "post_redaction_validation", "passed": False,
                       "details": "No residual validator was supplied."})
        return fail("VALIDATOR_REQUIRED",
                    "Post-redaction validation was not configured; downstream processing is blocked.")

    try:
        residual_issues = residual_validator(result)
        if not isinstance(residual_issues, list):
            return fail("INVALID_VALIDATOR_RESULT", "Validator returned an invalid result.")
        # Accept only sanitized issue fields, preventing accidental echo of raw content.
        for item in residual_issues:
            if not isinstance(item, dict):
                issues.append({"code": "RESIDUAL_FINDING", "message": "Validator reported an unresolved finding."})
            else:
                issues.append({
                    "code": str(item.get("code", "RESIDUAL_FINDING"))[:80],
                    "message": str(item.get("message", "Validator reported an unresolved finding."))[:240],
                })
    except Exception:
        return fail("VALIDATOR_ERROR", "Post-redaction validation failed unexpectedly.")

    validation_passed = len(issues) == 0
    checks.append({"name": "post_redaction_validation", "passed": validation_passed,
                   "details": "No configured residual findings." if validation_passed
                   else "One or more residual findings remain."})
    result["status"] = "redacted" if validation_passed else "failed"
    result["audit_events"] = audit_events
    result["validation"] = {"passed": validation_passed, "checks": checks, "issues": issues}
    result["safe_to_process"] = validation_passed
    return result
