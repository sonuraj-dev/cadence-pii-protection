from typing import Any


def redact_text(
    text: str,
    entities: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """
    Replace detected PII spans and return sanitized text plus audit records.

    Entity offsets are zero-based and use an exclusive end position.
    Raw PII values are never included in the returned audit records.

    Overlapping spans are rejected so ambiguous replacements cannot
    silently produce incorrect output.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if not isinstance(entities, list):
        raise TypeError("entities must be a list")

    validated = []

    for entity in entities:
        if not isinstance(entity, dict):
            raise TypeError("each entity must be a dictionary")

        entity_type = entity.get("type")
        start = entity.get("start")
        end = entity.get("end")
        confidence = entity.get("confidence")

        if not isinstance(entity_type, str) or not entity_type.strip():
            raise ValueError("entity type must be a non-empty string")

        # bool is a subclass of int in Python, so reject it explicitly.
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
        ):
            raise ValueError("entity offsets must be integers")

        if start < 0 or end <= start or end > len(text):
            raise ValueError("entity offsets are outside the text bounds")

        if confidence is not None:
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 1
            ):
                raise ValueError("confidence must be between 0 and 1")

        validated.append({
            "type": entity_type.strip().upper(),
            "start": start,
            "end": end,
            "confidence": confidence,
            "method": entity.get("method"),
        })

    # Sort by start position and then end position.
    validated.sort(key=lambda item: (item["start"], item["end"]))

    # Fail closed on overlapping spans; resolve them upstream or review.
    for previous, current in zip(validated, validated[1:]):
        if current["start"] < previous["end"]:
            raise ValueError("overlapping entity spans require review")

    sanitized = text
    audit_records = []

    # Right-to-left replacement preserves the remaining original offsets.
    for entity in reversed(validated):
        start = entity["start"]
        end = entity["end"]
        entity_type = entity["type"]
        replacement = f"[REDACTED:{entity_type}]"

        sanitized = sanitized[:start] + replacement + sanitized[end:]

        audit_records.append({
            "type": entity_type,
            "start": start,
            "end": end,
            "confidence": entity["confidence"],
            "method": entity["method"],
            "replacement": replacement,
            "redacted": True,
        })

    audit_records.reverse()
    return sanitized, audit_records