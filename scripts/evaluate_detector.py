from src.detection.detector import detect_pii_entities

# Synthetic examples with manually labelled expected PII spans.
CASES = [
    ("Contact alex.smith@example.com", [("EMAIL_ADDRESS", "alex.smith@example.com")]),
    ("Employee ID EMP-41077", [("EMP_ID", "EMP-41077")]),
    ("Call +1 (646) 555-0188", [("PHONE_NUMBER", "+1 (646) 555-0188")]),
    ("DOB 12 March 1995", [("DATE_OF_BIRTH", "DOB 12 March 1995")]),
    ("Naomi K. Osadebe is an employee.", [("PERSON", "Naomi K. Osadebe")]),
    ("Account number 123456789012", []),
    ("Contact Naomi K. Osadebe", [("PERSON", "Naomi K. Osadebe")]),
]

tp = fp = fn = 0

for text, expected in CASES:
    expected_spans = set()
    for label, value in expected:
        start = text.find(value)
        if start < 0:
            raise ValueError(f"Label not found in example: {value!r}")
        expected_spans.add((label, start, start + len(value)))

    predicted_spans = set()
    for finding in detect_pii_entities(text):
        predicted_spans.add((
            finding["type"],
            finding["start"],
            finding["end"],
        ))

    correct = expected_spans & predicted_spans
    false_positives = predicted_spans - expected_spans
    false_negatives = expected_spans - predicted_spans

    tp += len(correct)
    fp += len(false_positives)
    fn += len(false_negatives)

    print(f"\nTEXT: {text}")
    print("Correct:", sorted(correct))
    print("False positives:", sorted(false_positives))
    print("False negatives:", sorted(false_negatives))

precision = tp / (tp + fp) if tp + fp else 0.0
recall = tp / (tp + fn) if tp + fn else 0.0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

print("\n========== MICRO-AVERAGED METRICS ==========")
print(f"TP={tp} FP={fp} FN={fn}")
print(f"Precision: {precision:.3f}")
print(f"Recall:    {recall:.3f}")
print(f"F1 score:  {f1:.3f}")
print("NOTE: Small synthetic diagnostic set; not a real-world coverage estimate.")
