import re
from typing import List, Dict

def detect_pii_entities(block_text: str, file_meta: dict = None) -> List[Dict]:
    """
    PII Detector - schema: type,start,end,confidence,method
    Ready for Member 3 redaction
    """
    findings = []
    if not block_text:
        return findings

    # Regex patterns
    patterns = {
        "EMAIL_ADDRESS": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "EMP_ID": re.compile(r'EMP-\d{5}'),
        "PHONE_NUMBER": re.compile(
            r'(?<!\w)(?:\+?1[\s.-]*)?\(?\d{3}\)?[\s.-]+\d{3}[\s.-]+\d{4}(?!\w)'
        ),
        "DATE_OF_BIRTH": re.compile(r'DOB\s+\d{1,2}\s+\w+\s+\d{4}', re.I),
    }

    # EMAIL
    for m in patterns["EMAIL_ADDRESS"].finditer(block_text):
        findings.append({"type": "EMAIL_ADDRESS", "start": m.start(), "end": m.end(), "confidence": 1.0, "method": "regex_email_address"})

    # EMP_ID
    for m in patterns["EMP_ID"].finditer(block_text):
        findings.append({"type": "EMP_ID", "start": m.start(), "end": m.end(), "confidence": 0.9, "method": "regex_emp_id"})

    # PHONE
    for m in patterns["PHONE_NUMBER"].finditer(block_text):
        # Avoid overlapping with EMAIL
        if not any(f["start"] <= m.start() < f["end"] for f in findings):
            findings.append({"type": "PHONE_NUMBER", "start": m.start(), "end": m.end(), "confidence": 0.85, "method": "regex_phone_number"})

    # DOB
    for m in patterns["DATE_OF_BIRTH"].finditer(block_text):
        findings.append({"type": "DATE_OF_BIRTH", "start": m.start(), "end": m.end(), "confidence": 0.7, "method": "regex_date_of_birth"})

   
    # PERSON - conservative name detection.
    person_pattern = re.compile(
        r"(?=([A-Z][a-z]{1,}\s+(?:[A-Z]\.\s+)?[A-Z][a-z]{1,}))"
    )

    excluded_first_words = {
        "Contact", "Employee", "Account", "Phone", "Email",
        "Call", "Please", "Department", "Policy", "Date",
    }

    for m in person_pattern.finditer(block_text):
        name = m.group(1)
        first_word = name.split()[0].rstrip(".")

        if first_word in excluded_first_words:
            continue

        if "@" in block_text[max(0, m.start(1)-20):m.end(1)+20]:
            continue

        findings.append({
            "type": "PERSON",
            "start": m.start(1),
            "end": m.end(1),
            "confidence": 0.75,
            "method": "conservative_name_pattern",
        })

    # Deduplicate overlapping - keep highest confidence, earliest start
    findings = sorted(findings, key=lambda x: (x["start"], -x["confidence"]))
    deduped = []
    for f in findings:
        if not any(d["start"] <= f["start"] < d["end"] and d["type"] == f["type"] for d in deduped):
            # Remove duplicate phone with same start
            if f["type"] == "PHONE_NUMBER" and any(d["type"]=="PHONE_NUMBER" and d["start"]==f["start"] for d in deduped):
                continue
            deduped.append(f)

    return sorted(deduped, key=lambda x: x["start"])

# Test
if __name__ == "__main__":
    for t in ["Marguerite Vossberg m.vossberg@cadencefg.example M +1 (555) 0114",
              "Naomi K. Osadebe (EMP-41077, n.osadebe@cadencefg.com, +1 (646) 555-0188)",
              "Daniela Figueroa Bridgett Gatewood KC Burney"]:
        print(f"\nInput: {t}\n{detect_pii_entities(t)}")
