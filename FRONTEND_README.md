# Cadence PII Protection — Frontend setup

## Files
- `app.py`: simple launcher for the Streamlit dashboard.
- `src/frontend/app.py`: Streamlit dashboard UI.
- `src/frontend/frontend_adapter.py`: thin adapter that calls the existing extraction and integration pipeline in `src/`.
- `FRONTEND_README.md`: these setup instructions.

## Prerequisites
- Python 3.12
- The repository backend (`src/`) already present
- Tesseract OCR for scanned-PDF OCR fallback on Ubuntu

Install OS OCR support if needed:

```bash
sudo apt update
sudo apt install tesseract-ocr
```

From the repository root, activate the existing virtual environment and install the dashboard dependency:

```bash
.venv/bin/python -m pip install 'streamlit>=1.40,<2'
```

Install backend dependencies if not already installed:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

Launch the dashboard from the repository root:

```bash
.venv/bin/python -m streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

Open `http://127.0.0.1:8501` on the same computer. Team members on the same trusted network can use the host machine's LAN IP and port 8501, provided the host is running and firewall/network rules permit it. Do not expose this prototype directly to the public internet; it has no authentication layer.

## Safety notes
- Use synthetic or approved test documents only.
- The app accepts PDF, DOCX, and PPTX uploads up to 25 MiB each.
- The app only enables sanitized-text download when the backend explicitly passes the safety gate.
- The export is sanitized text, not a reconstructed original document.
- The rule-based detector and residual validation are limited; a passing result is not a guarantee that every possible PII value has been found.
- Do not treat this prototype as a certified production security control.

## Validation
From repository root:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src tests app.py
.venv/bin/python -m pip check
git diff --check
```
