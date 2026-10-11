"""Cadence PII Protection — local Streamlit review dashboard."""
from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from frontend_adapter import (
    MAX_UPLOAD_BYTES,
    UploadValidationError,
    history_summary,
    process_uploaded_document,
    sanitized_text_export,
)

st.set_page_config(
    page_title="Cadence PII Protection",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root { --ink:#172033; --muted:#6b7280; --line:#e6e9ef; --paper:#f6f7fb; --purple:#6257d9; --purple-soft:#f0efff; --teal:#0f766e; }
    html, body, [class*="css"] { font-family:'DM Sans',sans-serif; }
    .stApp { background:var(--paper); color:var(--ink); }
    [data-testid="stHeader"] { background:rgba(246,247,251,.88); }
    [data-testid="stSidebar"] { background:#fff; border-right:1px solid var(--line); }
    [data-testid="stSidebar"] > div:first-child { padding-top:1.2rem; }
    .brand { display:flex; align-items:center; gap:10px; padding:4px 2px 19px; border-bottom:1px solid var(--line); margin-bottom:20px; }
    .brand-mark { width:38px;height:38px;border-radius:12px;background:#6257d9;color:white;display:flex;align-items:center;justify-content:center;font-size:23px;font-weight:700; }
    .brand-name { font-family:Manrope,sans-serif;font-weight:800;font-size:17px;letter-spacing:-.5px;line-height:1.1; }
    .brand-sub { font-size:10px;letter-spacing:1.7px;color:#81879a;margin-top:5px;font-weight:700; }
    .privacy-note { background:#f5f7fb;border:1px solid #e7eaf1;border-radius:12px;padding:12px 13px;font-size:12px;color:#5f687b;line-height:1.55;margin-top:20px; }
    .privacy-note b { color:#283249; }
    .eyebrow { font-size:11px; font-weight:800; letter-spacing:1.8px; color:var(--purple); text-transform:uppercase; margin-bottom:7px; }
    .page-title { font-family:Manrope,sans-serif; font-weight:800; letter-spacing:-1.4px; font-size:34px; line-height:1.12; color:#182137; margin:0; }
    .page-subtitle { color:#727a8c; font-size:14px; margin-top:9px; line-height:1.6; }
    .local-pill { display:inline-flex; gap:7px; align-items:center; border-radius:30px; padding:7px 11px; border:1px solid #cfe7e1; background:#effaf7; color:#147568; font-size:11px; font-weight:800; letter-spacing:.5px; white-space:nowrap; }
    .metric-card { background:#fff;border:1px solid var(--line);border-radius:16px;padding:17px 18px;min-height:120px;box-shadow:0 2px 6px rgba(20,28,48,.025); }
    .metric-label { color:#747d90;font-size:12px;font-weight:600;margin-bottom:15px; }
    .metric-value { color:#19233a;font-family:Manrope,sans-serif;font-size:30px;line-height:1;font-weight:800;letter-spacing:-1px; }
    .metric-foot { color:#8991a1;font-size:11px;margin-top:10px; }
    .section-head { font-family:Manrope,sans-serif;font-size:18px;font-weight:800;letter-spacing:-.35px;color:#202a40;margin:2px 0 4px; }
    .section-desc { font-size:12px;color:#798194;margin:0 0 14px; }
    .surface { background:#fff;border:1px solid var(--line);border-radius:16px;padding:18px 20px; }
    .empty { border:1px dashed #d5d9e4;background:#fff;border-radius:16px;text-align:center;padding:34px 20px;color:#7c8495; }
    .empty-symbol { width:44px;height:44px;border-radius:14px;background:#f0efff;color:#6257d9;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:22px; }
    .empty-title { font-family:Manrope,sans-serif;font-weight:800;color:#263047;font-size:15px;margin-bottom:5px; }
    .status-chip { display:inline-block;padding:5px 9px;border-radius:20px;font-size:11px;font-weight:800;letter-spacing:.2px; }
    .status-validated { color:#08735f;background:#e8f7f2;border:1px solid #c8e9de; }
    .status-blocked { color:#a03939;background:#fff0ee;border:1px solid #f7d0ca; }
    .status-review { color:#92620c;background:#fff8e6;border:1px solid #f1e0ac; }
    .status-failed { color:#813f96;background:#f9effb;border:1px solid #ecd3f3; }
    .decision-card { border:1px solid var(--line);background:white;border-radius:15px;padding:15px 17px;margin:8px 0 15px; }
    .decision-title { color:#202a40;font-family:Manrope,sans-serif;font-size:17px;font-weight:800; }
    .decision-copy { font-size:12px;color:#727a8c;margin-top:6px;line-height:1.6; }
    div[data-testid="stFileUploader"] { border-radius:14px; }
    div[data-testid="stFileUploaderDropzone"] { border:1px dashed #bfc4e9; background:#fbfaff; border-radius:14px; }
    .stButton > button, .stDownloadButton > button { border-radius:10px; min-height:42px; font-weight:700; }
    .stButton > button[kind="primary"] { background:#6257d9;border-color:#6257d9; }
    div[data-testid="stDataFrame"] { border:1px solid var(--line);border-radius:12px;overflow:hidden; }
    .small-muted { font-size:11px;color:#858da0; }
    .flow { display:flex; gap:7px; flex-wrap:wrap; margin:10px 0 18px; }
    .flow-step { background:#fff;border:1px solid var(--line);border-radius:9px;padding:8px 10px;color:#687185;font-size:11px;font-weight:700; }
    .flow-step.done { border-color:#c9e8df;background:#f1faf7;color:#176f60; }
    .flow-step.warn { border-color:#f1dfad;background:#fff9eb;color:#8a650f; }
    @media (max-width:700px) { .page-title{font-size:28px}.metric-value{font-size:25px}.surface{padding:14px} }
    </style>
    """,
    unsafe_allow_html=True,
)

if "cadence_results" not in st.session_state:
    st.session_state.cadence_results = []
if "cadence_upload_errors" not in st.session_state:
    st.session_state.cadence_upload_errors = []


def escape(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


def status_label(status: str) -> tuple[str, str, str]:
    mapping = {
        "validated": ("Validated", "status-validated", "The backend explicitly marked the document safe, validation passed, and extraction completed without reported errors."),
        "blocked": ("Blocked", "status-blocked", "The backend validation or safety gate failed. This document must not proceed downstream."),
        "review_required": ("Review required", "status-review", "A required result is incomplete or unavailable. Safety has not been established."),
        "processing_failed": ("Processing failed", "status-failed", "Processing did not produce a trustworthy result. Safety has not been established."),
    }
    return mapping.get(status, mapping["review_required"])


def page_header(eyebrow: str, title: str, subtitle: str) -> None:
    left, right = st.columns([5, 1.4])
    with left:
        st.markdown(f'<div class="eyebrow">{escape(eyebrow)}</div><h1 class="page-title">{escape(title)}</h1><div class="page-subtitle">{escape(subtitle)}</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div style="text-align:right"><span class="local-pill">● LOCAL PROCESSING</span><div class="small-muted" style="margin-top:8px">No external AI APIs</div></div>', unsafe_allow_html=True)


def metric_card(label: str, value: object, foot: str) -> None:
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{escape(label)}</div><div class="metric-value">{escape(value)}</div><div class="metric-foot">{escape(foot)}</div></div>',
        unsafe_allow_html=True,
    )


def render_history(results: list[dict], limit: int = 8) -> None:
    if not results:
        st.markdown('<div class="empty"><div class="empty-symbol">◈</div><div class="empty-title">No documents processed yet</div><div>Upload a PDF, Word document, or PowerPoint to create your first session record.</div></div>', unsafe_allow_html=True)
        return
    records = []
    for item in reversed(results[-limit:]):
        summary = history_summary(item)
        label, _, _ = status_label(summary["decision"])
        records.append({
            "Document": summary["filename"],
            "Processed at": summary["processed_at"],
            "Extraction": summary["extraction_status"],
            "PII findings": summary["pii_findings"],
            "Redactions": summary["redactions"],
            "Safety decision": label,
        })
    st.dataframe(records, use_container_width=True, hide_index=True)


def render_detail(result: dict) -> None:
    label, css, explanation = status_label(str(result.get("gate_status", "review_required")))
    st.markdown(f'<div class="decision-card"><span class="status-chip {css}">{escape(label)}</span><div class="decision-title" style="margin-top:10px">{escape(result.get("filename", "Document"))}</div><div class="decision-copy">{escape(explanation)}</div></div>', unsafe_allow_html=True)
    if result.get("message"):
        st.warning(result["message"])

    # Stage labels are based only on returned backend outcomes; no artificial percentages.
    extraction = result.get("extraction", {})
    validation = result.get("validation", {})
    extracted_ok = extraction.get("complete") is True and not extraction.get("errors")
    pipeline_ran = result.get("processing_status") not in (None, "unknown", "failed") or bool(result.get("audit_events")) or bool(result.get("units"))
    validation_known = isinstance(validation, dict) and isinstance(validation.get("passed"), bool)
    steps = [
        ("1 · Received", True, False),
        ("2 · Extraction", extracted_ok, not extracted_ok),
        ("3 · PII detection", pipeline_ran, not pipeline_ran),
        ("4 · Redaction", pipeline_ran, not pipeline_ran),
        ("5 · Validation", validation_known and validation.get("passed") is True, validation_known and validation.get("passed") is False),
        ("6 · Safety decision", result.get("safe_to_process") is True, result.get("gate_status") in ("blocked", "processing_failed", "review_required")),
    ]
    step_html = '<div class="flow">' + ''.join(
        f'<span class="flow-step {"done" if good else "warn" if warn else ""}">{escape(name)} {"✓" if good else "!" if warn else "·"}</span>'
        for name, good, warn in steps
    ) + '</div>'
    st.markdown(step_html, unsafe_allow_html=True)
    st.caption("The backend exposes synchronous results rather than live stage-by-stage progress. These indicators summarize the completed response; they are not a real-time progress bar.")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Extracted blocks", extraction.get("total_blocks", 0), "Backend extraction result")
    with c2:
        metric_card("PII findings", result.get("pii_count", 0), "Audit events returned by backend")
    with c3:
        metric_card("Redactions", result.get("redaction_count", 0), "Replacement audit events")
    with c4:
        retention = extraction.get("retention")
        retention_status = str(extraction.get("retention_status", "unknown"))
        retention_display = "Not measured" if retention is None or "not_measured" in retention_status else str(retention)
        metric_card("Text retention", retention_display, "No reference comparison is configured by default")

    st.markdown('<div class="section-head" style="margin-top:24px">Extraction report</div><div class="section-desc">Structure and status only; original extracted text is not retained by the frontend adapter.</div>', unsafe_allow_html=True)
    reports = extraction.get("reports", [])
    if reports:
        st.dataframe([
            {"File": str(r.get("file", result.get("filename", "Document"))), "Document type": str(r.get("type", "Unknown")), "Blocks": r.get("blocks", 0), "Status": str(r.get("status", "unknown")).title()}
            for r in reports if isinstance(r, dict)
        ], use_container_width=True, hide_index=True)
    else:
        st.info("The extraction engine did not return a file-level report.")
    st.write(f"**Extraction complete:** {'Yes' if extraction.get('complete') is True else 'No'}")
    st.write(f"**Errors reported:** {len(extraction.get('errors', []))}")
    if extraction.get("errors"):
        st.dataframe(extraction["errors"], use_container_width=True, hide_index=True)
    if extraction.get("block_summaries"):
        with st.expander("View extracted block metadata"):
            st.dataframe(extraction["block_summaries"], use_container_width=True, hide_index=True)

    st.markdown('<div class="section-head" style="margin-top:24px">PII detection & redaction</div><div class="section-desc">Category totals come from the backend redaction audit events. Original matched values are never displayed here.</div>', unsafe_allow_html=True)
    counts = result.get("pii_counts", {})
    if counts:
        st.dataframe([{"PII category": key.replace("_", " ").title(), "Findings": value} for key, value in sorted(counts.items())], use_container_width=True, hide_index=True)
    else:
        if extraction.get("complete") is True and result.get("processing_status") not in ("failed", "unknown"):
            st.info("The backend returned no redaction audit events. This is not a guarantee that the document contains no PII.")
        else:
            st.info("PII detection results are unavailable because processing did not complete reliably.")

    st.markdown('<div class="section-head" style="margin-top:24px">Validation & safety checks</div><div class="section-desc">Approval is fail-closed: any missing requirement means the document is not approved.</div>', unsafe_allow_html=True)
    st.write(f"**Backend `safe_to_process`:** {result.get('backend_safe_to_process') if result.get('backend_safe_to_process') is not None else 'Unavailable'}")
    st.write(f"**Validation passed:** {validation.get('passed') if validation.get('passed') is not None else 'Unavailable'}")
    if validation.get("checks"):
        st.dataframe(validation["checks"], use_container_width=True, hide_index=True)
    if validation.get("issues"):
        st.markdown("**Issues reported**")
        st.dataframe(validation["issues"], use_container_width=True, hide_index=True)

    st.markdown('<div class="section-head" style="margin-top:24px">Sanitized preview</div><div class="section-desc">This is the processed text returned by the backend, not a reconstructed PDF, DOCX, or PPTX.</div>', unsafe_allow_html=True)
    if result.get("gate_status") != "validated":
        st.warning("The safety gate is not passed. The preview is available for review only; downstream use and download remain disabled.")
    units = result.get("units", [])
    has_text = any(block.get("text") for unit in units for block in unit.get("blocks", []) if isinstance(block, dict))
    if has_text:
        with st.expander("Open sanitized text preview", expanded=False):
            for unit in units:
                unit_type = str(unit.get("unit_type", "unit")).title()
                unit_no = unit.get("unit_number", "?")
                st.markdown(f"**{unit_type} {unit_no}**")
                for block in unit.get("blocks", []):
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        st.code(block["text"], language=None)
        if result.get("safe_to_process") is True:
            export = sanitized_text_export(result)
            stem = Path(str(result.get("filename", "document"))).stem or "document"
            st.download_button(
                "Download sanitized text (.txt)",
                data=export.encode("utf-8"),
                file_name=f"{stem}.sanitized.txt",
                mime="text/plain; charset=utf-8",
                type="primary",
                key=f"download-{result.get('document_id')}",
            )
            st.caption("Text-only export. Original document formatting and layout are not reconstructed.")
        else:
            st.button("Download disabled — safety gate not passed", disabled=True, key=f"blocked-download-{result.get('document_id')}")
    else:
        st.info("No sanitized text is available to preview.")

    st.markdown('<div class="section-head" style="margin-top:24px">Audit trail</div><div class="section-desc">Backend-provided events with matched source values excluded. This is an application audit view, not a claim of immutable logging.</div>', unsafe_allow_html=True)
    events = result.get("audit_events", [])
    if events:
        st.dataframe(events, use_container_width=True, hide_index=True)
    else:
        st.markdown('<div class="empty" style="padding:22px"><div class="empty-title">No audit events returned</div><div>No redaction events are available for this document.</div></div>', unsafe_allow_html=True)


with st.sidebar:
    st.markdown('<div class="brand"><div class="brand-mark">◈</div><div><div class="brand-name">Cadence</div><div class="brand-sub">PII PROTECTION</div></div></div>', unsafe_allow_html=True)
    st.markdown('<div class="eyebrow">WORKSPACE</div>', unsafe_allow_html=True)
    page = st.radio("Navigation", ["Overview", "Process documents", "Results & audit"], label_visibility="collapsed")
    st.markdown('<div class="privacy-note"><b>◉ Privacy by design</b><br>Documents are processed locally through the bundled Python backend. Upload bytes use temporary storage and are removed after processing. Session results are not written to a database.</div>', unsafe_allow_html=True)
    st.markdown('<div class="small-muted" style="margin-top:15px">DEMO BUILD · BACKEND RULE-BASED DETECTOR</div>', unsafe_allow_html=True)
    st.divider()
    if st.checkbox("I understand this clears session results"):
        if st.button("Clear session results", use_container_width=True):
            st.session_state.cadence_results = []
            st.session_state.cadence_upload_errors = []
            st.rerun()

results = st.session_state.cadence_results

if page == "Overview":
    page_header("Security workspace", "Cadence PII Protection", "Inspect, redact, and validate sensitive document content before downstream AI workflows.")
    st.write("")
    total = len(results)
    validated = sum(1 for r in results if r.get("gate_status") == "validated")
    review_blocked = sum(1 for r in results if r.get("gate_status") in ("blocked", "review_required", "processing_failed"))
    findings = sum(int(r.get("pii_count", 0) or 0) for r in results)
    cards = st.columns(4, gap="medium")
    with cards[0]: metric_card("Documents processed", total, "This browser session only")
    with cards[1]: metric_card("Validated documents", validated, "Backend safety gate passed")
    with cards[2]: metric_card("Blocked / review", review_blocked, "Not approved for downstream use")
    with cards[3]: metric_card("PII findings", findings, "Total audit findings, not unique documents")
    st.write("")
    st.markdown('<div class="section-head">Recent processing activity</div><div class="section-desc">Session history contains document metadata and counts, not original document text.</div>', unsafe_allow_html=True)
    render_history(results)
    st.write("")
    left, right = st.columns([1.05, 1])
    with left:
        st.markdown('<div class="surface"><div class="section-head">Document workflow</div><div class="section-desc">The bundled backend performs the actual work.</div><div class="flow"><span class="flow-step">01 · Upload</span><span class="flow-step">02 · Extract</span><span class="flow-step">03 · Detect PII</span><span class="flow-step">04 · Redact</span><span class="flow-step">05 · Validate</span><span class="flow-step">06 · Decide</span></div><div class="small-muted">No artificial live progress is shown because the current backend exposes a synchronous pipeline.</div></div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="surface"><div class="section-head">Safety policy</div><div class="section-desc">The interface fails closed.</div><p style="font-size:13px;color:#606a7d;line-height:1.65">A file can be marked <b>Validated</b> only when extraction is complete and error-free, validation explicitly passes, and the backend explicitly returns <code>safe_to_process = true</code>. Missing or conflicting results never imply approval.</p></div>', unsafe_allow_html=True)

elif page == "Process documents":
    page_header("Secure intake", "Process documents", "Upload PDF, DOCX, or PPTX files. Each document receives an independent backend result and safety decision.")
    st.write("")
    st.markdown('<div class="surface"><div class="section-head">Add documents</div><div class="section-desc">Files stay local. Each file is processed independently and temporary source files are removed afterward.</div></div>', unsafe_allow_html=True)
    uploads = st.file_uploader(
        "Drop files here or browse",
        type=["pdf", "docx", "pptx"],
        accept_multiple_files=True,
        help="PDF, DOCX, and PPTX only · Maximum 25 MiB per file · Scanned PDF OCR requires local Tesseract.",
        key="cadence-upload-widget",
    )
    if uploads:
        st.markdown("**Selected files**")
        selected_rows = []
        for upload in uploads:
            selected_rows.append({"Filename": Path(upload.name).name, "Format": Path(upload.name).suffix.upper().lstrip("."), "Size": format_size(upload.size), "Status": "Ready" if upload.size <= MAX_UPLOAD_BYTES else "Over size limit"})
        st.dataframe(selected_rows, use_container_width=True, hide_index=True)
        st.caption("Remove a file using the × control in the uploader before processing. Empty files and unreadable documents will be shown as review/processing failures.")
        if any(upload.size > MAX_UPLOAD_BYTES for upload in uploads):
            st.error("At least one selected file exceeds the 25 MiB per-file limit. Remove it or select a smaller file.")
        process_clicked = st.button("Process selected documents", type="primary", disabled=any(upload.size > MAX_UPLOAD_BYTES for upload in uploads), use_container_width=True)
        if process_clicked:
            newly_processed = []
            upload_errors = []
            for upload in uploads:
                filename = Path(upload.name).name
                try:
                    with st.spinner(f"Running the bundled backend for {filename}…"):
                        result = process_uploaded_document(filename, upload.getvalue())
                    newly_processed.append(result)
                except UploadValidationError as exc:
                    upload_errors.append({"filename": filename, "error": str(exc)})
                except Exception:
                    # Do not show tracebacks or data-bearing exception strings.
                    upload_errors.append({"filename": filename, "error": "This file could not be processed. Check the format and try again."})
            st.session_state.cadence_results.extend(newly_processed)
            st.session_state.cadence_upload_errors = upload_errors
            if newly_processed:
                st.success(f"Finished processing {len(newly_processed)} document(s). Review each decision below.")
            if upload_errors:
                for error in upload_errors:
                    st.error(f"{error['filename']}: {error['error']}")
            if newly_processed:
                st.markdown("### Latest results")
                for result in newly_processed:
                    label, css, _ = status_label(result.get("gate_status", "review_required"))
                    st.markdown(f'<div class="decision-card"><span class="status-chip {css}">{escape(label)}</span><div class="decision-title" style="margin-top:8px">{escape(result.get("filename"))}</div><div class="decision-copy">{int(result.get("pii_count", 0))} PII finding(s) · {int(result.get("redaction_count", 0))} redaction(s)</div></div>', unsafe_allow_html=True)
                st.info("Open ‘Results & audit’ to inspect extraction status, validation checks, sanitized previews, and privacy-safe audit events.")
    else:
        st.markdown('<div class="empty"><div class="empty-symbol">↑</div><div class="empty-title">Ready for a document</div><div>Drag files into the drop zone, or use the browse control above.</div><div class="small-muted" style="margin-top:10px">Supported: PDF · DOCX · PPTX &nbsp; | &nbsp; 25 MiB maximum per file</div></div>', unsafe_allow_html=True)
    st.write("")
    st.markdown('<div class="section-head">Before you upload</div>', unsafe_allow_html=True)
    st.markdown("- Use synthetic or approved documents for this prototype.\n- Extraction and detection run through the local bundled backend; no external AI service is called.\n- Scanned PDF OCR depends on Tesseract being installed on the machine.\n- A passing configured validation check is not a guarantee that every possible PII value has been found.")

else:
    page_header("Review center", "Results & audit", "Inspect sanitized output, backend validation, and audit events. Original matched PII values are intentionally omitted.")
    st.write("")
    if not results:
        st.markdown('<div class="empty"><div class="empty-symbol">✓</div><div class="empty-title">Nothing to review yet</div><div>Process a document first, then its backend results will appear here.</div></div>', unsafe_allow_html=True)
    else:
        options = {
            f"{r.get('filename', 'Document')} · {str(r.get('document_id', ''))[-6:]} · {status_label(str(r.get('gate_status', 'review_required')))[0]}": r
            for r in reversed(results)
        }
        selected_label = st.selectbox("Choose a document", list(options.keys()))
        render_detail(options[selected_label])

st.markdown('<div style="height:18px"></div><div style="border-top:1px solid #e4e7ef;padding-top:14px;color:#9299a8;font-size:11px">CADENCE PII PROTECTION · LOCAL CASE-STUDY DEMO · NOT A CERTIFIED PRODUCTION SECURITY CONTROL</div>', unsafe_allow_html=True)
