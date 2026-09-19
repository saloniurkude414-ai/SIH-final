import json
import os
import shutil
import uuid
from pathlib import Path
from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from recovery.recovery_engine import RecoveryEngine
from sanitization.sanitization_engine import SanitizationEngine
from analysis.forensic_analyzer import ForensicAnalyzer
from forensics import ForensicManager
from reporting import ReportBuilder
from secure_file import encrypt_file, decrypt_file, SecureFileError

BASE_DIR = Path(__file__).resolve().parent
WORK_DIR = BASE_DIR / "web_workspace"
WORK_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("DATARESQ_SECRET", "dataresq-demo-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB demo upload limit


def workspace():
    sid = session.get("workspace_id")
    if not sid:
        sid = uuid.uuid4().hex
        session["workspace_id"] = sid
    path = WORK_DIR / sid
    path.mkdir(parents=True, exist_ok=True)
    return path


def files_in_workspace():
    root = workspace()
    return [p for p in root.rglob("*") if p.is_file() and p.name != "audit.jsonl" and not p.name.endswith(".json")]


def fmt_size(size):
    size = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return "0 B"


@app.template_filter("filesize")
def filesize_filter(value):
    return fmt_size(value)


def dashboard_counts():
    root = workspace()
    all_files = files_in_workspace()
    recovered = len(list(root.glob("recovered/*"))) if (root / "recovered").exists() else 0
    events = 0
    audit = root / "audit.jsonl"
    if audit.exists():
        try:
            events = len(audit.read_text(encoding="utf-8").splitlines())
        except OSError:
            pass
    return len(all_files), recovered, events


@app.route("/")
def index():
    uploaded, recovered, events = dashboard_counts()
    return render_template("index.html", uploaded=uploaded, recovered=recovered, events=events,
                           files=files_in_workspace(), workspace_root=workspace())


@app.post("/upload")
def upload():
    target = workspace() / "evidence"
    target.mkdir(exist_ok=True)
    incoming = request.files.getlist("files")
    saved = 0
    for item in incoming:
        if not item or not item.filename:
            continue
        name = secure_filename(item.filename)
        if not name:
            continue
        # Avoid overwriting a previous upload with the same name.
        destination = target / name
        if destination.exists():
            destination = target / f"{destination.stem}_{uuid.uuid4().hex[:6]}{destination.suffix}"
        item.save(destination)
        saved += 1
    if saved:
        flash(f"{saved} evidence file(s) uploaded successfully.", "success")
    else:
        flash("Choose at least one file.", "error")
    return redirect(url_for("index"))


@app.post("/scan")
def scan():
    root = workspace() / "evidence"
    if not root.exists() or not any(root.rglob("*")):
        flash("Upload evidence files before scanning.", "error")
        return redirect(url_for("index") + "#recovery")
    try:
        rows = RecoveryEngine().scan_directory(str(root))
        workspace().joinpath("scan_results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        ForensicManager(str(workspace() / "cases")).add_event("RECOVERY_SCAN", {"source": str(root), "items": len(rows)})
        flash(f"Scan complete: {len(rows)} item(s) analyzed.", "success")
    except Exception as exc:
        flash(f"Scan failed: {exc}", "error")
    return redirect(url_for("index") + "#recovery")


@app.route("/scan-results")
def scan_results():
    p = workspace() / "scan_results.json"
    rows = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    return render_template("results.html", rows=rows, title="Recovery Scan Results")


@app.post("/carve")
def carve():
    file_id = request.form.get("file")
    source = find_workspace_file(file_id)
    if not source:
        flash("Select a valid uploaded disk image.", "error")
        return redirect(url_for("index") + "#recovery")
    try:
        rows = RecoveryEngine().deep_carve(str(source))
        p = workspace() / "carve_results.json"
        p.write_text(json.dumps({"source": str(source), "rows": rows}, indent=2), encoding="utf-8")
        flash(f"Deep signature carving complete: {len(rows)} signature(s) found.", "success")
    except Exception as exc:
        flash(f"Carving failed: {exc}", "error")
    return redirect(url_for("index") + "#recovery")


@app.route("/carve-results")
def carve_results():
    p = workspace() / "carve_results.json"
    data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"source": "", "rows": []}
    return render_template("carve_results.html", source=data.get("source", ""), rows=data.get("rows", []))


@app.get("/recover/<int:index>")
def recover(index):
    p = workspace() / "carve_results.json"
    if not p.exists():
        flash("Run deep carving first.", "error")
        return redirect(url_for("index"))
    data = json.loads(p.read_text(encoding="utf-8"))
    rows = data.get("rows", [])
    if index < 0 or index >= len(rows):
        flash("Invalid recovery item.", "error")
        return redirect(url_for("carve_results"))
    source = Path(data["source"])
    if not source.is_file():
        flash("The source image is no longer available.", "error")
        return redirect(url_for("carve_results"))
    out_dir = workspace() / "recovered"
    out_dir.mkdir(exist_ok=True)
    row = rows[index]
    name = f"recovered_{index:03d}{row.get('extension', '.bin')}"
    out = out_dir / name
    RecoveryEngine().carver.extract(str(source), row, str(out))
    return send_file(out, as_attachment=True, download_name=name)


def find_workspace_file(name):
    if not name:
        return None
    root = workspace().resolve()
    candidate = (root / name).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


@app.post("/erase")
def erase():
    name = request.form.get("file")
    source = find_workspace_file(name)
    if not source:
        flash("Select a valid uploaded file.", "error")
        return redirect(url_for("index") + "#erase")
    try:
        passes = max(1, min(int(request.form.get("passes", 1)), 5))
        sanitizer = SanitizationEngine(str(workspace() / "audit.jsonl"))
        result = sanitizer.secure_delete_file(str(source), passes=passes, pattern="zero", verify=True)
        ForensicManager(str(workspace() / "cases")).add_event("FILE_ERASURE", result)
        flash(f"Secure erasure completed. Verification: {result.get('verification')}", "success")
    except Exception as exc:
        flash(f"Erasure failed: {exc}", "error")
    return redirect(url_for("index") + "#erase")


@app.post("/analyze")
def analyze():
    name = request.form.get("file")
    source = find_workspace_file(name)
    if not source:
        flash("Select a valid evidence file.", "error")
        return redirect(url_for("index") + "#analysis")
    try:
        result = ForensicAnalyzer().analyze_file(str(source))
        (workspace() / "analysis_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        flash("Evidence metadata and SHA-256 hash generated.", "success")
    except Exception as exc:
        flash(f"Analysis failed: {exc}", "error")
    return redirect(url_for("index") + "#analysis")


@app.post("/encrypt")
def encrypt():
    name = request.form.get("file")
    password = request.form.get("password", "")
    source = find_workspace_file(name)
    if not source or not password:
        flash("Select a file and enter a password.", "error")
        return redirect(url_for("index") + "#secure-file")
    out = workspace() / "encrypted"
    out.mkdir(exist_ok=True)
    destination = out / f"{source.name}.drq"
    try:
        result = encrypt_file(str(source), str(destination), password)
        flash("AES-256-GCM encryption completed.", "success")
        return send_file(destination, as_attachment=True, download_name=destination.name)
    except Exception as exc:
        flash(f"Encryption failed: {exc}", "error")
        return redirect(url_for("index") + "#secure-file")


@app.post("/decrypt")
def decrypt():
    name = request.form.get("file")
    password = request.form.get("password", "")
    source = find_workspace_file(name)
    if not source or not password:
        flash("Select a .drq file and enter its password.", "error")
        return redirect(url_for("index") + "#secure-file")
    out = workspace() / "decrypted"
    out.mkdir(exist_ok=True)
    destination = out / (source.stem + "_decrypted")
    try:
        decrypt_file(str(source), str(destination), password)
        return send_file(destination, as_attachment=True, download_name=destination.name)
    except SecureFileError as exc:
        flash(str(exc), "error")
    except Exception as exc:
        flash(f"Decryption failed: {exc}", "error")
    return redirect(url_for("index") + "#secure-file")


@app.get("/report")
def report():
    root = workspace()
    sections = []
    scan = root / "scan_results.json"
    if scan.exists():
        rows = json.loads(scan.read_text(encoding="utf-8"))
        sections.append(("Recovery Scan", {"Items analyzed": len(rows), "Verified signatures": sum(1 for r in rows if r.get("status") == "SIGNATURE VERIFIED")}))
    analysis = root / "analysis_result.json"
    if analysis.exists():
        a = json.loads(analysis.read_text(encoding="utf-8"))
        sections.append(("Evidence Analysis", a))
    carve = root / "carve_results.json"
    if carve.exists():
        c = json.loads(carve.read_text(encoding="utf-8"))
        sections.append(("File Carving", {"Source": c.get("source", ""), "Signatures found": len(c.get("rows", []))}))
    audit = root / "audit.jsonl"
    if audit.exists():
        events = audit.read_text(encoding="utf-8").splitlines()
        sections.append(("Sanitization Audit", {"Audit events": len(events)}))
    if not sections:
        sections.append(("DataResQ Status", {"Message": "No analysis has been run yet."}))
    out = root / "DataResQ_Forensic_Report.html"
    ReportBuilder(str(root)).build({"sections": sections}, str(out))
    return send_file(out, as_attachment=True, download_name="DataResQ_Forensic_Report.html")


@app.post("/clear")
def clear_workspace():
    sid = session.get("workspace_id")
    if sid:
        path = WORK_DIR / sid
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
    session.pop("workspace_id", None)
    flash("Workspace cleared.", "success")
    return redirect(url_for("index"))


@app.errorhandler(413)
def too_large(_):
    flash("Upload is too large. The web demo allows files up to 100 MB.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
