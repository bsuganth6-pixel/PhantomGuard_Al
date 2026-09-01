"""
app.py
-------
PhantomGuard AI web UI. Flask app; all detection logic lives in core/
(neither this file nor anything else reimplements it) so the pipeline
stays testable and reusable independent of the web layer.
"""

from __future__ import annotations
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, render_template, request, jsonify, redirect, url_for

from core.pipeline import ScanPipeline
from core import database

app = Flask(__name__)
# Vercel Functions hard-cap request bodies at 4.5 MB at the infrastructure
# level (returns its own 413 before Flask ever sees oversized requests) --
# keep our own limit under that so the app's error page fires instead of a
# raw platform error, on Vercel or anywhere else.
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4 MB upload cap

pipeline = ScanPipeline()
database.init_db()

ALLOWED_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}


def _save_upload_to_temp(file_storage) -> str:
    ext = Path(file_storage.filename or "upload.png").suffix.lower()
    if ext not in ALLOWED_IMAGE_EXT:
        ext = ".png"
    fd, path = tempfile.mkstemp(suffix=ext)
    os.close(fd)
    file_storage.save(path)
    return path


@app.route("/")
def index():
    stats = database.get_dashboard_stats()
    history = database.get_history(limit=8)
    return render_template("index.html", stats=stats, history=history)


@app.route("/scan/text", methods=["POST"])
def scan_text():
    text = (request.form.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Please paste a message or URL to scan."}), 400
    result = pipeline.scan_text(text)
    database.save_scan(result.to_dict())
    return redirect(url_for("view_result", scan_id=result.scan_id))


@app.route("/scan/screenshot", methods=["POST"])
def scan_screenshot():
    file = request.files.get("screenshot")
    if not file or not file.filename:
        return jsonify({"error": "Please choose a screenshot to upload."}), 400
    tmp_path = _save_upload_to_temp(file)
    try:
        result = pipeline.scan_screenshot(tmp_path)
    finally:
        os.unlink(tmp_path)  # never persist the uploaded image itself
    database.save_scan(result.to_dict())
    return redirect(url_for("view_result", scan_id=result.scan_id))


@app.route("/scan/qr", methods=["POST"])
def scan_qr():
    file = request.files.get("qr_image")
    if not file or not file.filename:
        return jsonify({"error": "Please choose a QR code image to upload."}), 400
    tmp_path = _save_upload_to_temp(file)
    try:
        result = pipeline.scan_qr(tmp_path)
    finally:
        os.unlink(tmp_path)
    database.save_scan(result.to_dict())
    return redirect(url_for("view_result", scan_id=result.scan_id))


@app.route("/result/<scan_id>")
def view_result(scan_id):
    result = database.get_scan(scan_id)
    if not result:
        return render_template("error.html", message="Scan not found."), 404
    return render_template("result.html", r=result)


@app.route("/history")
def history():
    rows = database.get_history(limit=100)
    return render_template("history.html", history=rows)


@app.route("/report/<scan_id>", methods=["POST"])
def report_scam(scan_id):
    was_scam = request.form.get("was_scam", "yes")
    category = request.form.get("category")
    database.save_report(scan_id, was_scam, category)
    return redirect(url_for("view_result", scan_id=scan_id))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API for programmatic access -- same pipeline the web UI uses."""
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Missing 'text' field."}), 400
    result = pipeline.scan_text(text)
    database.save_scan(result.to_dict())
    return jsonify(result.to_dict())


@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", message="File too large (max 8 MB)."), 413


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
