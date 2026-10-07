"""
app.py
~~~~~~
Main Flask application entry point for the Malicious URL & IP Scanner.

Run with:
    python app.py

Then open http://127.0.0.1:5000 in your browser.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    abort,
)

try:
    from flask_limiter import Limiter  # type: ignore[import-untyped]
    from flask_limiter.util import get_remote_address  # type: ignore[import-untyped]
except ImportError:
    def get_remote_address() -> str:
        return request.remote_addr or "unknown"

    class Limiter:
        """No-op fallback when Flask-Limiter is not installed."""

        def __init__(self, *args, **kwargs):
            pass

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func
            return decorator

from config import Config
from database.database import (
    init_db,
    save_scan,
    get_scan_by_id,
    get_scans,
    count_scans,
    delete_scan,
    clear_all_scans,
    get_dashboard_stats,
    get_recent_scans,
)
from scanner.validators import validate_input, InputType
from scanner.url_scanner import scan_url
from scanner.ip_scanner import scan_ip
from scanner.risk_engine import calculate_risk

# ------------------------------------------------------------------ #
# App setup
# ------------------------------------------------------------------ #
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# ------------------------------------------------------------------ #
# Security headers
# ------------------------------------------------------------------ #
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ------------------------------------------------------------------ #
# Database initialisation on startup
# ------------------------------------------------------------------ #
with app.app_context():
    try:
        init_db()
        logger.info("Database initialised.")
    except Exception as exc:
        logger.error("Database init failed: %s", exc)


# ================================================================== #
# Page routes
# ================================================================== #

@app.route("/")
def index():
    """Dashboard / home page."""
    try:
        stats = get_dashboard_stats()
        recent = get_recent_scans(limit=10)
        ext_status = Config.external_services_status()
    except Exception as exc:
        logger.error("Dashboard error: %s", exc)
        stats = _empty_stats()
        recent = []
        ext_status = {}
    return render_template("index.html", stats=stats, recent=recent, ext_status=ext_status)


@app.route("/scan")
def scan_page():
    """Dedicated scanner page."""
    ext_status = Config.external_services_status()
    return render_template("index.html", stats=_empty_stats(), recent=[], ext_status=ext_status)


@app.route("/history")
def history_page():
    """Scan history page."""
    page       = max(1, request.args.get("page", 1, type=int))
    per_page   = 20
    search     = request.args.get("search", "").strip()
    target_type = request.args.get("type", "").strip()
    verdict    = request.args.get("verdict", "").strip()

    total = count_scans(search=search, target_type=target_type, verdict=verdict)
    scans = get_scans(
        limit=per_page,
        offset=(page - 1) * per_page,
        search=search,
        target_type=target_type,
        verdict=verdict,
    )
    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "history.html",
        scans=scans,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=search,
        target_type=target_type,
        verdict=verdict,
    )


@app.route("/result/<int:scan_id>")
def result_page(scan_id: int):
    """Individual scan result page."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)
    return render_template("result.html", scan=scan)


@app.route("/about")
def about_page():
    """About / information page."""
    return render_template("about.html")


# ================================================================== #
# API routes
# ================================================================== #

@app.route("/api/scan", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT)
def api_scan():
    """
    POST /api/scan
    Body: {"target": "<url or ip>"}
    Returns: scan result JSON.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        raw_target = data.get("target", "").strip()

        if not raw_target:
            return jsonify({"success": False, "error": "Target is required."}), 400

        if len(raw_target) > Config.MAX_INPUT_LENGTH:
            return jsonify({"success": False, "error": "Input too long."}), 400

        # Validate & classify input
        input_type, normalised, err = validate_input(raw_target)
        if err:
            return jsonify({"success": False, "error": err}), 400

        scan_time = datetime.now(timezone.utc).isoformat()

        # ---- Run appropriate scanner ----
        if input_type == InputType.URL:
            scan_result = scan_url(normalised)
            indicators  = scan_result.get("indicators", {})
            risk        = calculate_risk(indicators, scan_type="URL")

            domain     = scan_result.get("parsed", {}).get("domain", "")
            ip_address = scan_result.get("technical", {}).get("ip_address", "")
            is_https   = int(indicators.get("is_https", False))
            scheme     = scan_result.get("parsed", {}).get("scheme", "")
            port       = scan_result.get("parsed", {}).get("port")

            technical_info = {
                "parsed":    scan_result.get("parsed", {}),
                "technical": scan_result.get("technical", {}),
                "errors":    scan_result.get("errors", []),
            }

        elif input_type in (InputType.IPV4, InputType.IPV6):
            ip_ver = 4 if input_type == InputType.IPV4 else 6
            scan_result = scan_ip(normalised, ip_version=ip_ver)
            indicators  = scan_result.get("indicators", {})
            ext_score   = scan_result.get("external_score", 0)
            ext_reasons = scan_result.get("external_reasons", [])
            risk        = calculate_risk(
                indicators,
                scan_type=str(input_type.value),
                external_score=ext_score,
                external_reasons=ext_reasons,
            )

            domain     = ""
            ip_address = normalised
            is_https   = 0
            scheme     = ""
            port       = None

            ip_info    = scan_result.get("ip_info", {})
            technical_info = {
                "ip_info":   ip_info,
                "technical": scan_result.get("technical", {}),
                "errors":    scan_result.get("errors", []),
            }

        else:
            return jsonify({"success": False, "error": "Could not classify input."}), 400

        # ---- Persist to database ----
        reputation_data = technical_info.get("technical", {}).get("reputation", {})

        record = {
            "target":       normalised,
            "target_type":  input_type.value,
            "scan_time":    scan_time,
            "risk_score":   risk["score"],
            "verdict":      risk["verdict"],
            "is_https":     is_https,
            "scheme":       scheme,
            "domain":       domain,
            "ip_address":   ip_address,
            "port":         port,
            "country":      technical_info.get("technical", {}).get("country", ""),
            "asn":          technical_info.get("technical", {}).get("asn", ""),
            "reverse_dns":  technical_info.get("technical", {}).get("reverse_dns") or
                            technical_info.get("ip_info", {}).get("reverse_dns", ""),
            "reputation_data": json.dumps(reputation_data),
            "risk_reasons": risk["reasons"],
            "technical_info": technical_info,
        }

        scan_id = save_scan(record)

        return jsonify({
            "success":         True,
            "scan_id":         scan_id,
            "target":          normalised,
            "type":            input_type.value,
            "risk_score":      risk["score"],
            "verdict":         risk["verdict"],
            "reasons":         risk["reasons"],
            "recommendation":  risk["recommendation"],
            "detail_table":    risk["detail_table"],
            "technical":       technical_info,
            "scan_time":       scan_time,
        })

    except Exception as exc:
        logger.error("Scan error: %s\n%s", exc, traceback.format_exc())
        return jsonify({"success": False, "error": "Internal server error. Please try again."}), 500


@app.route("/api/history", methods=["GET"])
def api_history():
    """GET /api/history – paginated scan list."""
    try:
        page        = max(1, request.args.get("page", 1, type=int))
        per_page    = min(100, request.args.get("limit", 20, type=int))
        search      = request.args.get("search", "").strip()
        target_type = request.args.get("type", "").strip()
        verdict     = request.args.get("verdict", "").strip()

        total = count_scans(search=search, target_type=target_type, verdict=verdict)
        scans = get_scans(
            limit=per_page,
            offset=(page - 1) * per_page,
            search=search,
            target_type=target_type,
            verdict=verdict,
        )
        return jsonify({
            "success": True,
            "total":   total,
            "page":    page,
            "scans":   scans,
        })
    except Exception as exc:
        logger.error("History error: %s", exc)
        return jsonify({"success": False, "error": "Failed to retrieve history."}), 500


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    """GET /api/scan/<id> – retrieve a single scan result."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True, "scan": scan})


@app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    """DELETE /api/scan/<id> – delete a single scan."""
    deleted = delete_scan(scan_id)
    if not deleted:
        return jsonify({"success": False, "error": "Scan not found."}), 404
    return jsonify({"success": True, "message": f"Scan {scan_id} deleted."})


@app.route("/api/history/clear", methods=["DELETE"])
def api_clear_history():
    """DELETE /api/history/clear – delete all scans."""
    count = clear_all_scans()
    return jsonify({"success": True, "deleted": count})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """GET /api/stats – dashboard statistics."""
    try:
        stats = get_dashboard_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as exc:
        logger.error("Stats error: %s", exc)
        return jsonify({"success": False, "error": "Failed to get stats."}), 500


@app.route("/api/demo", methods=["POST"])
def api_demo():
    """POST /api/demo – run a pre-defined safe demo scan."""
    demos = [
        "https://example.com",
        "8.8.8.8",
        "2001:4860:4860::8888",
    ]
    idx = request.get_json(force=True, silent=True) or {}
    target = demos[int(idx.get("index", 0)) % len(demos)]
    # Reuse main scan endpoint logic by calling it internally
    with app.test_request_context(
        "/api/scan",
        method="POST",
        json={"target": target},
        content_type="application/json",
    ):
        return api_scan()


# ------------------------------------------------------------------ #
# Error handlers
# ------------------------------------------------------------------ #

@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Not found."}), 404
    return render_template("base.html", error="Page not found.", error_code=404), 404


@app.errorhandler(429)
def rate_limited(_):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Rate limit exceeded. Please wait a moment."}), 429
    return render_template("base.html", error="Too many requests. Please slow down.", error_code=429), 429


@app.errorhandler(500)
def server_error(_):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal server error."}), 500
    return render_template("base.html", error="Internal server error.", error_code=500), 500


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _empty_stats() -> Dict[str, Any]:
    return {
        "total": 0,
        "safe_count": 0,
        "low_risk_count": 0,
        "suspicious_count": 0,
        "high_risk_count": 0,
        "malicious_count": 0,
        "url_count": 0,
        "ipv4_count": 0,
        "ipv6_count": 0,
        "daily_scans": [],
    }


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=Config.DEBUG,
    )
