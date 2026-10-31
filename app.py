"""MikroTik PPPoE IP Allocation Manager: Flask backend.

Read-only toward the router. All allocation data is computed server-side; the browser
only stores UI preferences. Router credentials never leave the server.
"""
from __future__ import annotations

import csv
import hmac
import io
import json
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (Flask, Response, g, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import ip_analyzer as analyzer
import router_client
from router_client import RouterConfig, RouterError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ipmgr")

MAX_PAGE_SIZE = 500
SORT_FIELDS = {"ip": "ip_int", "status": "status", "username": "username", "profile": "profile",
               "network": "network", "session": "session", "route": "route", "comment": "comment"}
CSV_COLUMNS = ["ip", "status", "username", "profile", "secret_enabled", "session", "network",
               "route_dst", "route_gateway", "route_table", "comment", "note"]
USERNAME_MAX = 128


# =============================================================== storage

def db_path() -> Path:
    p = Path(os.environ.get("DATABASE_PATH") or "instance/app.db")
    return p if p.is_absolute() else BASE_DIR / p


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(db_path(), timeout=10)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def init_db() -> None:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            """
        )
        conn.commit()
    finally:
        conn.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _setting_defaults() -> dict:
    try:
        cap = int(os.environ.get("MAX_ADDRESSES") or analyzer.DEFAULT_MAX_ADDRESSES)
    except ValueError:
        cap = analyzer.DEFAULT_MAX_ADDRESSES
    return {"networks": [], "reserved": [], "max_addresses": cap}


def load_settings(db: sqlite3.Connection | None = None) -> dict:
    own = db is None
    conn = db or sqlite3.connect(db_path())
    try:
        data = _setting_defaults()
        for key, value in conn.execute("SELECT key, value FROM settings"):
            if key in data:
                try:
                    data[key] = json.loads(value)
                except ValueError:
                    pass
        return data
    finally:
        if own:
            conn.close()


def save_settings(db: sqlite3.Connection, data: dict) -> None:
    with db:
        for key in ("networks", "reserved", "max_addresses"):
            db.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(data[key])),
            )


def create_admin(username: str, password: str) -> None:
    conn = sqlite3.connect(db_path())
    try:
        with conn:
            conn.execute(
                "INSERT INTO admins(username, password_hash) VALUES(?, ?) "
                "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash",
                (username, generate_password_hash(password)),
            )
    finally:
        conn.close()


def seed_admin_from_env() -> None:
    conn = sqlite3.connect(db_path())
    try:
        exists = conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
    finally:
        conn.close()
    if exists:
        return
    user = (os.environ.get("ADMIN_USER") or "admin").strip()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    if len(password) >= 10:
        create_admin(user, password)
        log.info("Created admin account %r from environment.", user)
    else:
        log.warning("No admin account exists. Run `python app.py create-admin` "
                    "(or set ADMIN_PASSWORD with 10+ characters) before logging in.")


# =============================================================== router snapshot cache

class SnapshotStore:
    """Holds the last successful router snapshot and the state of the latest attempt."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.snapshot: dict | None = None
        self.snapshot_id = 0
        self.last_success_mono = 0.0
        self.last_attempt_mono = 0.0
        self.last_attempt_iso: str | None = None
        self.last_error: str | None = None
        self.error_kind: str | None = None
        self._memo_key = None
        self._memo_val = None

    def refresh(self, force: bool = False) -> None:
        ttl = float(os.environ.get("CACHE_TTL") or 15)
        with self.lock:
            now = time.monotonic()
            age = now - self.last_attempt_mono
            if self.last_attempt_mono and age < (1 if force else ttl):
                return  # another request refreshed (or failed) moments ago
            self.last_attempt_mono = now
            self.last_attempt_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                snap = router_client.fetch_snapshot(RouterConfig.from_env())
            except RouterError as exc:
                self.last_error, self.error_kind = str(exc), exc.kind
                log.warning("Router sync failed [%s]: %s", exc.kind, exc)
                return
            except Exception:  # defensive: never let a refresh crash a request
                self.last_error, self.error_kind = "Unexpected error while syncing.", "error"
                log.exception("Unexpected sync failure")
                return
            self.snapshot = snap
            self.snapshot_id += 1
            self.last_success_mono = time.monotonic()
            self.last_error = self.error_kind = None

    def status(self) -> dict:
        has = self.snapshot is not None
        stale = has and self.last_error is not None
        try:
            cfg = RouterConfig.from_env()
            host = f"{cfg.host}:{cfg.port}"
        except RouterError:
            host = None
        return {
            "connected": has and not stale,
            "has_data": has,
            "stale": stale,
            "verified": has and not stale,
            "router": host,
            "last_success": self.snapshot["fetched_at"] if has else None,
            "data_age_seconds": int(time.monotonic() - self.last_success_mono) if has else None,
            "last_attempt": self.last_attempt_iso,
            "error": self.last_error,
            "error_kind": self.error_kind,
            "fetch_ms": self.snapshot["duration_ms"] if has else None,
        }

    def analysis(self, settings: dict) -> dict:
        """Analysis of the cached snapshot (memoised per snapshot + settings + verified)."""
        snap = self.snapshot
        if snap is None:
            raise LookupError("no data")
        verified = self.last_error is None
        key = (self.snapshot_id, json.dumps(settings, sort_keys=True), verified)
        with self.lock:
            if self._memo_key == key:
                return self._memo_val
        result = analyzer.analyze(snap, settings["networks"], settings["reserved"],
                                  settings["max_addresses"], verified=verified)
        with self.lock:
            self._memo_key, self._memo_val = key, result
        return result


store = SnapshotStore()


# =============================================================== app factory

def create_app() -> Flask:
    app = Flask(__name__)
    init_db()
    seed_admin_from_env()

    key = os.environ.get("SECRET_KEY") or ""
    if not key:
        key_file = db_path().parent / "secret_key"
        if key_file.exists():
            key = key_file.read_text().strip()
        else:
            key = secrets.token_hex(32)
            key_file.write_text(key)
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
    app.config.update(
        SECRET_KEY=key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
        PERMANENT_SESSION_LIFETIME=8 * 3600,
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=False,
    )
    if os.environ.get("BEHIND_PROXY", "").lower() in ("1", "true", "yes"):
        # Trust one reverse proxy (nginx) for client IP and scheme; only enable when one is in front.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    login_failures: dict[str, list[float]] = {}

    # ---------------------------------------------------------- helpers
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def api_error(message: str, code: int, **extra):
        return jsonify({"ok": False, "error": message, **extra}), code

    def login_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return api_error("Authentication required.", 401)
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapper

    @app.teardown_appcontext
    def _close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def _csrf_check():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
            expected = session.get("csrf") or ""
            if not expected or not hmac.compare_digest(sent, expected):
                if request.path.startswith("/api/"):
                    return api_error("Invalid or missing CSRF token. Reload the page.", 403)
                return "Invalid CSRF token. Go back and reload the page.", 403

    @app.after_request
    def _headers(resp: Response):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        if request.path.startswith("/api/") or request.path in ("/", "/login"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(413)
    def _too_large(_e):
        return api_error("Request too large.", 413)

    @app.errorhandler(404)
    def _not_found(_e):
        if request.path.startswith("/api/"):
            return api_error("Not found.", 404)
        return "Not found", 404

    @app.errorhandler(500)
    def _server_error(_e):
        return api_error("Internal server error.", 500)

    # ---------------------------------------------------------- pages / auth
    @app.get("/")
    @login_required
    def index():
        return render_template("index.html", csrf_token=csrf_token(), user=session["user"])

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            now = time.time()
            recent = [t for t in login_failures.get(ip, []) if now - t < 300]
            login_failures[ip] = recent
            if len(recent) >= 5:
                error = "Too many failed attempts. Try again in a few minutes."
            else:
                username = (request.form.get("username") or "").strip()[:64]
                password = request.form.get("password") or ""
                row = get_db().execute(
                    "SELECT password_hash FROM admins WHERE username=?", (username,)).fetchone()
                dummy = "scrypt:32768:8:1$x$" + "0" * 128
                ok = check_password_hash(row["password_hash"] if row else dummy, password)
                if row and ok:
                    session.clear()
                    session.permanent = True
                    session["user"] = username
                    csrf_token()
                    login_failures.pop(ip, None)
                    return redirect(url_for("index"))
                recent.append(now)
                login_failures[ip] = recent
                error = "Invalid username or password."
        return render_template("login.html", csrf_token=csrf_token(), error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------------------------------------------------------- data helpers
    def ensure_data(force: bool = False):
        store.refresh(force=force)
        if store.snapshot is None:
            return api_error(store.last_error or "Router data is not available yet.", 503,
                             status=store.status())
        return None

    def get_analysis():
        settings = load_settings(get_db())
        if not settings["networks"]:
            return None, settings
        try:
            return store.analysis(settings), settings
        except analyzer.AddressLimitError as exc:
            raise ValueError(str(exc))

    def filter_rows(rows, args, force_status=None):
        statuses = {force_status} if force_status else {
            s for s in (args.get("status") or "").split(",") if s in analyzer.ALL_STATUSES}
        network = (args.get("network") or "").strip()
        q = (args.get("q") or "").strip().lower()
        out = []
        for r in rows:
            if statuses and r["status"] not in statuses:
                continue
            if network and r["network"] != network:
                continue
            if q and not any(q in str(r[k]).lower()
                             for k in ("ip", "username", "profile", "comment", "network", "note",
                                       "route", "route_table")):
                continue
            out.append(r)
        return out

    def public_row(r: dict) -> dict:
        return {k: v for k, v in r.items() if k != "ip_int"}

    def inventory_response(force_status=None):
        err = ensure_data()
        if err:
            return err
        try:
            result, _ = get_analysis()
        except ValueError as exc:
            return api_error(str(exc), 400)
        meta = store.status()
        if result is None:
            return jsonify({"ok": True, "status": meta, "needs_setup": True, "rows": [], "total": 0,
                            "page": 1, "pages": 1})
        rows = filter_rows(result["rows"], request.args, force_status)
        sort = request.args.get("sort", "ip")
        field = SORT_FIELDS.get(sort, "ip_int")
        reverse = request.args.get("dir", "asc") == "desc"
        if field == "ip_int":
            rows.sort(key=lambda r: r["ip_int"], reverse=reverse)
        else:
            rows.sort(key=lambda r: (str(r[field]).lower(), r["ip_int"]), reverse=reverse)
        try:
            size = max(1, min(MAX_PAGE_SIZE, int(request.args.get("page_size", 50))))
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            return api_error("page and page_size must be integers.", 400)
        pages = max(1, -(-len(rows) // size))
        page = min(page, pages)
        chunk = rows[(page - 1) * size: page * size]
        return jsonify({"ok": True, "status": meta, "rows": [public_row(r) for r in chunk],
                        "total": len(rows), "page": page, "pages": pages, "page_size": size,
                        "sort": sort, "dir": "desc" if reverse else "asc"})

    # ---------------------------------------------------------- API
    @app.get("/api/status")
    @login_required
    def api_status():
        store.refresh()
        return jsonify({"ok": True, "status": store.status()})

    @app.post("/api/sync")
    @login_required
    def api_sync():
        store.refresh(force=True)
        st = store.status()
        if not st["has_data"]:
            return api_error(st["error"] or "Router sync failed.", 502, status=st)
        return jsonify({"ok": st["connected"], "status": st,
                        "error": st["error"]})

    @app.get("/api/dashboard")
    @login_required
    def api_dashboard():
        err = ensure_data()
        if err:
            return err
        try:
            result, settings = get_analysis()
        except ValueError as exc:
            return api_error(str(exc), 400)
        meta = store.status()
        if result is None:
            return jsonify({"ok": True, "status": meta, "needs_setup": True,
                            "candidates": len(analyzer.candidate_networks(store.snapshot["routes"]))})
        return jsonify({"ok": True, "status": meta, "stats": result["stats"],
                        "networks": result["networks"], "verified": result["verified"],
                        "report_counts": {"out_of_range": len(result["out_of_range"]),
                                          "disabled": len(result["disabled_secrets"])},
                        "max_addresses": settings["max_addresses"]})

    @app.get("/api/inventory")
    @login_required
    def api_inventory():
        return inventory_response()

    @app.get("/api/assigned")
    @login_required
    def api_assigned():
        return inventory_response(analyzer.ASSIGNED)

    @app.get("/api/free")
    @login_required
    def api_free():
        err = ensure_data()
        if err:
            return err
        if not store.status()["verified"]:
            return api_error("Router data is stale, so Free IPs cannot be verified. "
                             "Showing them would be misleading.", 409, status=store.status())
        return inventory_response(analyzer.FREE)

    @app.get("/api/user/<path:username>")
    @login_required
    def api_user(username: str):
        """Details and live download/upload for one PPPoE user (read-only).

        Download = bytes the router sends to the client (interface tx);
        Upload   = bytes the router receives from the client (interface rx).
        """
        username = username.strip()
        if not username or len(username) > USERNAME_MAX:
            return api_error("Invalid username.", 400)
        err = ensure_data()
        if err:
            return err
        snap = store.snapshot
        # only names the router itself reported can be queried (no arbitrary interface lookups)
        secret = next((s for s in snap["secrets"] if str(s.get("name")) == username), None)
        session_row = next((a for a in snap["active"] if str(a.get("name")) == username), None)
        if secret is None and session_row is None:
            return api_error("Unknown PPPoE user.", 404)

        out = {
            "ok": True, "status": store.status(), "username": username,
            "profile": str((secret or {}).get("profile") or ""),
            "secret_enabled": None if secret is None else str(secret.get("disabled")).lower() not in ("true", "yes"),
            "remote_address": str((secret or {}).get("remote-address") or ""),
            "comment": str((secret or {}).get("comment") or ""),
            "online": session_row is not None,
            "address": str((session_row or {}).get("address") or ""),
            "caller_id": str((session_row or {}).get("caller-id") or ""),
            "uptime": str((session_row or {}).get("uptime") or ""),
            "traffic": None, "traffic_error": None,
        }
        if session_row is None:
            out["traffic_error"] = "User is offline: no active session, so no traffic."
            return jsonify(out)
        if snap.get("interfaces") is None:
            out["traffic_error"] = ("Traffic counters unavailable: the router user cannot read /interface.")
            return jsonify(out)
        try:
            traffic = router_client.fetch_user_traffic(RouterConfig.from_env(), f"<pppoe-{username}>")
        except RouterError as exc:
            out["traffic_error"] = str(exc)
            return jsonify(out)
        if traffic is None:
            out["traffic_error"] = "No PPPoE interface found for this session (it may have just disconnected)."
        else:
            out["traffic"] = traffic
        return jsonify(out)

    @app.get("/api/reports")
    @login_required
    def api_reports():
        err = ensure_data()
        if err:
            return err
        try:
            result, _ = get_analysis()
        except ValueError as exc:
            return api_error(str(exc), 400)
        if result is None:
            return jsonify({"ok": True, "status": store.status(), "needs_setup": True,
                            "out_of_range": [], "disabled_secrets": []})
        return jsonify({"ok": True, "status": store.status(),
                        "out_of_range": result["out_of_range"],
                        "disabled_secrets": result["disabled_secrets"]})

    @app.get("/api/networks")
    @login_required
    def api_networks_get():
        err = ensure_data()
        if err:
            return err
        settings = load_settings(get_db())
        selected = set(settings["networks"])
        cands = analyzer.candidate_networks(store.snapshot["routes"])
        for c in cands:
            c["selected"] = c["network"] in selected
        known = {c["network"] for c in cands}
        manual = [n for n in settings["networks"] if n not in known]
        return jsonify({"ok": True, "status": store.status(), "candidates": cands,
                        "manual": manual, "selected": settings["networks"],
                        "reserved": settings["reserved"],
                        "max_addresses": settings["max_addresses"],
                        "selected_addresses": analyzer.count_addresses(settings["networks"])})

    @app.put("/api/networks")
    @login_required
    def api_networks_put():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return api_error("JSON body required.", 400)
        nets_in, res_in = body.get("networks", []), body.get("reserved", [])
        if not isinstance(nets_in, list) or not isinstance(res_in, list):
            return api_error("networks and reserved must be lists.", 400)
        if len(nets_in) > 200 or len(res_in) > 5000:
            return api_error("Too many entries.", 400)
        try:
            cap = int(body.get("max_addresses", load_settings(get_db())["max_addresses"]))
        except (TypeError, ValueError):
            return api_error("max_addresses must be an integer.", 400)
        if not (256 <= cap <= 1_048_576):
            return api_error("max_addresses must be between 256 and 1,048,576.", 400)
        try:
            nets = analyzer.validate_network_list(nets_in)
            reserved = analyzer.validate_reserved_list(res_in)
        except ValueError as exc:
            return api_error(str(exc), 400)
        total = analyzer.count_addresses(nets)
        if total > cap:
            return api_error(f"Selected networks contain {total:,} addresses, above the limit "
                             f"of {cap:,}. Choose smaller networks or raise the limit.", 400)
        save_settings(get_db(), {"networks": nets, "reserved": reserved, "max_addresses": cap})
        return jsonify({"ok": True, "networks": nets, "reserved": reserved,
                        "max_addresses": cap, "selected_addresses": total})

    @app.get("/api/export.csv")
    @login_required
    def api_export():
        scope = request.args.get("scope", "all")
        if scope not in ("all", "assigned", "free"):
            return api_error("scope must be all, assigned or free.", 400)
        err = ensure_data()
        if err:
            return err
        if scope == "free" and not store.status()["verified"]:
            return api_error("Router data is stale; Free IPs cannot be verified, so no export "
                             "was produced.", 409, status=store.status())
        try:
            result, _ = get_analysis()
        except ValueError as exc:
            return api_error(str(exc), 400)
        if result is None:
            return api_error("Select networks to monitor first.", 400)
        rows = filter_rows(result["rows"], request.args,
                           scope if scope in ("assigned", "free") else None)
        rows.sort(key=lambda r: r["ip_int"])

        def safe(v):  # neutralise spreadsheet formula injection
            s = "" if v is None else str(v)
            return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_COLUMNS)
        for r in rows:
            w.writerow([safe(r.get(c)) for c in CSV_COLUMNS])
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        stale = "" if store.status()["verified"] else "-STALE"
        resp = Response("﻿" + buf.getvalue(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = f'attachment; filename="ips-{scope}-{stamp}{stale}.csv"'
        resp.headers["X-Data-Stale"] = "0" if not stale else "1"
        return resp

    return app


# =============================================================== CLI

def _cli() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "create-admin":
        import getpass
        init_db()
        user = input("Admin username [admin]: ").strip() or "admin"
        pw = getpass.getpass("Password (10+ characters): ")
        if len(pw) < 10:
            raise SystemExit("Password must be at least 10 characters.")
        if pw != getpass.getpass("Repeat password: "):
            raise SystemExit("Passwords do not match.")
        create_admin(user, pw)
        print(f"Admin {user!r} saved.")
    elif cmd == "run":
        application = create_app()
        application.run(host=os.environ.get("HOST", "127.0.0.1"),
                        port=int(os.environ.get("PORT", 5000)), debug=False, threaded=True)
    else:
        raise SystemExit("Usage: python app.py [run|create-admin]")


# Gunicorn / waitress entry point: `gunicorn app:app`
app = create_app() if __name__ != "__main__" else None

if __name__ == "__main__":
    _cli()
