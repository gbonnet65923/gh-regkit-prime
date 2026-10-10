#!/usr/bin/env python3
"""FastAPI control plane for the GitHub register toolkit."""
from __future__ import annotations

import asyncio
import collections
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = ROOT / "accounts"
RECOVERY_DIR = ACCOUNTS_DIR / "recovery"
GROUPS_FILE = ACCOUNTS_DIR / "groups.json"
_groups_lock = threading.Lock()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from github_register.config import Config, load_config
from github_register.mailcx import MailCxClient
from github_register.runner import load_proxy_pool, run_job, silence_playwright_noise

silence_playwright_noise()  # hide TargetClosedError spam when browsers close


def _load_dotenv() -> None:
    """Minimal .env loader (stdlib only): KEY=VALUE, # comments, quoted values."""
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = val


_load_dotenv()

# Auth like n8n/WAHA: username+password from .env for self-hosting/production.
# New: GITHUB_REGISTER_USERNAME + GITHUB_REGISTER_PASSWORD.
# Legacy (compatible): GITHUB_REGISTER_ACCESS_PASSWORD (password-only, no username).
AUTH_USERNAME = (os.getenv("GITHUB_REGISTER_USERNAME") or "").strip()
AUTH_PASSWORD = (os.getenv("GITHUB_REGISTER_PASSWORD") or "").strip()
ACCESS_PASSWORD = AUTH_PASSWORD or (os.getenv("GITHUB_REGISTER_ACCESS_PASSWORD") or "").strip()
AUTH_ENABLED = bool(ACCESS_PASSWORD)
# ponytail: read the real IP from X-Forwarded-For only behind a trusted
# proxy (spoofable when directly exposed). Compose sets =1.
TRUST_PROXY = (os.getenv("GITHUB_REGISTER_TRUST_PROXY") or "").strip().lower() in (
    "1", "true", "yes")
HOST = (os.getenv("GITHUB_REGISTER_HOST") or "127.0.0.1").strip()
PORT = int(os.getenv("GITHUB_REGISTER_PORT") or "8093")  # 8092 is used by grok-regkit (Chromium)

if AUTH_ENABLED and HOST in ("0.0.0.0", "::"):
    logging.getLogger("uvicorn.error").warning(
        "exposed on %s — make sure GITHUB_REGISTER_USERNAME/PASSWORD is strong + HTTPS reverse proxy",
        HOST,
    )

DIST = ROOT / "frontend" / "dist"

SECRET_FIELDS = {"proxy", "litensi_api_key", "imap_password"}


def _migrate_legacy_account_files() -> None:
    """Move pre-accounts/ output files once, preserving existing account data."""
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    for legacy in ROOT.glob("github_accounts_*.txt"):
        target = ACCOUNTS_DIR / legacy.name
        if not target.exists():
            legacy.replace(target)


_migrate_legacy_account_files()

_sessions: Dict[str, float] = {}
_SESSION_LOCK = threading.Lock()
_SESSION_TTL = 86400 * 7

# ponytail: in-memory per-IP rate-limit for /api/auth (anti brute-force);
# enough for single-user self-host, use a reverse-proxy limit for multi-replica
_AUTH_FAILS: Dict[str, Deque[float]] = {}
_AUTH_LOCK = threading.Lock()
_AUTH_MAX_ATTEMPTS = 10
_AUTH_WINDOW_SEC = 60.0

_job_lock = threading.Lock()
_job_thread: Optional[threading.Thread] = None
_controller: Optional[Any] = None
_log_buffer: Deque[str] = collections.deque(maxlen=2000)
_log_seq = 0
_log_cond = threading.Condition()
_job_state: Dict[str, Any] = {
    "running": False,
    "success": 0,
    "fail": 0,
    "target": 0,
    "started_at": None,
    "finished_at": None,
    "error": "",
    "accounts_file": "",
}

# Resend = reorder the same Litensi mailbox and wait for a fresh code.
# Hard stop after RESEND_TIMEOUT_SEC with no code so a stale window never
# hangs a worker thread or the UI forever.
RESEND_TIMEOUT_SEC = 120
_resend_lock = threading.Lock()
_resend_state: Dict[str, Dict[str, Any]] = {}
_resend_stop: Dict[str, threading.Event] = {}

app = FastAPI(
    title="GitHub Register",
    version="1.0.0",
    # ponytail: hide public swagger when auth is on (like n8n/waha); back on for dev without auth
    docs_url=None if AUTH_ENABLED else "/docs",
    redoc_url=None if AUTH_ENABLED else "/redoc",
    openapi_url=None if AUTH_ENABLED else "/openapi.json",
)

_AUTH_MAX_BODY = 8 * 1024  # /api/auth is only username+password; reject jumbo before reading (DoS)


@app.middleware("http")
async def _security_guard(request: Request, call_next):
    if request.url.path == "/api/auth":
        try:
            if int(request.headers.get("content-length") or 0) > _AUTH_MAX_BODY:
                return JSONResponse({"ok": False, "detail": "request too large"}, status_code=413)
        except ValueError:
            pass
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"  # admin console must not be iframed (clickjacking)
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


class _QuietSSECancellation(logging.Filter):
    """Suppress "Exception in ASGI application" tracebacks that are just
    CancelledError from tasks being torn down at shutdown (Ctrl+C).

    Two shapes occur:
      * uvicorn's http protocol logs CancelledError with exc_info when a
        StreamingResponse task (e.g. our /api/logs SSE stream) is cancelled;
      * starlette's lifespan handler formats CancelledError into a plain-text
        traceback message (no exc_info) and uvicorn logs it as an ERROR.
    Neither is an error — it is normal shutdown noise.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno != logging.ERROR:
            return True
        if record.exc_info:
            exc = record.exc_info[1]
            if isinstance(exc, asyncio.CancelledError):
                return False
            if isinstance(exc, BaseExceptionGroup) and not exc.split(asyncio.CancelledError)[1]:
                return False  # every sub-exception is a CancelledError
        msg = record.getMessage()
        if "CancelledError" in msg and "Traceback (most recent call last)" in msg:
            return False  # formatted CancelledError traceback text
        return True


logging.getLogger("uvicorn.error").addFilter(_QuietSSECancellation())


_job_proc: Optional["subprocess.Popen"] = None


class StopController:
    def __init__(self) -> None:
        self._stop = False

    def should_stop(self) -> bool:
        return self._stop

    def stop(self) -> None:
        self._stop = True
        # PRIME: also kill the subprocess job runner if present
        proc = _job_proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass


def _append_log(message: str) -> None:
    global _log_seq
    line = f"[{time.strftime('%H:%M:%S')}] {message}"
    with _log_cond:
        _log_buffer.append(line)
        _log_seq += 1
        _log_cond.notify_all()


def _mask_value(key: str, value: Any) -> Any:
    if key not in SECRET_FIELDS:
        return value
    s = "" if value is None else str(value)
    if not s:
        return ""
    if len(s) <= 6:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def _public_config() -> Dict[str, Any]:
    cfg = load_config(ROOT / "config.json")
    masked = {k: _mask_value(k, v) for k, v in asdict(cfg).items()}
    for key in SECRET_FIELDS:
        raw = getattr(cfg, key, "")
        masked[f"has_{key}"] = bool(str(raw or "").strip())
    pf = (getattr(cfg, "proxy_file", "") or "").strip()
    masked["proxy_file_count"] = len(load_proxy_pool(pf)) if pf else 0
    return masked


def _safe_compare(a: str, b: str) -> bool:
    """compare_digest without 500: non-ASCII/odd input = not valid credentials."""
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


def _require_auth(x_access_key: Optional[str]) -> None:
    if not AUTH_ENABLED:
        return
    key = (x_access_key or "").strip()
    if not key:
        raise HTTPException(status_code=401, detail="access key required")
    with _SESSION_LOCK:
        exp = _sessions.get(key)
        if exp and exp > time.time():
            return
        if exp:
            _sessions.pop(key, None)
    raise HTTPException(status_code=403, detail="invalid access key")


def _valid_credential(username: str, password: str) -> bool:
    # ponytail: always run both compares (no short-circuit) so timing
    # does not leak valid vs invalid username
    user_ok = _safe_compare(username, AUTH_USERNAME) if AUTH_USERNAME else True
    pass_ok = _safe_compare(password, ACCESS_PASSWORD)
    return bool(user_ok and pass_ok)


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        if xff:
            return xff
    return request.client.host if request.client else "unknown"


def _auth_rate_limited(ip: str) -> float:
    """Record 1 failed attempt; return wait seconds (>0 = rejected). Sliding window."""
    now = time.time()
    with _AUTH_LOCK:
        attempts = _AUTH_FAILS.setdefault(ip, collections.deque())
        while attempts and now - attempts[0] > _AUTH_WINDOW_SEC:
            attempts.popleft()
        if len(attempts) >= _AUTH_MAX_ATTEMPTS:
            return max(1.0, _AUTH_WINDOW_SEC - (now - attempts[0]))
        attempts.append(now)
        return 0.0


def _auth_reset(ip: str) -> None:
    with _AUTH_LOCK:
        _AUTH_FAILS.pop(ip, None)


def _issue_token() -> str:
    token = secrets.token_urlsafe(32)
    with _SESSION_LOCK:
        _sessions[token] = time.time() + _SESSION_TTL
    return token


class AuthBody(BaseModel):
    username: str = ""
    password: str = ""


class StartBody(BaseModel):
    count: int = Field(default=1, ge=1, le=1000)


class ConfigBody(BaseModel):
    mail_provider: Optional[str] = None
    mailcx_domain: Optional[str] = None
    litensi_api_id: Optional[str] = None
    litensi_api_key: Optional[str] = None
    litensi_site: Optional[str] = None
    litensi_zone: Optional[str] = None
    imap_user: Optional[str] = None
    imap_password: Optional[str] = None
    imap_host: Optional[str] = None
    imap_port: Optional[int] = None
    imap_alias_domain: Optional[str] = None
    temptf_providers: Optional[str] = None
    temptf_dot: Optional[bool] = None
    temptf_plus: Optional[bool] = None
    register_count: Optional[int] = None
    proxy: Optional[str] = None
    proxy_file: Optional[str] = None
    headless: Optional[bool] = None
    delay_sec: Optional[float] = None
    max_username_tries: Optional[int] = None
    otp_timeout_sec: Optional[int] = None
    browser_profile_dir: Optional[str] = None
    fresh_profile: Optional[bool] = None
    proxy_hard_block_retries: Optional[int] = None
    proxy_rate_limit_retries: Optional[int] = None
    solve_captcha: Optional[bool] = None
    captcha_max_rounds: Optional[int] = None
    create_repo: Optional[bool] = None
    repo_name: Optional[str] = None
    enable_2fa: Optional[bool] = None
    create_pat: Optional[bool] = None
    set_profile_status: Optional[bool] = None
    profile_status: Optional[str] = None
    complete_profile: Optional[bool] = None
    profile_name: Optional[str] = None
    profile_bio: Optional[str] = None
    profile_location: Optional[str] = None


def _save_config(cfg: Config) -> None:
    (ROOT / "config.json").write_text(
        json.dumps(asdict(cfg), indent=4, ensure_ascii=False), encoding="utf-8"
    )


def _run_job(count: int) -> None:
    global _controller
    controller = StopController()
    with _job_lock:
        _controller = controller
        _job_state.update(
            running=True,
            success=0,
            fail=0,
            target=count,
            error="",
            started_at=time.time(),
            finished_at=None,
            accounts_file="",
        )

    def _on_progress(ok_count: int, fail_count: int) -> None:
        # called by run_job() after each account attempt (and on start/finish)
        with _job_lock:
            _job_state["success"] = int(ok_count)
            _job_state["fail"] = int(fail_count)

    # PRIME: camoufox/Playwright cannot be launched from a uvicorn daemon
    # thread on Windows ([Errno 22] Invalid argument on browser pipe). Run
    # the job in a fresh SUBPROCESS (main.py) and stream its output back.
    global _job_proc
    try:
        import re as _re
        import subprocess
        import sys as _sys
        env = dict(os.environ)
        env["PYTHONPATH"] = ""
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            [_sys.executable, str(ROOT / "main.py"), "--count", str(count)],
            cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        _job_proc = proc
        assert proc.stdout is not None
        ok = fail = 0
        out_file = ""
        for line in proc.stdout:
            line = line.rstrip("\n")
            _append_log(line)
            m = _re.search(r"stats: OK (\d+) \| FAIL (\d+)", line)
            if m:
                ok, fail = int(m.group(1)), int(m.group(2))
                _on_progress(ok, fail)
            m2 = _re.search(r"output: (\S+\.txt)", line)
            if m2:
                out_file = m2.group(1)
            if controller.should_stop() and proc.poll() is None:
                proc.terminate()
        rc = proc.wait()
        _job_proc = None
        with _job_lock:
            _job_state.update(success=ok, fail=fail, accounts_file=out_file)
        if rc != 0 and not controller.should_stop():
            _append_log(f"[!] job process exit code {rc}")
    except Exception as exc:
        _append_log(f"[!] job error: {exc}")
        with _job_lock:
            _job_state["error"] = str(exc)
    finally:
        _job_proc = None
        with _job_lock:
            _job_state["running"] = False
            _job_state["finished_at"] = time.time()
            _controller = None
        _append_log("[*] web job thread finished")


@app.get("/", include_in_schema=False)
async def root() -> Response:
    index = DIST / "index.html"
    if index.is_file():
        return FileResponse(index, headers={"Cache-Control": "no-store"})
    return Response("frontend not built: run `npm run build` in frontend/", status_code=200)


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"ok": True, "service": "github-register"}


@app.get("/monitor/status")
async def monitor_status(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _job_lock:
        return {"ok": True, "service": "github-register", "running_job": bool(_job_state["running"])}


@app.post("/api/auth")
async def api_auth(body: AuthBody, request: Request) -> Dict[str, Any]:
    if not AUTH_ENABLED:
        return {"ok": True, "needs_auth": False, "token": ""}
    if not _valid_credential((body.username or "").strip(), (body.password or "").strip()):
        ip = _client_ip(request)
        wait = _auth_rate_limited(ip)
        if wait > 0:
            return JSONResponse(
                {"ok": False, "detail": f"too many attempts, retry in {int(wait)}s"},
                status_code=429,
                headers={"Retry-After": str(int(wait))},
            )
        return JSONResponse({"ok": False, "detail": "invalid username or password"}, status_code=403)
    _auth_reset(_client_ip(request))
    return {"ok": True, "needs_auth": True, "token": _issue_token()}


@app.post("/api/logout")
async def api_logout(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    key = (x_access_key or "").strip()
    if AUTH_ENABLED and key:
        with _SESSION_LOCK:
            _sessions.pop(key, None)
    return {"ok": True}


@app.get("/api/config")
async def api_get_config(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    return {"ok": True, "config": _public_config(), "needs_auth": AUTH_ENABLED}


@app.put("/api/config")
async def api_put_config(body: ConfigBody, x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    cfg = load_config(ROOT / "config.json")
    updates = body.model_dump(exclude_unset=True)
    for key, value in updates.items():
        if key in SECRET_FIELDS and isinstance(value, str):
            stripped = value.strip()
            if stripped == "":
                setattr(cfg, key, "")
                continue
            if "*" in stripped:  # masked placeholder from GET — keep previous
                continue
        setattr(cfg, key, value)
    _save_config(cfg)
    return {"ok": True, "config": _public_config()}


class MailCxConfigBody(BaseModel):
    """Optional override for mail.cx domain."""
    mailcx_domain: Optional[str] = None


@app.post("/api/mailcx/domains")
async def api_mailcx_domains(
    body: MailCxConfigBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Return the list of available mail.cx domains."""
    _require_auth(x_access_key)
    cfg = load_config(ROOT / "config.json")
    domain = body.mailcx_domain or cfg.mailcx_domain or ""
    try:
        client = MailCxClient(domain=domain)
        domains = client._get_domains()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to contact mail.cx: {exc}")
    return {
        "ok": True,
        "domains": domains,
        "current_domain": cfg.mailcx_domain or "",
    }


class LitensiZoneBody(BaseModel):
    litensi_api_id: Optional[str] = None
    litensi_api_key: Optional[str] = None
    litensi_site: Optional[str] = None


@app.post("/api/litensi/zones")
async def api_litensi_zones(
    body: LitensiZoneBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Return Litensi zones (prices + stock) for the configured site."""
    _require_auth(x_access_key)
    cfg = load_config(ROOT / "config.json")
    api_id = body.litensi_api_id or cfg.litensi_api_id or ""
    api_key = body.litensi_api_key or ""
    if "*" in api_key:  # masked placeholder from GET — fall back to stored key
        api_key = ""
    api_key = api_key or cfg.litensi_api_key or ""
    site = body.litensi_site or cfg.litensi_site or ""
    if not api_id or not api_key:
        raise HTTPException(status_code=400, detail="litensi_api_id and litensi_api_key are required")
    if not site:
        raise HTTPException(status_code=400, detail="litensi_site is required (e.g. github.com)")
    try:
        from github_register.litensi import LitensiClient
        client = LitensiClient(api_id=api_id, api_key=api_key, site=site)
        zones = client.prices()
        stock = [z for z in zones if float(z.get("stock") or 0) > 0]
        cheapest = min(stock, key=lambda z: float(z.get("price") or 0))["zone"] if stock else ""
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to contact Litensi: {exc}")
    return {"ok": True, "zones": zones, "site": site, "cheapest": cheapest}


PROXY_SCHEMES = ("http", "https", "socks4", "socks5")


def _valid_proxy_line(line: str) -> bool:
    p = urlsplit(line)
    return bool(p.hostname) and (p.scheme or "http").lower() in PROXY_SCHEMES


@app.post("/api/proxy/upload")
async def api_proxy_upload(
    request: Request, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Save an uploaded proxy list as the active pool (proxies.txt, one URL per line).

    Body: raw file content (text/plain) — no multipart needed.
    """
    _require_auth(x_access_key)
    raw = (await request.body()).decode("utf-8", errors="replace")
    valid: List[str] = []
    seen: set = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in seen or not _valid_proxy_line(line):
            continue
        seen.add(line)
        valid.append(line)
    if not valid:
        raise HTTPException(
            status_code=400,
            detail="no valid proxies found (one per line: scheme://user:pass@host:port)",
        )
    pool_name = "proxies.txt"
    (ROOT / pool_name).write_text("\n".join(valid) + "\n", encoding="utf-8")
    cfg = load_config(ROOT / "config.json")
    cfg.proxy_file = pool_name
    _save_config(cfg)
    _append_log(f"[*] proxy pool uploaded: {len(valid)} proxies -> {pool_name}")
    return {"ok": True, "proxy_file": pool_name, "count": len(valid), "config": _public_config()}


@app.get("/api/status")
async def api_status(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _job_lock:
        return {"ok": True, **_job_state}


@app.post("/api/start")
async def api_start(body: StartBody, x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    global _job_thread
    _require_auth(x_access_key)
    with _job_lock:
        if _job_state["running"]:
            raise HTTPException(status_code=409, detail="job already running")
        _append_log(f"[*] starting registration count={body.count}")
        t = threading.Thread(target=_run_job, args=(body.count,), daemon=True)
        _job_thread = t
        t.start()
    return {"ok": True, "started": True, "count": body.count}


@app.post("/api/stop")
async def api_stop(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _job_lock:
        ctrl = _controller
        running = _job_state["running"]
    if not running or ctrl is None:
        return {"ok": True, "stopped": False, "detail": "no running job"}
    ctrl.stop()
    _append_log("[!] stop requested from web")
    return {"ok": True, "stopped": True}


@app.get("/api/logs")
async def api_logs(
    request: Request,
    x_access_key: Optional[str] = Header(None),
    after: int = Query(0, ge=0),
):
    _require_auth(x_access_key)

    async def event_stream():
        last = after
        try:
            while True:
                if await request.is_disconnected():
                    break
                with _log_cond:
                    buf = list(_log_buffer)
                    seq = _log_seq
                if seq > last:
                    start_idx = max(0, len(buf) - (seq - last))
                    for line in buf[start_idx:]:
                        yield f"data: {line}\n\n"
                    last = seq
                await asyncio.sleep(0.5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            # client went away / server shutdown — exit the stream quietly;
            # uvicorn would otherwise log "Exception in ASGI application"
            pass

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/logs/snapshot")
async def api_logs_snapshot(
    x_access_key: Optional[str] = Header(None),
    limit: int = Query(200, ge=1, le=2000),
) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _log_cond:
        lines = list(_log_buffer)[-limit:]
        seq = _log_seq
    return {"ok": True, "seq": seq, "lines": lines}


@app.get("/api/accounts")
async def api_accounts_list(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    files = sorted(ACCOUNTS_DIR.glob("github_accounts_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    items = [
        {"name": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime}
        for f in files[:50]
    ]
    return {"ok": True, "files": items}


def _parse_accounts_file(path: Path) -> List[Dict[str, str]]:
    """Parse account records, including whether a recovery file is available."""
    rows: List[Dict[str, str]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("----")]
            if len(parts) >= 4:
                rows.append({
                    "email": parts[0], "password": parts[1],
                    "username": parts[2], "totp": parts[3],
                    "has_recovery": _recovery_path(parts[0]).is_file(),
                })
            elif len(parts) == 3:
                rows.append({
                    "email": parts[0], "password": parts[1],
                    "username": parts[2], "totp": "", "has_recovery": _recovery_path(parts[0]).is_file(),
                })
            elif len(parts) == 2:
                rows.append({
                    "email": parts[0], "password": parts[1],
                    "username": parts[0].split("@")[0], "totp": "", "has_recovery": _recovery_path(parts[0]).is_file(),
                })
    except Exception:
        pass
    return rows


def _recovery_path(email: str) -> Path:
    key = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    return RECOVERY_DIR / f"{key}.txt"


@app.get("/api/totp")
async def api_totp_code(
    x_access_key: Optional[str] = Header(None),
    secret: str = Query(..., min_length=16, max_length=64),
) -> Dict[str, Any]:
    """Current TOTP code + seconds remaining for a stored secret."""
    _require_auth(x_access_key)
    try:
        import pyotp

        totp = pyotp.TOTP(secret.strip())
        code = totp.now()
        remaining = totp.interval - (int(time.time()) % totp.interval)
        return {"ok": True, "code": code, "expires_in": remaining}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"invalid TOTP secret: {exc}")


@app.get("/api/accounts/preview")
async def api_accounts_preview(
    x_access_key: Optional[str] = Header(None),
    name: Optional[str] = Query(None),
    group: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Parsed account rows of one file (or the newest) for the export panel.

    With ?group=<name> returns the union of that group's members across ALL
    accounts files (deduplicated by email, newest occurrence wins).
    """
    _require_auth(x_access_key)
    with _groups_lock:
        gdata = _load_groups()
    if group is not None:
        if group not in gdata["groups"]:
            raise HTTPException(status_code=404, detail="group not found")
        files = sorted(ACCOUNTS_DIR.glob("github_accounts_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        seen: set = set()
        rows: List[Dict[str, Any]] = []
        for f in files:
            for row in _parse_accounts_file(f):
                key = row["email"].strip().lower()
                memberships = gdata["assignments"].get(key, [])
                if key in seen or group not in memberships:
                    continue
                seen.add(key)
                row["groups"] = memberships
                row["group"] = group  # convenience alias for the active view
                rows.append(row)
        return {"ok": True, "rows": rows, "total": len(rows), "name": "", "group": group}
    if name:
        safe = Path(name).name
        path = ACCOUNTS_DIR / safe
        if not safe.startswith("github_accounts_") or not safe.endswith(".txt") or not path.is_file():
            raise HTTPException(status_code=404, detail="file not found")
    else:
        files = sorted(ACCOUNTS_DIR.glob("github_accounts_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            return {"ok": True, "rows": [], "total": 0, "name": ""}
        path = files[0]
    rows = _parse_accounts_file(path)
    for row in rows:
        memberships = gdata["assignments"].get(row["email"].strip().lower(), [])
        row["groups"] = memberships
        row["group"] = memberships[0] if memberships else ""  # legacy alias
    return {"ok": True, "rows": rows, "total": len(rows), "name": path.name}


@app.get("/api/accounts/recovery")
async def api_accounts_recovery(
    email: str = Query(..., min_length=3, max_length=320),
    x_access_key: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Read recovery codes for exactly one account, if they were captured."""
    _require_auth(x_access_key)
    path = _recovery_path(email)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="recovery codes are not available for this account")
    try:
        codes = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"unable to read recovery codes: {exc}")
    if not codes:
        raise HTTPException(status_code=404, detail="recovery code file is empty")
    return {"ok": True, "email": email, "codes": codes}


def _find_account_email(email: str) -> Optional[str]:
    """Return the stored address when it appears in an accounts file.

    Guards the resend endpoint: reordering an address we never registered would
    burn Litensi balance for nothing and, worse, could reorder someone else's
    activation if the address were ever valid on the same account.
    """
    needle = email.strip().lower()
    if not needle:
        return None
    for f in sorted(ACCOUNTS_DIR.glob("github_accounts_*.txt")):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            addr = line.split("----", 1)[0].strip()
            if addr.lower() == needle:
                return addr
    return None


def _run_resend(key: str, email: str, stop_event: threading.Event) -> None:
    """Background worker: reorder the mailbox, then poll for a fresh code."""

    def _set(**kwargs: Any) -> None:
        with _resend_lock:
            state = _resend_state.get(key)
            if state is not None:
                state.update(kwargs)

    try:
        cfg = load_config(ROOT / "config.json")
        from github_register.litensi import LitensiClient, LitensiError

        if not (cfg.litensi_api_id and cfg.litensi_api_key and cfg.litensi_site):
            raise LitensiError(
                "Litensi is not configured (litensi_api_id / litensi_api_key / litensi_site)"
            )
        client = LitensiClient(
            api_id=cfg.litensi_api_id,
            api_key=cfg.litensi_api_key,
            site=cfg.litensi_site,
            zone=cfg.litensi_zone,
        )
        _append_log(f"[*] resend: reordering mailbox {email}")
        data = client.reorder(email)
        order_id = str(data.get("order_id") or "")
        expired_at = str(data.get("expired_at") or "")
        _set(order_id=order_id, expired_at=expired_at,
             message="Waiting for a new code")
        _append_log(f"[*] resend: window for {email} open until {expired_at or '?'} "
                    f"(order {order_id})")
        code = client.wait_for_code(
            order_id, email=email, timeout=RESEND_TIMEOUT_SEC,
            log=_append_log, cancel_cb=stop_event.is_set,
        )
        _set(status="done", code=code, finished_at=time.time(),
             message=f"Code received: {code}")
        _append_log(f"[+] resend: new code for {email} = {code}")
    except Exception as exc:
        stopped = stop_event.is_set()
        _set(status="error",
             message="Resend stopped" if stopped else str(exc),
             finished_at=time.time())
        _append_log(f"[!] resend {'stopped' if stopped else 'failed'} for {email}"
                    + ("" if stopped else f": {exc}"))


class ResendBody(BaseModel):
    email: str = Field(min_length=3, max_length=320)


@app.post("/api/accounts/resend")
async def api_accounts_resend(
    body: ResendBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Reopen the mailbox window (Litensi reorder) and wait for a new code.

    Runs in a background thread because polling can take up to
    RESEND_TIMEOUT_SEC; the client watches /api/accounts/resend-status and the
    live log. Reorder needs no stored metadata: api_id/api_key/site come from
    config, the email from the accounts file.
    """
    _require_auth(x_access_key)
    email = _find_account_email(body.email)
    if not email:
        raise HTTPException(status_code=404, detail="email not found in any accounts file")
    key = email.strip().lower()
    with _resend_lock:
        # drop finished entries after an hour; the map stays tiny
        cutoff = time.time() - 3600
        for stale in [k for k, v in _resend_state.items()
                      if v.get("finished_at") and v["finished_at"] < cutoff]:
            _resend_state.pop(stale, None)
            _resend_stop.pop(stale, None)
        current = _resend_state.get(key)
        already = bool(current and current.get("status") == "running")
        if not already:
            _resend_state[key] = {
                "email": email,
                "status": "running",
                "message": "Reordering mailbox",
                "code": "",
                "order_id": "",
                "expired_at": "",
                "started_at": time.time(),
                "finished_at": None,
            }
            _resend_stop[key] = threading.Event()
        stop_event = _resend_stop.get(key)
    if not already and stop_event is not None:
        threading.Thread(target=_run_resend, args=(key, email, stop_event), daemon=True).start()
    return {"ok": True, "started": not already, "email": email,
            "timeout": RESEND_TIMEOUT_SEC}


@app.get("/api/accounts/resend-status")
async def api_accounts_resend_status(
    email: str = Query(..., min_length=3, max_length=320),
    x_access_key: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Current resend state for one email (idle when none has been started)."""
    _require_auth(x_access_key)
    key = email.strip().lower()
    with _resend_lock:
        state = _resend_state.get(key)
        if not state:
            return {"ok": True, "status": "idle"}
        return {"ok": True, **state}


@app.post("/api/accounts/resend-stop")
async def api_accounts_resend_stop(
    body: ResendBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Stop a running resend: the worker aborts its poll at the next check."""
    _require_auth(x_access_key)
    key = body.email.strip().lower()
    with _resend_lock:
        state = _resend_state.get(key)
        running = bool(state and state.get("status") == "running")
        event = _resend_stop.get(key)
        if running and event is not None:
            event.set()
    if running:
        _append_log(f"[!] resend stop requested for {body.email.strip()}")
    return {"ok": True, "stopped": running}


class DeleteRowBody(BaseModel):
    email: str
    name: str  # accounts file name


@app.delete("/api/accounts/row")
async def api_accounts_delete_row(
    body: DeleteRowBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Delete one account row (by email) from an accounts file."""
    _require_auth(x_access_key)
    safe = Path(body.name).name
    path = ACCOUNTS_DIR / safe
    if not safe.startswith("github_accounts_") or not safe.endswith(".txt") or not path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    kept = [l for l in lines if not l.strip().lower().startswith(body.email.strip().lower() + "----")]
    if len(kept) == len(lines):
        raise HTTPException(status_code=404, detail=f"row not found: {body.email}")
    path.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")
    recovery = _recovery_path(body.email)
    if recovery.is_file():
        recovery.unlink()
    with _groups_lock:
        gdata = _load_groups()
        if gdata["assignments"].pop(body.email.strip().lower(), None) is not None:
            _save_groups(gdata)
    return {"ok": True, "deleted": len(lines) - len(kept), "remaining": len(kept)}


class RenameFileBody(BaseModel):
    name: str  # current accounts file name
    new_name: str  # new base name (without github_accounts_ prefix / .txt suffix)


@app.post("/api/accounts/rename")
async def api_accounts_rename_file(
    body: RenameFileBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Rename an accounts file, keeping the github_accounts_<name>.txt pattern."""
    _require_auth(x_access_key)
    old = Path(body.name).name
    old_path = ACCOUNTS_DIR / old
    if not old.startswith("github_accounts_") or not old.endswith(".txt") or not old_path.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    base = body.new_name.strip()
    # strip prefix/suffix if the user typed the full old-style name
    for prefix in ("github_accounts_", "github_accounts"):
        if base.lower().startswith(prefix):
            base = base[len(prefix):]
            break
    if base.lower().endswith(".txt"):
        base = base[:-4]
    base = base.strip()
    if not base:
        raise HTTPException(status_code=400, detail="new name cannot be empty")
    if not all(ch.isalnum() or ch in "-_." for ch in base):
        raise HTTPException(
            status_code=400, detail="new name may only contain letters, digits, '-', '_' and '.'"
        )
    if len(base) > 120:
        raise HTTPException(status_code=400, detail="new name is too long (max 120 chars)")

    new = f"github_accounts_{base}.txt"
    if new == old:
        return {"ok": True, "renamed": False, "name": old, "detail": "name unchanged"}
    new_path = ACCOUNTS_DIR / new
    if new_path.exists():
        raise HTTPException(status_code=409, detail=f"a file named {new} already exists")

    old_path.replace(new_path)
    return {"ok": True, "renamed": True, "name": new, "old_name": old}


class MergeFilesBody(BaseModel):
    source: str  # accounts file whose rows are moved out
    target: str  # accounts file that receives the rows


@app.post("/api/accounts/merge")
async def api_accounts_merge_files(
    body: MergeFilesBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Move every row from one accounts file into another, then remove the source.

    Rows whose email already exists in the target are skipped, so merging the
    same file twice cannot duplicate accounts. Recovery codes and group
    memberships are keyed by email, so they survive the move untouched.
    """
    _require_auth(x_access_key)
    source = Path(body.source).name
    target = Path(body.target).name
    for name in (source, target):
        if not name.startswith("github_accounts_") or not name.endswith(".txt"):
            raise HTTPException(status_code=404, detail="file not found")
    if source == target:
        raise HTTPException(status_code=400, detail="source and target must be different files")
    source_path = ACCOUNTS_DIR / source
    target_path = ACCOUNTS_DIR / target
    if not source_path.is_file() or not target_path.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    def _email_of(line: str) -> str:
        return line.split("----", 1)[0].strip().lower()

    source_lines = [l for l in source_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    target_lines = [l for l in target_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    seen = {_email_of(l) for l in target_lines}
    moved = [l for l in source_lines if _email_of(l) not in seen]
    skipped = len(source_lines) - len(moved)

    merged = target_lines + moved
    target_path.write_text(("\n".join(merged) + "\n") if merged else "", encoding="utf-8")
    source_path.unlink()
    _append_log(f"[*] merged {source} into {target}: {len(moved)} moved, "
                f"{skipped} duplicate(s) skipped")
    return {
        "ok": True,
        "moved": len(moved),
        "skipped": skipped,
        "total": len(merged),
        "source": source,
        "target": target,
    }


# ---------- account groups ----------
# groups.json: {"groups": ["Github", ...], "assignments": {email_lower: [group, ...]}}
# An account may belong to multiple groups at once. Membership is keyed by
# email so an account keeps its groups even if its accounts file is renamed;
# deleting the row removes all of its assignments.
# Legacy format (single group string per email) is migrated on load.

def _norm_groups_value(value: Any) -> List[str]:
    """Normalize one assignment entry into a list of group names.

    Accepts a single string (legacy format), a list of strings, or anything
    else (dropped). Order is preserved, duplicates removed.
    """
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        out: List[str] = []
        for g in value:
            if isinstance(g, str) and g and g not in out:
                out.append(g)
        return out
    return []


def _load_groups() -> Dict[str, Any]:
    try:
        data = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"groups": [], "assignments": {}}
    groups = data.get("groups") if isinstance(data, dict) else None
    assignments = data.get("assignments") if isinstance(data, dict) else None
    normalized: Dict[str, List[str]] = {}
    if isinstance(assignments, dict):
        for email, value in assignments.items():
            memberships = _norm_groups_value(value)
            if memberships:
                normalized[str(email)] = memberships
    return {
        "groups": [str(g) for g in groups] if isinstance(groups, list) else [],
        "assignments": normalized,
    }


def _save_groups(data: Dict[str, Any]) -> None:
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = GROUPS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(GROUPS_FILE)


def _valid_group_name(name: str) -> bool:
    return 0 < len(name) <= 60 and all(ch.isalnum() or ch in "-_." for ch in name)


class GroupBody(BaseModel):
    name: str


@app.get("/api/groups")
async def api_groups_list(x_access_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _groups_lock:
        data = _load_groups()
    counts = collections.Counter()
    for memberships in data["assignments"].values():
        counts.update(memberships)
    items = [{"name": g, "count": counts.get(g, 0)} for g in data["groups"]]
    return {"ok": True, "groups": items}


@app.post("/api/groups")
async def api_groups_create(
    body: GroupBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    _require_auth(x_access_key)
    name = " ".join((body.name or "").split())
    if not _valid_group_name(name):
        raise HTTPException(
            status_code=400,
            detail="group name may only contain letters, digits, '-', '_', '.' (max 60 chars)",
        )
    with _groups_lock:
        data = _load_groups()
        if name in data["groups"]:
            raise HTTPException(status_code=409, detail=f"group already exists: {name}")
        data["groups"].append(name)
        _save_groups(data)
    return {"ok": True, "created": True, "group": name}


@app.delete("/api/groups")
async def api_groups_delete(
    x_access_key: Optional[str] = Header(None),
    name: str = Query(...),
) -> Dict[str, Any]:
    _require_auth(x_access_key)
    with _groups_lock:
        data = _load_groups()
        if name not in data["groups"]:
            raise HTTPException(status_code=404, detail="group not found")
        data["groups"].remove(name)
        removed = 0
        cleaned: Dict[str, List[str]] = {}
        for email, memberships in data["assignments"].items():
            if name in memberships:
                removed += 1
            kept = [g for g in memberships if g != name]
            if kept:
                cleaned[email] = kept
        data["assignments"] = cleaned
        _save_groups(data)
    return {"ok": True, "deleted": name, "unassigned": removed}


class AssignBody(BaseModel):
    email: str
    group: str  # group name to toggle membership for


@app.post("/api/groups/assign")
async def api_groups_assign(
    body: AssignBody, x_access_key: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Toggle one account's membership in a group.

    If the account is not a member it is added; if it is already a member it
    is removed. An account may belong to any number of groups.
    """
    _require_auth(x_access_key)
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="invalid email")
    group = body.group.strip()
    if not group or not _valid_group_name(group):
        raise HTTPException(status_code=400, detail="invalid group name")
    with _groups_lock:
        data = _load_groups()
        if group not in data["groups"]:
            raise HTTPException(status_code=404, detail=f"group not found: {group}")
        memberships = list(data["assignments"].get(email, []))
        if group in memberships:
            memberships.remove(group)
            action = "removed"
        else:
            memberships.append(group)
            action = "added"
        if memberships:
            data["assignments"][email] = memberships
        else:
            data["assignments"].pop(email, None)
        _save_groups(data)
    return {"ok": True, "email": email, "group": group, "action": action, "groups": memberships}


@app.get("/api/groups/membership")
async def api_groups_membership(
    email: str = Query(..., min_length=3, max_length=320),
    x_access_key: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """List all groups one account (by email) currently belongs to."""
    _require_auth(x_access_key)
    key = email.strip().lower()
    if not key or "@" not in key:
        raise HTTPException(status_code=400, detail="invalid email")
    with _groups_lock:
        data = _load_groups()
    return {"ok": True, "email": key, "groups": data["assignments"].get(key, [])}


@app.delete("/api/accounts/file")
async def api_accounts_delete_file(
    x_access_key: Optional[str] = Header(None),
    name: str = Query(...),
) -> Dict[str, Any]:
    """Delete an entire accounts file."""
    _require_auth(x_access_key)
    safe = Path(name).name
    path = ACCOUNTS_DIR / safe
    if not safe.startswith("github_accounts_") or not safe.endswith(".txt") or not path.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    path.unlink()
    return {"ok": True, "deleted": safe}


@app.get("/api/accounts/download")
async def api_accounts_download(
    x_access_key: Optional[str] = Header(None),
    name: Optional[str] = Query(None),
) -> Response:
    _require_auth(x_access_key)
    if name:
        safe = Path(name).name
        path = ACCOUNTS_DIR / safe
        if not safe.startswith("github_accounts_") or not safe.endswith(".txt") or not path.is_file():
            raise HTTPException(status_code=404, detail="file not found")
    else:
        files = sorted(ACCOUNTS_DIR.glob("github_accounts_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            raise HTTPException(status_code=404, detail="no accounts file")
        path = files[0]
    return FileResponse(
        path,
        filename=path.name,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


if (DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=str(DIST / "assets")), name="assets")


def main() -> None:
    import uvicorn

    uvicorn.run("web.server:app", host=HOST, port=PORT, workers=1, log_level="info")


if __name__ == "__main__":
    main()
