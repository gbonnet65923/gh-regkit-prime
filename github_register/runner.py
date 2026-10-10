"""GitHub sign-up automation driven by Camoufox (Firefox anti-detect) + Litensi mail."""
from __future__ import annotations

import json
import hashlib
import logging
import os
import random
import socket
import socketserver
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from camoufox.sync_api import Camoufox
import requests

from .config import Config
from .litensi import LitensiClient, LitensiError
from .mail_errors import MailboxCancelled, MailboxTimeoutError
from .mailcx import MailCxClient, MailCxError
from .mail_imap import ImapMailClient
from .mail_temptf import TempTfClient
from .profiles import (
    generate_password,
    generate_username,
    parse_public_profile,
    username_from_email,
)
from .captcha_solver import arkose_present, solve_arkose_voting

ROOT = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = ROOT / "accounts"
RECOVERY_DIR = ACCOUNTS_DIR / "recovery"


def _save_recovery_per_account(email: str, recovery: str, log) -> None:
    """Store one account's multiline recovery codes in accounts/recovery/."""
    if not recovery:
        return
    try:
        RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
        (RECOVERY_DIR / f"{key}.txt").write_text(recovery.strip() + "\n", encoding="utf-8")
        log(f"[*] recovery codes saved for {email}")
    except Exception as exc:
        log(f"[i] recovery codes write failed: {exc}")

_EMAIL_INPUTS = ["#email", "input[name='email']", "input[type='email']"]
_PASSWORD_INPUTS = ["#password", "input[name='password']"]
_USERNAME_INPUTS = ["#login", "input[name='login']"]
_OTP_INPUTS = [
    "#otp",
    "input[name='otp']",
    "input[autocomplete='one-time-code']",
    "#launch-code-0",  # verify page: 8 single-digit boxes launch-code-0..7
]
# The main signup form (NOT the Google/Apple OAuth forms which live in their own <form> tags)
_SIGNUP_FORM = "form[action*='signup']"
_SUBMIT_SELECTORS = [f"{_SIGNUP_FORM} button[type='submit']", "#submit", "button[type='submit']"]


class SignupError(RuntimeError):
    pass


class SignupBlocked(SignupError):
    pass


class RegistrationCancelled(SignupError):
    pass


class GitHubRateLimited(SignupError):
    pass


_DATADOME_HARD_BLOCK_MARKERS = (
    "access is temporarily restricted",
    "we detected unusual activity",
    "your access is restricted",
    "you have been temporarily blocked",
    # Indonesian localization of the DataDome block page
    "akses dibatasi untuk sementara",
    "kami mendeteksi aktivitas yang tidak biasa",
    "ada robot di jaringan",
)

_RATE_LIMIT_MARKERS = (
    "secondary rate limit",
    "too many requests",
    "you have exceeded a secondary rate limit",
    "please wait a few minutes before you try again",
)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _raise_if_cancelled(stop) -> None:
    if stop and stop():
        raise RegistrationCancelled("stop requested")


def _sleep_with_cancel(seconds: float, stop=None) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        time.sleep(min(0.25, deadline - time.time()))


def silence_playwright_noise() -> None:
    """Suppress the asyncio 'Task exception was never retrieved' spam.

    Playwright leaves in-flight Channel.send tasks behind when the browser is
    closed mid-operation; asyncio then dumps a TargetClosedError traceback for
    each of them. Harmless noise — filter it at the logging level.
    """
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)


def _parse_proxy(url: str) -> Optional[dict]:
    """'http(s)/socks5(h)://user:pass@host:port' -> Camoufox proxy dict, or None.

    Scheme normalization (Playwright accepts only these):
      socks://   -> socks5://   (bare 'socks' is rejected by Firefox)
      socks5h:// -> socks5://   ('h' variant is a curl/requests-only notation;
                                 Firefox resolves DNS remotely by default)
    """
    url = (url or "").strip()
    if not url:
        return None
    p = urlsplit(url)
    if not p.hostname:
        raise SignupError(f"invalid proxy url: {url}")
    scheme = (p.scheme or "http").lower()
    if scheme in ("socks", "socks5h"):
        scheme = "socks5"
    if scheme not in ("http", "https", "socks4", "socks5"):
        raise SignupError(f"unsupported proxy scheme: {p.scheme}:// (use http/socks5)")
    port = p.port or (1080 if scheme.startswith("socks") else (443 if scheme == "https" else 80))
    proxy = {"server": f"{scheme}://{p.hostname}:{port}"}
    if p.username:
        proxy["username"] = p.username
        proxy["password"] = p.password or ""
    return proxy


def load_proxy_pool(name: str) -> list[str]:
    """Valid proxy URLs from a pool file in project root (one per line, # comments ok)."""
    path = ROOT / name.strip()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = urlsplit(line)
        if p.hostname and (p.scheme or "http").lower() in ("http", "https", "socks4", "socks5"):
            out.append(line)
    return out


def _pick_proxy_url(cfg: Config, log=None) -> str:
    """Effective proxy URL: random pick from proxy_file pool, else the single URL."""
    name = (getattr(cfg, "proxy_file", "") or "").strip()
    if name:
        pool = load_proxy_pool(name)
        if pool:
            return random.choice(pool)
        if log:
            log(f"[!] proxy file {name!r} missing/empty — falling back to single proxy URL")
    return (cfg.proxy or "").strip()


def _proxy_is_socks(proxy: Optional[dict]) -> bool:
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks")


def _socks_exit_ip(url: str, timeout: int = 12) -> str:
    """Resolve the proxy exit IP using the 'socks5h://' scheme (remote DNS).

    DataImpulse (and similar gateways) reject IP-based connections under a
    'ruleset' when the client resolves DNS locally (plain socks5://). The
    requests-based geoip probe inside Camoufox uses plain socks5 and dies with
    '0x02: Connection not allowed by ruleset' — so we look the exit IP up
    ourselves over socks5h and hand it to Camoufox via geoip=<ip>.
    """
    import requests as _requests

    p = urlsplit(url.strip())
    scheme = "socks5h" if (p.scheme or "socks").lower().startswith("socks") else (p.scheme or "http")
    auth = f"{p.username}:{p.password}@" if p.username else ""
    port = p.port or 1080
    proxies = {"http": f"{scheme}://{auth}{p.hostname}:{port}",
               "https": f"{scheme}://{auth}{p.hostname}:{port}"}
    last_exc: Exception | None = None
    # sticky ports can take a few seconds to warm up (allocate the IP) — retry
    for attempt in range(2):
        for check_url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.co/ip"):
            try:
                resp = _requests.get(check_url, proxies=proxies, timeout=20)
                ip = (resp.text or "").strip()
                if resp.ok and ip:
                    return ip
            except Exception as exc:
                last_exc = exc
        if attempt == 0:
            time.sleep(3)  # give the sticky session a moment to warm up
    raise SignupError(f"proxy exit-IP lookup failed: {last_exc} "
                        f"(check scheme http/https/socks5, user:pass, and port in proxies.txt — "
                        f"'405/407' = proxy refuses CONNECT/auth)")


# ---------------------------------------------------------------------------
# Sticky proxy session
#
# Residential gateways such as DataImpulse rotate the exit IP on EVERY TCP
# connection by default (rotating ports 823/824). A browser opens dozens of
# parallel connections — mid-session IP changes are an instant DataDome flag
# ("same cookie, different countries within seconds").
#
# Fix: use a STICKY port instead. DataImpulse assigns ports 10000–20000 for
# sticky SOCKS5 — all connections through the same port exit through the SAME
# IP for the session lifetime (~30 min default).
# ---------------------------------------------------------------------------

_sticky_suffix: Optional[str] = None
_last_exit_ip: Optional[str] = None


def _ensure_sticky_proxy(url: str, log=None) -> str:
    """Switch a rotating DataImpulse endpoint to a sticky one.

    DataImpulse docs: rotating = port 823 (HTTP) / 824 (SOCKS5); sticky =
    ports 10000-20000. We pick a random sticky port per process so each job
    gets a fresh stable IP. The port is deterministic within the process.
    """
    p = urlsplit(url.strip())
    port = p.port or 0
    # only switch known rotating ports
    if port in (823, 824):
        global _sticky_suffix
        if _sticky_suffix is None:
            import secrets as _secrets

            _sticky_suffix = str(10000 + int(_secrets.token_hex(4), 16) % 10001)
            if log:
                log(f"[*] sticky proxy port: {_sticky_suffix} (IP stabil ~30 menit, DataImpulse)")
        scheme = (p.scheme or "socks5").lower()
        if scheme in ("socks", "socks5h"):
            scheme = "socks5"
        auth = f"{p.username}:{p.password}@" if p.username else ""
        return f"{scheme}://{auth}{p.hostname}:{_sticky_suffix}"
    return url.strip()  # already sticky or non-DataImpulse — untouched


# ---------------------------------------------------------------------------
# Local auth proxy bridge
#
# Firefox does not support authenticated SOCKS5 proxies ("Browser does not
# support socks5 proxy authentication") and many gateways reject locally
# resolved DNS (socks5://). The bridge listens as a plain local HTTP proxy
# (no auth — Firefox loves that) and relays CONNECT/GET traffic to the
# upstream gateway with the credentials injected, resolving DNS remotely.
# Same pattern as LocalAuthProxyBridge in grok-regkit.
# ---------------------------------------------------------------------------

_UPSTREAM: dict = {}


class _AuthBridgeHandler(socketserver.BaseRequestHandler):
    def _relay(self, src: socket.socket, dst: socket.socket, timeout: float = 180.0) -> None:
        """Bidirectional relay using two pump threads (blocking one-way relay
        deadlocks TLS: the handshake needs simultaneous both-direction I/O)."""
        src.settimeout(timeout)
        dst.settimeout(timeout)

        def pump(a: socket.socket, b: socket.socket) -> None:
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for sock in (a, b):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=pump, args=(src, dst), daemon=True)
        t2 = threading.Thread(target=pump, args=(dst, src), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def _connect_upstream(self) -> socket.socket:
        s = socket.create_connection((_UPSTREAM["host"], _UPSTREAM["port"]), timeout=20)
        if _UPSTREAM["socks"]:
            # minimal SOCKS5 handshake with remote DNS (ATYP=0x03 hostname)
            s.sendall(b"\x05\x01\x02")  # greet: support user/pass auth
            resp = s.recv(2)
            if len(resp) < 2 or resp[0] != 5:
                raise OSError("socks5: bad greeting")
            if resp[1] == 0x02:
                user = _UPSTREAM["user"].encode()
                pwd = _UPSTREAM["pass"].encode()
                s.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
                resp = s.recv(2)
                if len(resp) < 2 or resp[1] != 0:
                    raise OSError("socks5: auth rejected")
            elif resp[1] != 0x00:
                raise OSError("socks5: no acceptable auth method")
        return s

    def _socks5_connect_remote(self, s: socket.socket, host: str, port: int) -> None:
        """SOCKS5 CONNECT with hostname (ATYP=0x03) so DNS resolves at the gateway."""
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        resp = s.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise OSError(f"socks5: connect failed code={resp[1] if len(resp) > 1 else '?'}")

    def _inject_auth_header(self, data: bytes) -> bytes:
        """Rewrite/add 'Proxy-Authorization: Basic ...' on the first request."""
        if not _UPSTREAM.get("user"):
            return data
        import base64

        token = base64.b64encode(f"{_UPSTREAM['user']}:{_UPSTREAM['pass']}".encode()).decode()
        head, sep, rest = data.partition(b"\r\n\r\n")
        if not sep:
            return data
        lines = head.split(b"\r\n")
        out = [lines[0]]
        for ln in lines[1:]:
            if ln.lower().startswith(b"proxy-authorization:"):
                continue  # drop existing
            out.append(ln)
        out.append(f"Proxy-Authorization: Basic {token}".encode())
        return b"\r\n".join(out) + b"\r\n\r\n" + rest

    def handle(self) -> None:
        try:
            self.request.settimeout(20)
            first = self.request.recv(65536)
            if not first:
                return
            if first[:7] == b"CONNECT":
                # --- HTTPS tunnel ---
                line = first.split(b"\r\n", 1)[0]
                hostport = line.split()[1].decode()
                host, _, port_s = hostport.rpartition(":")
                port = int(port_s or "443")
                upstream = self._connect_upstream()
                if _UPSTREAM["socks"]:
                    # SOCKS5 CONNECT with remote DNS, then tell the browser the
                    # tunnel is up — do NOT wait for upstream data (deadlock:
                    # upstream waits for the browser's TLS ClientHello).
                    self._socks5_connect_remote(upstream, host, port)
                    self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                else:
                    # HTTP upstream: forward CONNECT with auth injected, relay
                    # the gateway's own 2xx reply to the browser
                    authed = self._inject_auth_header(first)
                    upstream.sendall(authed)
                    reply = self._wait_http_connect_reply(upstream)
                    self.request.sendall(reply)
                self._relay(self.request, upstream)
            else:
                # --- plain HTTP: forward the full request with auth injected ---
                upstream = self._connect_upstream()
                upstream.sendall(self._inject_auth_header(first))
                self._relay(self.request, upstream)
        except OSError:
            pass
        finally:
            try:
                self.request.close()
            except OSError:
                pass

    @staticmethod
    def _wait_http_connect_reply(upstream: socket.socket, timeout: float = 20.0) -> bytes:
        """Read the upstream HTTP proxy's CONNECT reply (up to the blank line)."""
        upstream.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf or b"HTTP/1.1 502 Bad Gateway\r\n\r\n"


class LocalAuthProxyBridge:
    """Run a local no-auth HTTP proxy that forwards to an authed upstream.

    Use for SOCKS5-with-auth upstreams (Firefox can't authenticate to SOCKS5)
    or HTTP upstreams behind DataDome-style rulesets. DNS for CONNECT is
    resolved at the gateway (hostname-based SOCKS5 ATYP=0x03).
    """

    def __init__(self, proxy_url: str):
        p = urlsplit(proxy_url.strip())
        scheme = (p.scheme or "http").lower()
        if scheme in ("socks", "socks5", "socks5h"):
            scheme = "socks5"
        if not p.hostname:
            raise SignupError(f"invalid proxy url for bridge: {proxy_url}")
        self._upstream = {
            "host": p.hostname,
            "port": p.port or (1080 if scheme == "socks5" else 8080),
            "user": p.username or "",
            "pass": p.password or "",
            "socks": scheme == "socks5",
        }
        self._server: Optional[socketserver.ThreadingTCPServer] = None
        self.port: Optional[int] = None

    def start(self) -> int:
        global _UPSTREAM
        _UPSTREAM = self._upstream
        for attempt in range(20):
            candidate = 20000 + (os.getpid() % 10000) + attempt * 7
            try:
                self._server = socketserver.ThreadingTCPServer(
                    ("127.0.0.1", candidate), _AuthBridgeHandler
                )
                self._server.daemon_threads = True
                self.port = candidate
                threading.Thread(target=self._server.serve_forever, daemon=True).start()
                return candidate
            except OSError:
                continue
        raise SignupError("local auth proxy bridge: no free port found")

    def stop(self) -> None:
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    def browser_proxy(self) -> dict:
        """Playwright proxy dict pointing at the local bridge (no auth)."""
        return {"server": f"http://127.0.0.1:{self.port}"}


_bridge: Optional[LocalAuthProxyBridge] = None


def _stop_proxy_bridge() -> None:
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None


def _rotate_sticky_proxy() -> None:
    """Discard a blocked DataImpulse sticky port and allocate a new one."""
    global _sticky_suffix, _last_exit_ip
    _stop_proxy_bridge()
    _sticky_suffix = None
    _last_exit_ip = None


def _disable_blocked_proxy(log) -> None:
    """Tell the proxy rotator to permanently disable the current upstream proxy.

    POST to http://127.0.0.1:8100/disable — the rotator comments out the proxy
    in proxies.txt so it's never used again.
    """
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:8100/disable",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        if data.get("ok"):
            log(f"[!] permanently disabled proxy: {data.get('disabled')} ({data.get('remaining')} remaining)")
        else:
            log(f"[i] proxy disable: {data}")
    except Exception as exc:
        log(f"[i] could not disable proxy via rotator: {exc}")


def _proxy_needs_bridge(proxy: Optional[dict]) -> bool:
    """Firefox rejects authed SOCKS5; bridge it locally."""
    return bool(proxy) and str(proxy.get("server", "")).startswith("socks") and proxy.get("username")


def _page_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=3000)
    except Exception:
        return ""


def _first(page, selectors: list[str], visible: bool = False):
    for sel in selectors:
        loc = page.locator(sel).first
        try:
            if loc.count() == 0:
                continue
            if not visible or loc.is_visible():
                return loc
        except Exception:
            continue
    raise SignupError(f"no visible element matching {selectors}")


def _wait_step(page, selectors: list[str], label: str, timeout: int = 30) -> None:
    try:
        page.wait_for_selector(", ".join(selectors), state="visible", timeout=timeout * 1000)
    except Exception:
        raise SignupError(f"{label} did not appear; body={_page_text(page)[:300]!r}")


def _fill(page, selectors: list[str], value: str) -> None:
    _first(page, selectors, visible=True).fill(value)


def _human_fill(page, selectors: list[str], value: str, stop=None) -> None:
    """Type a signup value progressively so GitHub's async validators run.

    `locator.fill()` injects a whole value in one DOM task. GitHub's signup
    form validates email/password/username and obtains an Octocaptcha token
    asynchronously; instant fills often leave Create account disabled. Typing
    at a modest, consistent pace plus blur matches the normal UI path.
    """
    field = _first(page, selectors, visible=True)
    _raise_if_cancelled(stop)
    # Do not pointer-click inputs here. GitHub's Octocaptcha can briefly place
    # an invisible overlay above a perfectly valid field, causing click() to
    # time out after "performing click action". DOM focus has the same input
    # semantics without needing a pointer target.
    try:
        field.focus(timeout=5_000)
    except Exception:
        field.evaluate("el => el.focus()")
    field.fill("")
    # Fixed cadence is deliberate: rapid random typing is less human than a
    # coherent typing speed. Passwords use the same path but are never logged.
    field.press_sequentially(value, delay=55)
    _raise_if_cancelled(stop)
    try:
        field.evaluate("el => el.blur()")
    except Exception:
        pass


def _form_validation_hint(page) -> str:
    """Return a concise visible validation error when Create account is disabled."""
    try:
        alerts = page.locator("[role='alert'], .is-error, .error, .flash-error").all()
        messages = []
        for alert in alerts:
            try:
                text = (alert.inner_text(timeout=500) or "").strip()
            except Exception:
                continue
            if text and "may only contain alphanumeric" not in text.lower():
                messages.append(text)
        if messages:
            return " | ".join(messages[:3])[:300]
    except Exception:
        pass
    return ""


def _click_submit(page) -> None:
    """Click the real signup Continue button, never the Google/Apple OAuth buttons.

    The signup page has 3 forms: 2 OAuth (/sessions/social/*) and 1 main
    (action contains 'signup'). Scope the submit click to the main form;
    fall back to legacy selectors for later steps (OTP/preferences pages).
    """
    scoped = page.locator("form[action*='signup'] button[type='submit']").first
    try:
        if scoped.count() and scoped.is_visible() and scoped.is_enabled():
            scoped.click()
            return
    except Exception:
        pass
    _first(page, _SUBMIT_SELECTORS, visible=True).click()


def _reject_blocked(page) -> None:
    """GitHub risk engine may force a 'Login to continue' device interstitial."""
    text = _page_text(page).lower()
    for marker in ("login to continue", "log in with a different device"):
        if marker in text:
            raise SignupBlocked(f"github risk check: {marker}")


def _cancel_order(mail, order_id: str, log) -> None:
    """Cancel the Litensi order after a failed registration.

    For Mail.cx this is a no-op (no order system). Litensi returns HTTP 404
    with ``CANCEL AFTER 4 MINUTES`` when the order is already past the cancel
    window — that is expected on longer flows and is logged at info level.
    """
    if isinstance(mail, LitensiClient) and order_id:
        try:
            mail.set_status(order_id, "CANCELED")
            log(f"[*] litensi order {order_id} canceled")
        except Exception as exc:
            msg = str(exc)
            if "CANCEL AFTER" in msg or "HTTP 404" in msg:
                log(f"[i] litensi order {order_id} already past cancel window "
                    f"(no action needed)")
            else:
                log(f"[i] litensi cancel failed (non-fatal): {exc}")


def _confirm_order(mail, order_id: str, log) -> None:
    """Mark the Litensi order as SUCCESS after the code has been consumed.

    Documented in the Litensi API as ``setstatus SUCCESS``; called only when
    the account was successfully registered end-to-end (per litensi docs the
    order must be confirmed by the caller). Mail.cx has no order concept so
    this is a no-op there.
    """
    if isinstance(mail, LitensiClient) and order_id:
        # Prefer the last order id that actually delivered the code — after a
        # ``reorder`` the original id is no longer the right one to confirm.
        confirm_id = mail.last_order_id or order_id
        try:
            mail.mark_success(confirm_id)
            log(f"[*] litensi order {confirm_id} confirmed (SUCCESS)")
        except Exception as exc:
            msg = str(exc)
            if "HTTP 404" in msg:
                # order already expired / auto-confirmed on the provider side
                log(f"[i] litensi order {confirm_id} setstatus skipped "
                    f"(already past confirm window)")
            else:
                log(f"[i] litensi confirm failed (non-fatal): {exc}")


def _is_hard_block(page) -> bool:
    """DataDome hard block: 'Access is temporarily restricted' — no checkbox to solve."""
    text = ""
    try:
        text = _page_text(page).lower()
    except Exception:
        pass
    return any(marker in text for marker in _DATADOME_HARD_BLOCK_MARKERS)


def _raise_if_rate_limited(page) -> None:
    text = _page_text(page).lower()
    if any(marker in text for marker in _RATE_LIMIT_MARKERS):
        raise GitHubRateLimited(
            "GitHub secondary rate limit reached. Stop the job and wait before trying again; "
            "do not rotate/retry this limit."
        )


def _challenge_hint(page) -> str:
    """Return a short description of the anti-bot page GitHub served, or ''."""
    if "captcha-delivery" in page.url:
        return "DataDome challenge (geo.captcha-delivery.com)"
    try:
        html = page.content()[:2000]
    except Exception:
        html = ""
    if "captcha-delivery" in html or "id=\"cmsg\"" in html:
        return "DataDome challenge page"
    if "cf-chl" in html:
        return "Cloudflare challenge"
    return ""


def _try_click_datadome(page, log) -> None:
    """Best-effort click on the DataDome checkbox iframe (headed mode)."""
    try:
        for frame in page.frames:
            if "captcha-delivery" in (frame.url or ""):
                for sel in (
                    "#ddv1-test-tracking",
                    "input[type='checkbox']",
                    "[id*='checkbox']",
                    "label",
                ):
                    loc = frame.locator(sel).first
                    if loc.count() and loc.is_visible():
                        loc.click(timeout=3000)
                        log("[*] clicked DataDome checkbox")
                        return
                # no checkbox: click somewhere in the challenge frame to trigger it
                try:
                    frame.locator("body").click(timeout=3000)
                    log("[*] poked DataDome challenge frame")
                except Exception:
                    pass
                return
    except Exception:
        pass


def _form_ready(page) -> bool:
    sel = ", ".join(_EMAIL_INPUTS)
    try:
        return page.locator(sel).first.is_visible()
    except Exception:
        return False


SIGNUP_HOME_URL = "https://github.com/?utm_source=google"
SIGNUP_URL = "https://github.com/signup"
_HARD_BLOCK_MSG = (
    "DataDome HARD BLOCK: 'Access is temporarily restricted' — this IP is "
    "temporarily blocked by GitHub. Change IP, disable VPN/WARP, change network, "
    "or configure a residential proxy and retry."
)


def _wait_for_signup(page, log, stop, seconds: int) -> bool:
    """Wait `seconds` for the email form, poking a DataDome challenge if shown.

    Raises SignupBlocked on a hard block and GitHubRateLimited on a rate limit
    so the caller's retry policy still applies. Returns False on timeout.
    """
    deadline = time.time() + seconds
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        if _is_hard_block(page):
            raise SignupBlocked(_HARD_BLOCK_MSG)
        if _form_ready(page):
            return True
        _try_click_datadome(page, log)
        _sleep_with_cancel(2, stop)
    return False


def _warmup_dwell(page, log, stop=None, min_s: float = 4.0, max_s: float = 7.0) -> None:
    """Human-like warm-up on the current page: random dwell, mouse moves,
    scroll a bit. Ported from Git_clean fast_hunt_warm (field-verified:
    warm sessions reach the CLEAN signup form far more often than cold ones)."""
    import random as _r
    log(f"[*] warm-up dwell ({min_s:.0f}-{max_s:.0f}s)")
    _sleep_with_cancel(_r.uniform(min_s, max_s), stop)
    # NOTE: Playwright's mouse API has NO timeout — mouse.move on a
    # half-loaded page hangs the protocol call forever. Use JS scroll
    # (evaluate honors the default timeout) + plain sleeps instead.
    try:
        page.set_default_timeout(6_000)
        for _ in range(_r.randint(2, 3)):
            page.evaluate(
                "(d) => window.scrollBy({top: d, behavior: 'smooth'})",
                _r.randint(120, 420))
            _sleep_with_cancel(_r.uniform(0.8, 2.0), stop)
        page.evaluate("() => window.scrollBy({top: -150, behavior: 'smooth'})")
        _sleep_with_cancel(_r.uniform(0.8, 1.6), stop)
    except Exception:
        pass
    finally:
        try:
            page.set_default_timeout(30_000)
        except Exception:
            pass
    _sleep_with_cancel(_r.uniform(1.5, 3.0), stop)


def _open_signup(page, log, attempts: int = 3, stop=None, headless: bool = False) -> None:
    """Open github.com/signup the way a visitor arrives from a search result.

    Entry is the GitHub homepage with a Google referral query, then the header
    "Sign up" link, so the session carries a referral instead of a cold direct
    hit. A direct /signup load is the fallback when the link is missing or the
    form never renders. A manual solve window is given at the end in headed mode.
    """
    last_hint = ""
    proxy_fails = 0
    _PROXY_DEAD_MARKERS = (
        "NS_ERROR_PROXY", "ERR_PROXY", "PROXY_CONNECTION", "ProxyError",
        "proxy", "NS_ERROR_NET_TIMEOUT", "<unknown error>",
        "Page.goto: Timeout", "navigation timeout",
    )
    for attempt in range(1, attempts + 1):
        _raise_if_cancelled(stop)
        home_ok = False
        try:
            log(f"[*] opening {SIGNUP_HOME_URL}")
            page.goto(SIGNUP_HOME_URL, wait_until="domcontentloaded", timeout=60_000)
            home_ok = True
        except Exception as exc:
            home_ok = False
            log(f"[!] goto homepage failed ({exc}); retry {attempt}/{attempts}")
            exc_s = str(exc).lower()
            if any(m.lower() in exc_s for m in _PROXY_DEAD_MARKERS):
                proxy_fails += 1
                if proxy_fails >= 2:
                    # the exit proxy itself is dead — retrying on it only burns
                    # minutes; escalate so the outer loop disables + rotates it
                    raise SignupBlocked(f"proxy dead on navigation: {str(exc)[:120]}")
        # WARM-UP (ported from Git_clean fast_hunt_warm): dwell on the homepage
        # like a real visitor — DataDome/Picasso score instant navigations as
        # bot-like. Only when the page actually loaded; mouse ops on a dead
        # page hang the protocol forever.
        if home_ok:
            try:
                _warmup_dwell(page, log, stop)
            except Exception as exc:
                log(f"[i] warmup skipped: {exc}")
        # homepage -> "Sign up" link: the navigation a real visitor follows
        try:
            link = page.get_by_role("link", name="Sign up").first
            if link.count():
                link.click(timeout=10_000)
        except Exception as exc:
            log(f"[i] 'Sign up' link skipped: {exc}")
        # dwell on the signup page before touching the form (Git_clean: 9s)
        _sleep_with_cancel(random.uniform(6.0, 10.0), stop)
        if _wait_for_signup(page, log, stop, 30):
            log("[*] github.com/signup email form is ready")
            return
        last_hint = _challenge_hint(page) or last_hint
        if attempt < attempts:
            # fallback: cold direct load, still inside the retry budget
            try:
                _raise_if_cancelled(stop)
                page.goto(SIGNUP_URL, wait_until="domcontentloaded", timeout=60_000)
            except Exception as exc:
                log(f"[!] direct /signup goto failed: {exc}")
                exc_s = str(exc).lower()
                if any(m.lower() in exc_s for m in _PROXY_DEAD_MARKERS):
                    proxy_fails += 1
                    if proxy_fails >= 2:
                        raise SignupBlocked(f"proxy dead on navigation: {str(exc)[:120]}")
            if _wait_for_signup(page, log, stop, 25):
                log("[*] email form ready on direct /signup load")
                return
            last_hint = _challenge_hint(page) or last_hint
            log(f"[!] {last_hint or 'form not ready'} — reload attempt {attempt + 1}/{attempts}")
    if last_hint:
        if headless:
            # no visible window to solve the challenge in — fail fast instead of
            # burning 120s on a manual-solve window that cannot be seen
            raise SignupError(
                f"{last_hint} in headless mode — solve requires a visible browser "
                f"window; use a residential proxy or set headless=false"
            )
        # final long wait: challenge may need a manual click in the visible window
        log(f"[!] {last_hint} — waiting up to 120s; solve the check in the browser window "
            f"if visible, or configure a residential proxy")
        _try_click_datadome(page, log)
        if _wait_for_signup(page, log, stop, 120):
            log("[*] challenge passed, email form is ready")
            return
    raise SignupError(f"email form did not appear ({last_hint or 'no challenge marker'}); "
                      f"IP is blocked by DataDome — use a residential proxy in config")


def _username_error(page) -> str:
    """Return the username validation error shown under the field, or ''.

    IMPORTANT: 'Username may only contain alphanumeric...' is a PERMANENT helper
    (id=username-helper), not an error. Real errors render inside the auto-check
    element above it (role=alert / .is-error text), e.g. 'Username is not
    available' or 'Username xyz is not available'.
    """
    try:
        # error text lives in <auto-check> successors with role=alert
        alerts = page.locator("auto-check [role='alert'], .is-error, [role='alert']").all()
        for a in alerts:
            try:
                txt = (a.inner_text(timeout=1000) or "").strip().lower()
            except Exception:
                continue
            if "username" in txt and "may only contain" not in txt:
                if "not available" in txt or "already taken" in txt:
                    return "taken"
                if txt:
                    return "invalid"
        # fallback: visible error paragraphs mentioning the typed name
        text = _page_text(page)[:1200].lower()
        if "username is not available" in text or "username is already taken" in text:
            return "taken"
    except Exception:
        pass
    return ""


def _dom_click_create_account(page) -> bool:
    """JS .click() on the ENABLED submit button — bypasses pointer hit-testing.

    When the button is enabled, JS click() runs the page's real handler (this
    is how a keyboard Enter on a focused form submits). Unlike force=True it
    does NOT fire a pointer event into whatever overlay covers the button, so
    it cannot trigger the 'Sorry, something went wrong' flash error.
    Returns True when the click landed on an enabled button.
    """
    return bool(
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='signup']");
                const b = form && form.querySelector("button[type='submit']");
                if (!b || b.disabled) return false;
                b.click();
                return true;
            }"""
        )
    )


def _click_create_account(page, log, wait_enabled: int = 30, stop=None) -> None:
    """Click 'Create account' once it is ENABLED.

    GitHub gates the button on the octocaptcha token, so first wait for
    `disabled` to clear. Then submit in the safest order:
      1. native pointer click (most human-like)
      2. JS DOM click on the enabled button — pointer events can be eaten by
         an invisible Octocaptcha/DataDome overlay; DOM click cannot
    A force=True pointer click is deliberately NOT used: it fires a real
    pointer event at the overlay's coordinates and has produced GitHub's
    'Sorry, something went wrong' flash error.
    """
    btn = page.locator("form[action*='signup'] button[type='submit']").first
    deadline = time.time() + wait_enabled
    enabled = False
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        try:
            if btn.count() and btn.is_visible() and btn.is_enabled():
                enabled = True
                break
        except Exception:
            pass
        _sleep_with_cancel(0.8, stop)
    if enabled:
        # an invisible/visible Octocaptcha overlay is often what eats the
        # pointer click — poke the captcha frame first so it can finish
        _try_click_datadome(page, log)
        try:
            btn.click(timeout=10_000)
            log("[*] 'Create account' clicked (button enabled)")
            return
        except Exception as exc:
            log(f"[i] native click intercepted ({exc}); trying DOM click on enabled button")
            if _dom_click_create_account(page):
                log("[*] 'Create account' clicked via DOM (overlay bypassed)")
                return
            log("[!] DOM click found the button disabled again — validation regressed")
    # Do not force-submit a disabled form. Its disabled state means GitHub has
    # not completed its email/password/username/Octocaptcha checks yet; forcing
    # it creates false submits, secondary rate-limit pressure, and stuck flows.
    # A TAKEN username keeps the button disabled forever — report it precisely
    # so the caller retries with a fresh suffix instead of reloading the page
    # with the same data (which just burns attempts).
    if _username_error(page) == "taken":
        raise SignupError("username taken (Create account disabled by validation)")
    hint = _form_validation_hint(page)
    raise SignupError(
        "Create account stayed disabled after validation wait"
        + (f": {hint}" if hint else " (Octocaptcha or async validation still pending)")
    )


def _fill_and_create_account(page, base_username: str, tries: int, log, stop=None) -> str:
    """Fill username, wait 3s, CLICK 'Create account', verify the page reacts.

    If GitHub answers with a username error, append one digit and retry
    (name -> name2 -> name3 ...). Returns the accepted username once the
    page actually moves past the signup form.
    """
    name = base_username
    for attempt in range(1, tries + 1):
        _raise_if_cancelled(stop)
        _human_fill(page, _USERNAME_INPUTS, name, stop=stop)
        # GitHub debounces username availability; wait for the server result.
        _sleep_with_cancel(3.5, stop)
        try:
            _click_create_account(page, log, stop=stop)
        except SignupError as exc:
            # 'Create account' stayed disabled because the NAME is taken —
            # retry with a fresh random suffix instead of burning a page reload
            if "username taken" in str(exc) and attempt < tries:
                name = f"{base_username}{random.randint(1000, 99999)}"
                log(f"[*] username taken (disabled button), new suffix -> {name} ({attempt}/{tries})")
                continue
            raise

        # wait for reaction: error under username field OR page moving forward
        deadline = time.time() + 15
        reacted = False
        while time.time() < deadline:
            _raise_if_cancelled(stop)
            _raise_if_rate_limited(page)
            _sleep_with_cancel(1, stop)
            err = _username_error(page)
            if err == "taken":
                # random 3-4 digit suffix: sequential name2/name3 are also
                # usually taken when the base is a short common word
                name = f"{base_username}{random.randint(100, 9999)}"
                log(f"[*] username taken, retry with random suffix -> {name} ({attempt}/{tries})")
                reacted = True
                break
            if err == "invalid":
                raise SignupError(f"username {name} rejected as invalid")
            # page moved on from the signup form -> submit accepted
            if not _form_ready(page):
                return name
            if "signup" not in page.url:
                return name
        if reacted:
            continue  # username was taken — loop with the next suffix
        # no error and no movement: the submit never registered (button still
        # disabled by octocaptcha?) — one JS-click retry, then fail loudly
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='signup']");
                const b = form && form.querySelector("button[type='submit']");
                if (b) b.click();
            }"""
        )
        _sleep_with_cancel(5, stop)
        if not _form_ready(page) or "signup" not in page.url:
            return name
        raise SignupError(
            f"'Create account' did nothing after two clicks (username={name}); "
            f"octocaptcha/DataDome gate never lifted — retry the run or change IP"
        )
    raise SignupError(f"username still taken after {tries} tries (base={base_username})")


def _verify_input_visible(page) -> bool:
    """Is any e-mail verification code input visible? (launch-code page)"""
    for sel in _OTP_INPUTS:
        try:
            if page.locator(sel).first.is_visible():
                return True
        except Exception:
            continue
    return False


def _verify_page_markers(page) -> bool:
    """Text markers of the email-verification ('launch code') page."""
    try:
        text = _page_text(page)[:2000].lower()
    except Exception:
        return False
    return any(
        m in text
        for m in ("launch code", "verify your email", "check your email",
                  "enter the code", "we sent a code", "verification code")
    )


def _logged_in(context) -> bool:
    """Reliable success signal: GitHub sets cookie logged_in=yes on a real session."""
    try:
        for c in context.cookies():
            if c.get("name") == "logged_in" and str(c.get("value", "")).lower() == "yes":
                return True
    except Exception:
        pass
    return False


def _post_submit_state(page, context) -> str:
    """Classify what GitHub shows after 'Create account'.

    Returns one of:
      'verify' — email verification (launch code) page: code input visible or markers
      'done'   — logged in (cookie logged_in=yes) or a welcome/onboarding page
      'pending'— still transitioning
    """
    if _verify_input_visible(page):
        return "verify"
    if _logged_in(context):
        return "done"
    url = page.url or ""
    text = ""
    try:
        text = _page_text(page)[:2000].lower()
    except Exception:
        pass
    if _verify_page_markers(page):
        return "verify"
    if "signup" in url:
        return "pending"
    # off /signup without verify markers and without login cookie — ambiguous,
    # treat onboarding/welcome/created-successfully text as done, else pending
    if any(m in text for m in ("welcome to github", "let's get started", "get started",
                               "what do you want to do", "your github journey",
                               "your account was created successfully")):
        return "done"
    return "pending"


def _wait_post_submit(page, context, timeout: int = 120, log=None, stop=None) -> str:
    """Wait after submit until the state is stable (not 'pending').

    Anti-race: require the state to hold for 2 consecutive checks (≥4s) before
    deciding, so a mid-transition page can't be misread as 'done'.
    """
    stable_state = ""
    stable_hits = 0
    deadline = time.time() + timeout
    last_log = 0.0
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        state = _post_submit_state(page, context)
        if state != "pending":
            if state == stable_state:
                stable_hits += 1
            else:
                stable_state = state
                stable_hits = 1
            if stable_hits >= 2:
                return state
        else:
            stable_state = ""
            stable_hits = 0
        if log and time.time() - last_log >= 3:
            log(f"[*] post-submit state={state or 'pending'} url={page.url}")
            last_log = time.time()
        _sleep_with_cancel(2, stop)
    raise SignupError(
        f"post-submit state never stabilized; url={page.url} "
        f"body={_page_text(page)[:200]!r}"
    )


def _browser_ctx_options(cfg: Config, log=None) -> dict:
    """Launch options tuned for DataDome (see 2026 field guides):

    - fresh_profile=True: a NEW browser per account (incognito-like, zero
      cached state — no stacked GitHub logins). The DataDome trust cookie is
      carried over separately via .datadome-trust.json (see _save_trust_cookie
      / _restore_trust_cookie) so the signup page keeps loading.
    - persistent profile (fresh_profile=False): keeps the whole profile incl.
      the `datadome` cookie (accumulated trust) — but GitHub sessions stack.
    - geoip=True: timezone/locale aligned with the (proxy) exit IP
    - os=host OS: Picasso canvas hash matches the REAL device class we run on
    - headful by default: headless rendering is a Picasso tell

    SOCKS proxies: Camoufox's own geoip probe uses plain 'socks5://' which many
    gateways (DataImpulse: '0x02 connection not allowed by ruleset') reject
    because DNS is resolved locally. For SOCKS we resolve the exit IP ourselves
    via 'socks5h://' and pass geoip=<ip> so Camoufox skips its probe.
    """
    import platform

    opts = {"headless": cfg.headless, "humanize": True, "geoip": True}
    host_os = platform.system()
    if host_os == "Darwin":
        opts["os"] = "macos"  # canvas/GPU class must match the real machine
    elif host_os == "Linux":
        opts["os"] = "linux"
    elif host_os == "Windows":
        opts["os"] = "windows"
    # sticky session FIRST: one stable exit IP for the whole job — rotating
    # IPs mid-session (DataImpulse default) are an instant DataDome flag
    raw_proxy = _pick_proxy_url(cfg, log=log)
    proxy_url = _ensure_sticky_proxy(raw_proxy, log=log) if raw_proxy else ""
    proxy = _parse_proxy(proxy_url) if proxy_url else None
    if proxy:
        if _proxy_needs_bridge(proxy):
            # Firefox cannot authenticate to SOCKS5 — run a local no-auth HTTP
            # bridge that relays to the authed upstream with remote DNS.
            # Reuse an already-running bridge so a NEW bridge is NOT started
            # for every fresh-profile launch (bridge is sticky-session-bound).
            global _bridge
            if _bridge is None:
                _bridge = LocalAuthProxyBridge(proxy_url)
                _bridge.start()
                if log:
                    log(f"[*] local auth bridge 127.0.0.1:{_bridge.port} -> "
                        f"{proxy['server']} (socks5 auth handled locally)")
            opts["proxy"] = _bridge.browser_proxy()
        else:
            opts["proxy"] = proxy
        if _proxy_is_socks(proxy):
            try:
                exit_ip = _socks_exit_ip(proxy_url)
                opts["geoip"] = exit_ip
                global _last_exit_ip
                _last_exit_ip = exit_ip  # consumed by trust-cookie IP binding
                if log:
                    log(f"[*] socks proxy exit IP: {exit_ip} (geoip pinned, sticky)")
            except Exception as exc:
                opts["geoip"] = False
                _last_exit_ip = None  # no IP to bind — do NOT restore stale cookies
                if log:
                    log(f"[!] socks exit-IP lookup failed ({exc}); geoip disabled — "
                        f"timezone/locale may mismatch the proxy country. "
                        f"Trust cookie will NOT be restored (IP unknown).")
    if getattr(cfg, "fresh_profile", False):
        # fresh browser per account — no user_data_dir at all
        if log:
            log("[*] fresh profile mode: new browser without cache (DataDome trust cloned)")
    elif cfg.browser_profile_dir:
        opts["persistent_context"] = True
        opts["user_data_dir"] = str((ROOT / cfg.browser_profile_dir).resolve())
    return opts


# ---------------------------------------------------------------------------
# DataDome trust-cookie carry-over for fresh-profile mode
#
# A brand-new browser has zero cookies — DataDome will challenge it. We persist
# ONLY the `datadome` cookie (+device id) to .datadome-trust.json after each
# successful run and inject it into every fresh context. No GitHub session
# state is ever carried over, so accounts never stack.
# ---------------------------------------------------------------------------

_TRUST_FILE = ROOT / ".datadome-trust.json"
_TRUST_COOKIE_NAMES = {"datadome", "datadome_proxied", "device_id", "_device_id"}


def _save_trust_cookie(context, log=None) -> None:
    """Persist only the DataDome trust cookies, bound to the current exit IP.

    A datadome cookie issued for IP A looks forged when replayed from IP B —
    worse than no cookie at all. We therefore store the exit IP alongside and
    only restore when the IP matches (sticky session keeps it stable in-job).
    """
    try:
        cookies = context.cookies()
        keep = [
            c for c in cookies
            if c.get("name") in _TRUST_COOKIE_NAMES and c.get("domain", "").endswith("github.com")
        ]
        if not keep:
            return
        _TRUST_FILE.write_text(
            json.dumps({
                "cookies": keep,
                "exit_ip": _last_exit_ip or "",
                "saved_at": datetime.now().isoformat(timespec="seconds"),
            }),
            encoding="utf-8",
        )
        if log:
            log(f"[*] datadome trust cookie saved ({len(keep)} cookies, ip={_last_exit_ip or 'n/a'})")
    except Exception as exc:
        if log:
            log(f"[i] trust cookie save failed: {exc}")


def _restore_trust_cookie(context, log=None) -> None:
    """Inject persisted DataDome trust cookies — ONLY if the exit IP matches.

    Mismatched IP -> skip silently (a fresh challenge is less suspicious than
    a cookie replayed from the wrong IP). When exit IP is unknown (lookup
    failed), also skip — restoring a stale IP-bound cookie is worse than none.
    """
    try:
        if not _TRUST_FILE.is_file():
            return
        data = json.loads(_TRUST_FILE.read_text(encoding="utf-8"))
        cookies = data.get("cookies") or []
        if not cookies:
            return
        bound_ip = data.get("exit_ip") or ""
        # No current exit IP? Don't guess — skip restore entirely
        if not _last_exit_ip:
            if log:
                log("[i] trust cookie skipped (current exit IP is unknown; lookup failed)")
            return
        if bound_ip and _last_exit_ip and bound_ip != _last_exit_ip:
            if log:
                log(f"[i] trust cookie skipped (bound to IP {bound_ip}, current IP {_last_exit_ip})")
            return
        # context.add_cookies requires url OR domain+path
        clean = []
        for c in cookies:
            cc = {k: c.get(k) for k in ("name", "value", "domain", "path",
                                        "expires", "httpOnly", "secure", "sameSite") if c.get(k) is not None}
            if "domain" not in cc or "path" not in cc:
                cc["domain"] = ".github.com"
                cc["path"] = "/"
            clean.append(cc)
        context.add_cookies(clean)
        if log:
            log(f"[*] datadome trust cookie restored ({len(clean)} cookies, ip={bound_ip or 'unbound'})")
    except Exception as exc:
        if log:
            log(f"[i] trust cookie restore failed: {exc}")


def _context_and_page(browser):
    """Return (context, page) for BOTH launch modes.

    persistent_context=True -> Camoufox returns a BrowserContext with one page
    fresh launch             -> Camoufox returns a Browser; create a context
                                + page ourselves.
    """
    if hasattr(browser, "cookies"):  # BrowserContext (persistent mode)
        context = browser
        page = context.pages[0] if context.pages else context.new_page()
    else:  # Browser (fresh mode)
        context = browser.new_context(locale="en-US")
        page = context.new_page()
    return context, page


def _clean_github_session_cookies(context, log) -> None:
    """Between accounts: drop GitHub login cookies, keep DataDome/trust cookies.

    A persistent profile survives across accounts, so 'logged_in'/'user_session'
    cookies must be cleared to avoid signing INTO the previous account instead
    of signing UP a new one. DataDome (datadome) cookies are kept — they carry
    the anti-bot trust that lets /signup load at all.
    """
    drop = {"logged_in", "user_session", "__Host-user_session_same_site", "_gh_sess", "dotcom_user"}
    try:
        cookies = context.cookies()
        keep = [c for c in cookies if c.get("name") not in drop]
        if len(keep) == len(cookies):
            return  # nothing to clean
        context.clear_cookies()
        for c in keep:
            try:
                context.add_cookies([c])
            except Exception:
                pass
        log("[*] session cookies cleared (DataDome trust kept)")
    except Exception as exc:
        log(f"[i] cookie cleanup skipped: {exc}")


def _fill_launch_code(page, code: str, log) -> None:
    """Fill the 8-box launch-code page (one digit per #launch-code-N input).

    Falls back to a single OTP input when the boxes are not present.
    """
    boxes = page.locator("input[id^='launch-code-']")
    count = boxes.count()
    if count >= len(code):  # 8 boxes for an 8-digit code
        for i, digit in enumerate(code):
            boxes.nth(i).fill(digit)
            time.sleep(0.15)  # small human cadence between boxes
        log(f"[*] launch code typed into {len(code)} boxes")
        try:
            page.locator(
                "button[class*='Button--primary'], button[class*='Button-module__Button--primary']"
            ).first.click(timeout=5000)
            log("[*] launch code submitted")
        except Exception:
            log("[*] no submit button found — launch code may auto-submit")
        return
    # single input fallback
    otp = _first(page, _OTP_INPUTS, visible=True)
    if not otp.input_value():
        otp.fill(code)
    _click_submit(page)
    log("[*] OTP submitted")


_LOGIN_INPUTS = ["#login_field", "input[name='login']", "input#login"]
_LOGIN_PASS_INPUTS = ["#password", "input[name='password']", "input[type='password']"]


def _try_login(
    page,
    username: str,
    password: str,
    context,
    log,
    mail=None,
    order_id: str = "",
    email: str = "",
    otp_timeout: int = 240,
    used_codes: Optional[set] = None,
    stop=None,
) -> bool:
    """GitHub sends fresh signups to /login: sign in to obtain logged_in=yes.

    Because ``fresh_profile`` mode gives every account a brand-new browser
    profile, GitHub often treats the resulting login as coming from an
    unrecognized device and challenges it with ANOTHER launch-code email
    (device verification). When that page shows up after the credentials are
    submitted, poll the same mailbox for a NEW code — codes already used
    (e.g. the one from signup) are excluded — and fill it in before waiting
    for the ``logged_in`` session cookie.

    Returns True when the login cookie is present afterwards.
    """
    used = set(used_codes or ())
    try:
        user = page.locator(", ".join(_LOGIN_INPUTS)).first
        if not user.is_visible():
            return _logged_in(context)
        user.fill(username, timeout=5000)
        page.locator(", ".join(_LOGIN_PASS_INPUTS)).first.fill(password, timeout=5000)
        time.sleep(0.5)
        # the sign-in button lives in form[action='/session'] but is NOT
        # type=submit (only Google/Apple are). Click the form's own button.
        page.evaluate(
            """() => {
                const form = document.querySelector("form[action*='session']");
                if (!form) return;
                // prefer a real submit element, else the last button in the form
                let btn = form.querySelector("input[type='submit'], button:not([type='button'])");
                if (!btn) {
                    const btns = form.querySelectorAll("button");
                    btn = btns[btns.length - 1];
                }
                if (btn) btn.click();
            }"""
        )
        log("[*] login form submitted after signup")
    except Exception as exc:
        log(f"[i] auto-login skipped: {exc}")

    verifications = 0
    while True:
        _raise_if_cancelled(stop)
        try:
            _raise_if_rate_limited(page)
        except Exception:
            raise  # GitHubRateLimited propagates for proxy rotation
        if _logged_in(context):
            return True
        on_verify = False
        try:
            on_verify = _verify_input_visible(page) or _verify_page_markers(page)
        except Exception:
            on_verify = False
        if on_verify:
            if mail is None:
                log("[!] device verification page shown but no mail client available")
                return False
            if verifications >= 2:
                log("[!] device verification requested more than twice — giving up")
                return False
            verifications += 1
            log(f"[*] device verification after login (url={page.url}) — waiting for a new code")
            try:
                code = mail.wait_for_code(
                    order_id,
                    timeout=otp_timeout,
                    log=log,
                    cancel_cb=stop,
                    email=email,
                    exclude_codes=used,
                )
            except RegistrationCancelled:
                raise
            except Exception as exc:
                if stop and stop():
                    raise RegistrationCancelled("cancelled during device verification wait")
                log(f"[!] second launch code never arrived: {exc}")
                return False
            log(f"[*] login verification code: {code}")
            used.add(code)
            _fill_launch_code(page, code, log)
            try:
                state = _wait_post_submit(page, context, timeout=90, log=log, stop=stop)
            except (RegistrationCancelled, GitHubRateLimited):
                raise
            except Exception as exc:
                log(f"[!] post-verification wait failed: {exc}")
                return False
            if state == "verify":
                log("[!] login verification code rejected (still on verify page)")
                return False
            continue
        # no verify page — wait up to 30s for the cookie, breaking early if
        # a verification page appears mid-wait
        deadline = time.time() + 30
        appeared = False
        while time.time() < deadline:
            _raise_if_cancelled(stop)
            if _logged_in(context):
                return True
            try:
                if _verify_input_visible(page) or _verify_page_markers(page):
                    appeared = True
                    break
            except Exception:
                pass
            time.sleep(1.5)
        if not appeared:
            log(f"[!] auto-login not confirmed within 30s — url={page.url}")
            return False


def _create_repository(page, username: str, base_name: str, log) -> str:
    """Stage 4 (user recording): create the first repository on /new.

    The name field auto-generates a suggestion; we type our own name and submit.
    Returns the repository name created.
    """
    def _submit() -> None:
        """Submit the visible enabled repo form without clicking an overlay."""
        btn = page.get_by_role("button", name="Create repository").first
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                if btn.count() and btn.is_visible() and btn.is_enabled():
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            raise SignupError("Create repository stayed disabled after validation wait")

        try:
            btn.click(timeout=10_000)
            log("[*] 'Create repository' clicked")
            return
        except Exception as exc:
            log(f"[i] repository native click intercepted ({exc}); trying DOM click")

        clicked = bool(page.evaluate(
            """() => {
                const buttons = [...document.querySelectorAll('button')];
                const button = buttons.find((b) =>
                    b.offsetParent !== null && !b.disabled &&
                    (b.textContent || '').trim() === 'Create repository'
                );
                if (!button) return false;
                button.click();
                return true;
            }"""
        ))
        if not clicked:
            raise SignupError("Create repository button was not visible/enabled for DOM click")
        log("[*] 'Create repository' clicked via DOM (overlay bypassed)")

    name = base_name or "hello"
    for _nav_try in range(2):
        try:
            page.goto("https://github.com/new", wait_until="domcontentloaded", timeout=60_000)
            break
        except Exception as _nav_exc:
            # fresh account lands on /dashboard which interrupts the /new nav —
            # settle and retry once
            if _nav_try == 0 and "interrupted" in str(_nav_exc):
                time.sleep(2.5)
                continue
            raise
    try:
        page.wait_for_selector("#repository-name-input", state="visible", timeout=30_000)
    except Exception:
        raise SignupError(f"repo form not found; url={page.url} body={_page_text(page)[:200]!r}")
    inp = page.locator("#repository-name-input").first
    inp.fill(name)
    try:
        # React ignores synthetic fill() in some builds — push the value
        # through the native setter so React state actually updates and the
        # Create button enables
        page.evaluate(
            """(name) => {
                const inp = document.querySelector('#repository-name-input')
                    || document.querySelector("input[name='repository[name]']");
                if (!inp) return;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(inp, name);
                inp.dispatchEvent(new Event('input', {bubbles: true}));
                inp.dispatchEvent(new Event('change', {bubbles: true}));
            }""",
            name,
        )
    except Exception:
        pass
    time.sleep(1.5)  # let GitHub validate + enable the submit button
    try:
        _submit()
    except Exception as exc:
        raise SignupError(f"cannot click 'Create repository': {exc}")
    # success = redirected to /<username>/<repo>
    deadline = time.time() + 30
    resubmitted = False
    while time.time() < deadline:
        url = page.url or ""
        if "/new" not in url and f"/{username}/" in url:
            log(f"[*] repository created: {url}")
            return name
        # still on /new after a while? the click may not have submitted the
        # form (React handler race) — force a native form submit once
        if not resubmitted and time.time() > deadline - 20 and "/new" in url:
            resubmitted = True
            try:
                ok = page.evaluate(
                    """() => {
                        const inp = document.querySelector('#repository-name-input')
                            || document.querySelector("input[name='repository[name]']");
                        if (!inp) return 'no-input';
                        const f = inp.closest('form');
                        if (!f) return 'no-form';
                        f.requestSubmit ? f.requestSubmit() : f.submit();
                        return true;
                    }"""
                )
                log(f"[*] forced form submit on /new (result={ok})")
                if ok == 'no-input':
                    # dump what github actually shows (error banner?)
                    try:
                        txt = _page_text(page)[:400].replace(chr(10), ' | ')
                        log(f"[i] /new page text: {txt}")
                    except Exception:
                        pass
            except Exception as exc:
                log(f"[i] forced submit failed: {exc}")
        # name conflict? GitHub shows an error — retry with a numeric suffix
        err = ""
        try:
            err = _page_text(page)[:600].lower()
        except Exception:
            pass
        if "already exists" in err and "/new" in url:
            log(f"[*] repo {name} exists, retry with suffix")
            name = f"{base_name}{int(time.time()) % 10000}"
            page.goto("https://github.com/new", wait_until="domcontentloaded", timeout=60_000)
            page.wait_for_selector("#repository-name-input", state="visible", timeout=20_000)
            page.locator("#repository-name-input").first.fill(name)
            time.sleep(1.5)
            _submit()
        time.sleep(1)
    # last chance: /new may create via fetch + client-side redirect that got
    # lost — check the repo URL directly
    try:
        probe = f"https://github.com/{username}/{name}"
        page.goto(probe, wait_until="domcontentloaded", timeout=30_000)
        time.sleep(1.5)
        cur = (page.url or "").rstrip("/")
        if cur.endswith(f"/{username}/{name}") and "This is not the web page" not in _page_text(page)[:400]:
            log(f"[*] repository confirmed by direct visit: {cur}")
            return name
    except Exception as exc:
        log(f"[i] repo direct-visit probe failed: {exc}")
    raise SignupError(f"repository creation not confirmed; url={page.url}")


def _fetch_public_profile() -> dict[str, str]:
    """Fetch one display identity and one quote without using their credentials."""
    random_user = requests.get("https://randomuser.me/api/", timeout=15).json()
    quote = requests.get("https://zenquotes.io/api/random", timeout=15).json()
    return parse_public_profile(random_user, quote)


def _visible_dom_click(page, matcher_js: str) -> bool:
    """Click a visible enabled button through DOM when overlays eat pointer input."""
    return bool(page.evaluate(
        f"""() => {{
            const button = [...document.querySelectorAll('button')].find({matcher_js});
            if (!button || button.disabled || button.offsetParent === null) return false;
            button.click();
            return true;
        }}"""
    ))


def _create_pat(page, password: str, log, username: str = "", email: str = "") -> str:
    """Stage 6 (ported from Git_clean enrich_account.create_pat): create a
    classic PAT with repo+workflow scopes. Returns 'ghp_...' or '' on failure.

    Flow: /settings/tokens/new -> sudo password if asked -> note -> scopes ->
    Generate token -> read token from page (it is shown ONCE).
    """
    import re as _re
    # retry loop: fresh accounts on flagged IPs bounce /settings -> /login
    # multiple times (GitHub re-auth loop). Give the gate 2 full attempts.
    landed = False
    for attempt in (1, 2):
        page.goto("https://github.com/settings/tokens/new",
                  wait_until="domcontentloaded", timeout=60_000)
        _sleep_with_cancel(4)
        if "/login" not in (page.url or ""):
            landed = True
            break
        _pass_sudo_gate(page, password, log, username, email)
        if "tokens/new" in (page.url or ""):
            landed = True
            break
        # detect device-verification / unusual-activity wall
        try:
            txt = (_page_text(page) or "").lower()
        except Exception:
            txt = ""
        if "unusual" in txt or "device" in txt and "activation" in txt:
            log("[!] PAT blocked: GitHub device verification wall (suspicious IP) — skipping")
            return ""
        log(f"[!] PAT gate attempt {attempt} did not land on tokens/new (url={page.url})")
    if not landed:
        log("[!] PAT: stuck in login redirect loop — skipping PAT stage")
        return ""
    # sudo (password) gate
    for sel in ("#sudo_login_password", "input[name='password']"):
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                loc.fill(password)
                page.locator("button:has-text('Confirm'), input[type='submit']").first.click(timeout=8_000)
                _sleep_with_cancel(4)
                log("[*] PAT: sudo password confirmed")
                # make sure we actually landed on the token form
                if "tokens/new" not in (page.url or ""):
                    page.goto("https://github.com/settings/tokens/new",
                              wait_until="domcontentloaded", timeout=60_000)
                    _sleep_with_cancel(3)
                break
        except Exception:
            pass
    note = random.choice(["dev-token", "automation", "ci-token", "workflow-token"]) + "-" + "".join(
        random.choices("0123456789", k=4))
    for sel in ("#oauth_access_description", "textarea#oauth_access_description",
                "input[name='oauth_access[description]']",
                "textarea[name='oauth_access[description]']",
                "#token_description", "input[name='token[description]']"):
        try:
            loc = page.locator(sel).first
            if loc.count():
                loc.fill(note, timeout=6_000)
                log(f"[*] PAT note filled ({sel})")
                break
        except Exception:
            pass
    for scope in ("repo", "workflow"):
        try:
            cb = page.locator(f"input[name='oauth_access[scopes][]'][value='{scope}']").first
            if cb.count() and not cb.is_checked():
                cb.check(timeout=6_000)
                log(f"[*] PAT scope {scope} checked")
        except Exception:
            pass
    clicked = False
    for sel in ("button:has-text('Generate token')", "input[value='Generate token']",
                "button[name='commit']", "input[name='commit']"):
        try:
            btn = page.locator(sel).first
            if btn.count():
                try:
                    btn.scroll_into_view_if_needed(timeout=4_000)
                except Exception:
                    pass
                try:
                    btn.click(timeout=8_000)
                except Exception:
                    btn.click(timeout=8_000, force=True)
                clicked = True
                log(f"[*] PAT: Generate token clicked ({sel})")
                break
        except Exception:
            pass
    if not clicked:
        try:
            clicked = bool(page.evaluate(
                "() => { const b=[...document.querySelectorAll('button,input[type=submit],summary')]"
                ".find(e=>/generate/i.test(e.innerText||e.value||'')); "
                "if(b){b.scrollIntoView();b.click();return true;} return false; }"))
            log(f"[*] PAT: Generate via JS click={clicked}")
        except Exception:
            pass
    _sleep_with_cancel(5)
    m = _re.search(r"ghp_[A-Za-z0-9]{36}", _page_text(page))
    if not m:
        # token often lives in HTML attributes (<code>, clipboard-value) not innerText
        try:
            m = _re.search(r"ghp_[A-Za-z0-9]{36}", page.content())
        except Exception:
            m = None
    if not m:
        # wait a bit more and retry (token page can render late)
        _sleep_with_cancel(5)
        try:
            m = _re.search(r"ghp_[A-Za-z0-9]{36}", _page_text(page) + page.content())
        except Exception:
            m = None
    if m:
        log("[*] PAT created: ghp_...%s" % m.group(0)[-4:])
        return m.group(0)
    log("[!] PAT token not found on page")
    try:
        dbg = ROOT / "accounts" / f"pat_debug_{int(time.time())}.html"
        dbg.write_text(page.content(), encoding="utf-8", errors="ignore")
        log(f"[i] PAT debug dump saved: {dbg.name} (url={page.url})")
    except Exception:
        pass
    return ""

def _complete_profile(page, username: str, cfg: Config, log) -> None:
    """Set recorded status and public profile fields after 2FA is secured."""
    if not (cfg.set_profile_status or cfg.complete_profile):
        return
    profile = None
    if cfg.complete_profile:
        custom = {
            "name": cfg.profile_name.strip(),
            "bio": cfg.profile_bio.strip(),
            "location": cfg.profile_location.strip(),
        }
        # Avoid external APIs entirely when every profile field is configured.
        profile = _fetch_public_profile() if not all(custom.values()) else {}
        profile = {key: custom[key] or profile[key] for key in custom}
    page.goto(f"https://github.com/{username}", wait_until="domcontentloaded", timeout=60_000)
    # profile page renders via react-partial lazily — scroll to wake the
    # right-column widgets (Set status / Edit profile) before clicking
    try:
        page.evaluate("window.scrollBy(0, 300)")
        time.sleep(1.0)
        page.wait_for_load_state("networkidle", timeout=8_000)
    except Exception:
        pass

    if cfg.set_profile_status:
        status = cfg.profile_status.strip() or "On vacation"
        # Recording: profile -> react-partial-anchor button "Set status" ->
        # #user-status-status-input -> portal "Set status" submit button.
        # Do not use the preset chip: it is not present on a fresh profile.
        launcher = page.locator("react-partial-anchor button, button").filter(
            has_text="Set status"
        ).first
        launcher_opened = False
        for _st_try in range(3):
            try:
                launcher.click(timeout=6_000)
                launcher_opened = True
                break
            except Exception:
                launcher_opened = _visible_dom_click(
                    page,
                    "b => /status/i.test(b.getAttribute('aria-label') || '') || "
                    "(b.textContent || '').trim() === 'Set status'",
                )
                if launcher_opened:
                    log("[*] profile status launcher clicked via DOM")
                    break
                try:
                    page.evaluate("window.scrollBy(0, 150)")
                except Exception:
                    pass
                time.sleep(1.5)
        if not launcher_opened:
            log("[i] profile status launcher not found; status skipped")
        if launcher_opened:
            status_input = page.locator("#user-status-status-input").first
            try:
                status_input.wait_for(state="visible", timeout=8_000)
            except Exception:
                raise SignupError("profile status popup did not open")
            status_input.fill(status, timeout=8_000)
            if status_input.input_value(timeout=3_000) != status:
                raise SignupError("profile status input did not retain the configured value")

            submit = page.locator("#__primerPortalRoot__ button").filter(
                has_text="Set status"
            ).last
            try:
                submit.click(timeout=8_000)
            except Exception:
                if not _visible_dom_click(
                    page,
                    "b => b.closest('#__primerPortalRoot') && "
                    "(b.textContent || '').trim() === 'Set status'",
                ):
                    raise SignupError("cannot submit profile status")
                log(f"[*] profile status submitted via DOM: {status}")

            # A successful submit closes the status popup. It is the reliable
            # confirmation independent of profile-page text rendering timing.
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    if not status_input.is_visible():
                        log(f"[*] profile status saved: {status}")
                        break
                except Exception:
                    log(f"[*] profile status saved: {status}")
                    break
                time.sleep(0.4)
            else:
                raise SignupError(f"profile status did not save: {status}")

    if not profile:
        return
    edit_opened = False
    for _ep_try in range(3):
        edit_button = page.locator(
            "button[name='button'], summary, [data-testid='edit-profile-button'], "
            "button[data-testid='profile-edit-button']"
        ).filter(has_text="Edit profile").first
        try:
            edit_button.click(timeout=8_000)
            edit_opened = True
            break
        except Exception as exc:
            log(f"[i] Edit profile native click intercepted ({exc}); trying DOM click")
            if _visible_dom_click(
                page,
                "b => (b.textContent || '').trim() === 'Edit profile' || "
                "b.classList.contains('js-profile-editable-edit-button') || "
                "(b.getAttribute('data-testid') || '').includes('edit-profile')",
            ):
                edit_opened = True
                log("[*] Edit profile clicked via DOM (overlay bypassed)")
                break
            # react-partial may still be hydrating — scroll and retry
            try:
                page.evaluate("window.scrollBy(0, 200)")
            except Exception:
                pass
            time.sleep(2.0)
    if not edit_opened:
        raise SignupError("cannot open Edit profile (button not found for DOM click)")

    name_input = page.locator("#user_profile_name").first
    bio_input = page.locator("#user_profile_bio").first
    location_input = page.locator("input[name='user[profile_location]']").first
    for field in (name_input, bio_input, location_input):
        field.wait_for(state="visible", timeout=15_000)
    name_input.fill(profile["name"])
    bio_input.fill(profile["bio"])
    location_input.fill(profile["location"])

    try:
        page.locator(f"form[action='/users/{username}'] button").filter(
            has_text="Save"
        ).first.click(timeout=10_000)
    except Exception:
        if not _visible_dom_click(page, "b => (b.textContent || '').trim() === 'Save'"):
            raise SignupError("cannot submit Edit profile")
    try:
        page.wait_for_timeout(1_500)
        # After a successful save, either profile text is rendered or the form
        # retains the saved input value during its partial refresh.
        if profile["name"] not in _page_text(page) and name_input.input_value() != profile["name"]:
            raise SignupError("profile save was not confirmed")
    except SignupError:
        raise
    except Exception:
        pass
    log(f"[*] profile completed: {profile['name']} | {profile['location']}")


def _pass_sudo_gate(page, password: str, log, username: str = "", email: str = "") -> bool:
    """GitHub redirects sensitive settings pages to /login (sudo gate).

    The gate can be either a password-only sudo confirm OR a full login form
    (login_field + password). Fill whatever is present and submit; return True
    when we left /login.
    """
    if "/login" not in (page.url or ""):
        return False
    log("[*] sudo gate detected — confirming credentials")
    filled_pw = False
    # full login form: username first
    for usel in ("#login_field", "input[name='login']"):
        try:
            uloc = page.locator(usel).first
            if uloc.count() and uloc.is_visible():
                ident = email or username or ""
                if not ident:
                    # fall back to whatever the form already has
                    ident = (uloc.input_value() or "").strip()
                if ident:
                    uloc.fill(ident)
                    log(f"[*] sudo gate: login field filled ({'email' if email else 'username'})")
                break
        except Exception:
            continue
    for sel in ("#sudo_login_password", "#password", "input[name='password']",
                "input[type='password']"):
        try:
            loc = page.locator(sel).first
            if loc.count() and loc.is_visible():
                loc.fill(password)
                filled_pw = True
                log(f"[*] sudo gate: password field filled ({sel})")
                break
        except Exception:
            continue
    if not filled_pw:
        log("[!] sudo gate: no visible password field")
        return False
    # IMPORTANT: submit via the password form's own commit input. Generic
    # button clicks can land on the passkey/WebAuthn widget, which makes
    # GitHub answer "Authentication failed / Retry passkey".
    def _click_commit() -> None:
        for bsel in ("input[name='commit'][type='submit']",
                     "form input[name='commit']",
                     "button[type='submit']", "input[type='submit']",
                     "button:has-text('Sign in')", "button:has-text('Confirm')"):
            try:
                b = page.locator(bsel).first
                if b.count() and b.is_visible():
                    b.click(timeout=8_000)
                    return
            except Exception:
                continue
        # last resort: DOM click on the visible submit inside the auth form
        try:
            page.evaluate(
                """() => {
                    const f = document.querySelector('form#login-form, form[action*="session"], form');
                    const b = f && (f.querySelector("input[name='commit']") || f.querySelector("button[type='submit']"));
                    if (b) b.click();
                }"""
            )
        except Exception:
            pass

    _click_commit()
    # wait for the redirect back to the settings page
    deadline = time.time() + 20
    while time.time() < deadline:
        if "/login" not in (page.url or ""):
            break
        _sleep_with_cancel(1.5)
    passed = "/login" not in (page.url or "")
    # "Authentication failed" with passkey prompt => wrong widget got the click
    # or GitHub wants the username instead of the email. One retry with username.
    if not passed and email and username:
        try:
            txt = (_page_text(page) or "").lower()
        except Exception:
            txt = ""
        if "authentication failed" in txt or "passkey" in txt or "/login" in (page.url or ""):
            log("[*] sudo gate retry with username")
            try:
                uloc = page.locator("#login_field, input[name='login']").first
                if uloc.count():
                    uloc.fill(username)
                ploc = page.locator("#password, input[name='password']").first
                if ploc.count():
                    ploc.fill(password)
                _click_commit()
                deadline = time.time() + 20
                while time.time() < deadline:
                    if "/login" not in (page.url or ""):
                        break
                    _sleep_with_cancel(1.5)
                passed = "/login" not in (page.url or "")
                log(f"[*] sudo gate retry {'passed' if passed else 'NOT passed'} (url={page.url})")
            except Exception as exc:
                log(f"[i] sudo gate retry failed: {exc}")
    log(f"[*] sudo gate {'passed' if passed else 'NOT passed'} (url={page.url})")
    if not passed:
        # surface the reason: GitHub flashes an error banner (wrong password / 2FA)
        try:
            txt = _page_text(page)[:500].replace(chr(10), " | ")
            log(f"[i] sudo gate page text: {txt}")
        except Exception:
            pass
    return passed


def _enable_2fa(page, password: str, log, username: str = "", email: str = "") -> tuple[str, str]:
    """Stage 5 (user recording): enable TOTP 2FA and return the secret.

    Flow (from the recording):
      Settings → Password and authentication → 'Enable two-factor authentication'
      → 'Authenticator apps and browser extension' → click 'setup key' to reveal
      the secret in a textfield → READ the secret → compute TOTP via pyotp →
      fill input[name='otp'] → Continue → save recovery codes → 'I have saved my
      recovery codes' → Done.
    """
    import pyotp

    page.goto("https://github.com/settings/security", wait_until="domcontentloaded", timeout=60_000)
    if "/login" in (page.url or ""):
        _pass_sudo_gate(page, password, log, username, email)
        # after the gate we can land on /session or /dashboard — go back
        if "settings/security" not in (page.url or ""):
            page.goto("https://github.com/settings/security",
                      wait_until="domcontentloaded", timeout=60_000)
            if "/login" in (page.url or ""):
                log("[!] 2FA: stuck in login redirect loop after sudo gate — skipping")
                raise SignupError(f"security settings page failed; url={page.url}")
    try:
        page.wait_for_selector("#settings-frame", state="visible", timeout=30_000)
    except Exception:
        # one retry after a possible late sudo redirect
        if "/login" in (page.url or ""):
            _pass_sudo_gate(page, password, log, username, email)
            page.goto("https://github.com/settings/security", wait_until="domcontentloaded", timeout=60_000)
        try:
            page.wait_for_selector("#settings-frame", state="visible", timeout=20_000)
        except Exception:
            raise SignupError(f"security settings page failed; url={page.url}")

    # 'Enable two-factor authentication' is an <a href> link (NOT a button):
    # /settings/two_factor_authentication/setup/intro — navigate straight to it.
    # NOTE: GitHub REGENERATES the TOTP secret on every load of this page, so
    # read the secret only from the page we actually fill the code into.
    try:
        with page.expect_navigation(wait_until="domcontentloaded", timeout=30_000):
            page.goto(
                "https://github.com/settings/two_factor_authentication/setup/intro",
                wait_until="domcontentloaded", timeout=60_000,
            )
    except Exception:
        pass  # already on the page; proceed

    # wait for the setup wizard (QR code page shows the secret in a hidden dialog)
    try:
        page.wait_for_selector(
            "div[data-target='two-factor-setup-verification.mashedSecret']",
            state="attached",  # present in DOM even while the dialog is closed
            timeout=45_000,
        )
    except Exception:
        raise SignupError(f"2FA setup wizard did not load; url={page.url}")

    # reveal the setup key via the 'setup key' button (mirrors the recording),
    # then read the secret from the dialog's data-target div.
    try:
        page.locator("#dialog-show-two-factor-setup-verification-mashed-secret").first.click(
            timeout=10_000
        )
        time.sleep(0.8)
    except Exception:
        pass  # dialog content is in the DOM even when closed — read anyway

    secret = ""
    for _sec_try in range(4):
        try:
            secret = (
                page.locator(
                    "div[data-target='two-factor-setup-verification.mashedSecret']"
                ).first.inner_text(timeout=5000)
                or ""
            ).strip()
        except Exception:
            secret = ""
        if secret and len(secret) >= 16:
            break
        # dialog fetch may not have resolved yet — re-open the setup-key dialog
        try:
            page.locator("#dialog-show-two-factor-setup-verification-mashed-secret").first.click(
                timeout=5_000
            )
        except Exception:
            pass
        time.sleep(1.5)
    if not secret:
        # fallback: scan page HTML for a base32-looking secret (16-32 chars)
        import re

        body = ""
        try:
            body = page.content()
        except Exception:
            body = ""
        # GitHub embeds otpauth://totp/GitHub:USER?secret=BASE32&issuer=GitHub
        m = re.search(r"otpauth%3A%2F%2Ftotp[^\"']*secret%3D([A-Z2-7]{16,32})", body or "") \
            or re.search(r"otpauth://totp[^\"']*secret=([A-Z2-7]{16,32})", body or "") \
            or re.search(r"setup[-_ ]?key[^A-Z2-7]{0,200}([A-Z2-7]{16,32})", body or "", re.I) \
            or re.search(r"secret[\s\"']{1,6}[:=][\s\"']{1,6}([A-Z2-7]{16,32})", body or "")
        if m:
            secret = m.group(1)
        else:
            m = re.search(r"\b([A-Z2-7]{16,32})\b", body or "")
            if m:
                secret = m.group(1)
    if not secret or len(secret) < 16:
        raise SignupError(f"TOTP secret not found (got {secret!r})")
    log(f"[*] TOTP secret captured: {secret}")

    # close the setup-key dialog if it opened
    try:
        page.locator("[aria-label='Close']").first.click(timeout=3000)
    except Exception:
        pass

    # compute the current TOTP code and submit it
    totp = pyotp.TOTP(secret)
    code = totp.now()
    log(f"[*] TOTP code generated: {code}")
    # the ENABLED otp input is the one with aria-label; input[name='otp'] is a
    # hidden/disabled twin (from the recording) — fill the enabled one.
    # pick the VISIBLE otp input — the wizard keeps hidden twins in the DOM,
    # and :first can resolve to a non-visible one (fill hangs 'element is not visible')
    def _find_visible_otp(page):
        for sel in ("input[aria-label='Verify the code from the app']:not([disabled])",
                    "input[name='otp']:not([disabled])",
                    "input[pattern='[0-9]{6}']:not([disabled])"):
            try:
                loc = page.locator(sel)
                for i in range(min(loc.count(), 5)):
                    el = loc.nth(i)
                    try:
                        if el.is_visible() and el.is_editable():
                            return el
                    except Exception:
                        continue
            except Exception:
                continue
        return None

    otp_input = _find_visible_otp(page)
    if otp_input is not None:
        otp_input.fill(code, timeout=10_000)
    else:
        # last resort: JS fill + dispatch input event on the offsetParent-visible one
        page.evaluate(
            """(code) => {
                const els = [...document.querySelectorAll("input[name='otp'],input[aria-label='Verify the code from the app']")];
                const vis = els.find(e => e.offsetParent !== null && !e.disabled);
                if (vis) {
                    vis.value = code;
                    vis.dispatchEvent(new Event('input', {bubbles: true}));
                    vis.dispatchEvent(new Event('change', {bubbles: true}));
                }
            }""", code)
        log("[*] otp filled via JS dispatch")

    # --- helper: click the VISIBLE enabled wizard button by its label ---
    # The wizard keeps all steps' buttons in the DOM; Playwright's is_visible()
    # is unreliable there, so use the browser's own visibility semantics
    # (offsetParent !== null) to find the ACTIVE step's button.
    def _click_active_wizard_button(page, label: str) -> bool:
        try:
            clicked = page.evaluate(
                """(label) => {
                    const btns = [...document.querySelectorAll(
                        "button[data-target='single-page-wizard-step.nextButton'], " +
                        "button[data-action='click:two-factor-setup-recovery-codes#onDownloadClick'], " +
                        "button[data-action='click:single-page-wizard-step#onNext']"
                    )];
                    for (const b of btns) {
                        if (b.offsetParent !== null && !b.disabled &&
                            (b.textContent || '').trim().toLowerCase() === label.toLowerCase()) {
                            b.click();
                            return true;
                        }
                    }
                    return false;
                }""",
                label,
            )
            return bool(clicked)
        except Exception:
            return False

    if not _click_active_wizard_button(page, "Continue"):
        # fallback: any visible enabled next button (its label may be icon-only)
        try:
            page.evaluate(
                """() => {
                    const btns = [...document.querySelectorAll(
                        "button[data-target='single-page-wizard-step.nextButton']"
                    )];
                    for (const b of btns) {
                        if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                    }
                    return false;
                }"""
            )
        except Exception:
            pass
    log("[*] TOTP code submitted → Continue")
    time.sleep(3)

    # ---- recovery codes step ----
    recovery = ""
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            # prefer the dedicated element, else scan the page text
            codes: list[str] = []
            try:
                rc_el = page.locator("two-factor-setup-recovery-codes, [data-target='two-factor-setup-recovery-codes']")
                if rc_el.count():
                    txt = rc_el.first.inner_text(timeout=3000) or ""
                else:
                    txt = _page_text(page)
            except Exception:
                txt = _page_text(page)
            import re as _re

            codes = list(dict.fromkeys(_re.findall(r"\b[a-z0-9]{5,6}-[a-z0-9]{5,6}\b", txt, _re.I)))
            if codes:
                recovery = "\n".join(codes[:16])
                break
            time.sleep(1)
        if recovery:
            log(f"[*] recovery codes captured ({len(recovery.splitlines())} codes)")
    except Exception:
        pass

    # download recovery codes (as recorded), then confirm & finish.
    # SKIP the download when the codes were already scraped from the DOM —
    # Firefox download handling intermittently hangs the whole wizard.
    if not recovery:
        try:
            with page.expect_download(timeout=10_000) as dl_info:
                page.evaluate(
                    """() => {
                        const b = [...document.querySelectorAll('button')].find(
                            b => b.offsetParent !== null && !b.disabled &&
                                 /download/i.test((b.textContent || '').trim())
                        );
                        if (b) b.click();
                    }"""
                )
            download = dl_info.value
            log(f"[*] recovery codes downloaded: {download.suggested_filename}")
            try:
                path = str(download.path())
                if path and os.path.exists(path):
                    with open(path, encoding="utf-8") as f:
                        dl_text = f.read()
                    if dl_text and not recovery:
                        import re as _re

                        codes = list(dict.fromkeys(_re.findall(r"\b[a-z0-9]{5,6}-[a-z0-9]{5,6}\b", dl_text, _re.I)))
                        if codes:
                            recovery = "\n".join(codes[:16])
                            log(f"[*] recovery codes from download ({len(codes)} codes)")
            except Exception:
                pass
        except Exception as exc:
            log(f"[i] recovery codes download skipped: {exc}")
    else:
        log("[*] recovery codes already captured from DOM — download skipped")

    if _click_active_wizard_button(page, "I have saved my recovery codes"):
        log("[*] recovery codes confirmed")
    else:
        # fallback: click by data-action nextButton (visible one)
        page.evaluate(
            """() => {
                const btns = [...document.querySelectorAll(
                    "button[data-target='single-page-wizard-step.nextButton']"
                )];
                for (const b of btns) {
                    if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                }
                return false;
            }"""
        )
        log("[*] recovery codes confirmed (fallback)")
    time.sleep(2)
    if _click_active_wizard_button(page, "Done"):
        log("[*] 2FA wizard finished")
    else:
        page.evaluate(
            """() => {
                const btns = [...document.querySelectorAll(
                    "button[data-target='single-page-wizard-step.nextButton']"
                )];
                for (const b of btns) {
                    if (b.offsetParent !== null && !b.disabled) { b.click(); return true; }
                }
                return false;
            }"""
        )
    time.sleep(2)

    # persist recovery codes next to the accounts file for account recovery
    if recovery:
        try:
            rc_path = ROOT / "github_recovery_codes.txt"
            with rc_path.open("a", encoding="utf-8") as f:
                f.write(f"=== {page.url} @ {datetime.now().isoformat(timespec='seconds')} ===\n")
                f.write(recovery + "\n\n")
            log(f"[*] recovery codes saved to {rc_path.name}")
        except Exception as exc:
            log(f"[i] recovery codes write failed: {exc}")
    return secret, recovery


def _visible(page, selectors) -> bool:
    sel = ", ".join(selectors)
    try:
        return page.locator(sel).first.is_visible()
    except Exception:
        return False


def _advance_step(page, next_selectors, log, stop, timeout: int = 25) -> None:
    """Click the signup form's Continue button (NEVER the OAuth buttons) and
    wait until the next step's inputs are visible.

    GitHub switched /signup to a multi-step wizard (email -> Continue ->
    password -> Continue -> username + country -> Create account). The main
    form is the ONLY one with action*=signup; OAuth forms live separately.
    """
    deadline = time.time() + timeout
    clicked = False
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        if _visible(page, next_selectors):
            return
        if not clicked:
            btn = page.locator("form[action*='signup'] button[type='submit']").first
            try:
                if btn.count() and btn.is_visible() and btn.is_enabled():
                    _try_click_datadome(page, log)
                    try:
                        btn.click(timeout=8_000)
                    except Exception:
                        btn.evaluate("el => el.click()")
                    log("[*] step advanced: Continue clicked")
                    clicked = True
            except Exception:
                pass
        _sleep_with_cancel(1, stop)
    raise SignupError(
        f"next step ({next_selectors}) did not appear after Continue; "
        f"url={page.url} body={_page_text(page)[:200]!r}"
    )


def _fill_signup_form(page, cfg, email, password, log, stop) -> str:
    """Fill the signup wizard: email -> Continue -> password -> Continue ->
    username (+ country) -> Create account. Also tolerates the legacy
    single-page layout (all three fields visible at once).

    Returns the accepted username. Raises SignupError with a clear reason when
    the form cannot be completed (validation error, overlay, rate limit).
    """
    _human_fill(page, _EMAIL_INPUTS, email, stop=stop)
    _sleep_with_cancel(1.5, stop)
    _raise_if_rate_limited(page)

    if not _visible(page, _PASSWORD_INPUTS):
        _advance_step(page, _PASSWORD_INPUTS, log, stop)
        _sleep_with_cancel(1.0, stop)

    _human_fill(page, _PASSWORD_INPUTS, password, stop=stop)
    _sleep_with_cancel(1.5, stop)
    _raise_if_rate_limited(page)

    if not _visible(page, _USERNAME_INPUTS):
        _advance_step(page, _USERNAME_INPUTS, log, stop)
        _sleep_with_cancel(1.0, stop)

    # country dropdown on the final step (custom listbox, optional — GitHub
    # auto-detects by IP and Create account may still be gated on it)
    try:
        combo = page.locator("select[name*='country'], #country, [data-testid='country-select']").first
        if combo.count() and combo.is_visible():
            pass  # native select: leave as detected
    except Exception:
        pass

    # 3s pause after username -> CLICK Create account -> on username error
    # append one digit and retry (name -> name2 -> name3 ...)
    return _fill_and_create_account(
        page, username_from_email(email), cfg.max_username_tries, log, stop=stop
    )


def _post_form_flow(
    page, context, cfg: Config, email: str, password: str, username: str,
    mail, order_id: str, log, stop, pending=None,
) -> tuple[str, str, str]:
    """Everything AFTER the signup form was accepted: email verification
    (launch code), auto-login, first repository (stage 4), TOTP 2FA (stage 5).
    Returns (username, totp_secret, recovery_codes)."""
    if pending is None:
        pending = {}
    # after submit GitHub either shows the email verification (launch code)
    # page, or (high-trust sessions) logs straight in.
    # PRIME: Arkose FunCaptcha gate — solve via multi-LLM voting ($0 default
    # pool: qwen3-vl-flash/qwen-vl-max/qwen-vl-plus on the local dashscope proxy)
    if getattr(cfg, "solve_captcha", True):
        for _aw in range(10):  # up to ~30s for the challenge to render
            if arkose_present(page):
                break
            if _verify_input_visible(page) or _logged_in(context):
                break
            _sleep_with_cancel(3, stop)
        if arkose_present(page):
            log("[*] Arkose FunCaptcha detected — multi-LLM voting solver")
            try:
                res = solve_arkose_voting(
                    page,
                    shot_dir=str(ROOT / "screenshots_captcha"),
                    max_rounds=int(getattr(cfg, "captcha_max_rounds", 12) or 12),
                    log=log,
                )
            except Exception as exc:
                res = False
                log(f"[!] captcha solver crashed: {exc}")
            if res == "SKIP_VARIANT":
                raise SignupError("hard captcha variant (character) — reload for a new challenge")
            if not res:
                log("[!] captcha NOT solved — flow will likely fail at verification")
            else:
                log("[*] captcha solved — continuing to email verification")
    state = _wait_post_submit(page, context, timeout=120, log=log, stop=stop)
    used_codes: set[str] = set()
    if state == "verify":
        log(f"[*] verification page: {page.url}")
        code = mail.wait_for_code(
            order_id,
            timeout=cfg.otp_timeout_sec,
            log=log,
            cancel_cb=stop,
            email=email,
            exclude_codes=used_codes,
        )
        log(f"[*] verification code: {code}")
        used_codes.add(code)
        _fill_launch_code(page, code, log)
        # mail.cx has no order confirmation — code already extracted
        log(f"[*] verification code extracted and submitted")
        # after OTP: must reach a logged-in state
        state2 = _wait_post_submit(page, context, timeout=90, log=log, stop=stop)
        if state2 == "verify":
            raise SignupError("verification code rejected (still on verify page)")

    def _finalize(post_login: bool) -> tuple[str, str, str, str]:
        """Run the optional post-login stages (repo, 2FA, profile).

        ``post_login`` is False when the browser never confirmed the
        logged_in cookie — in that case we still keep the (already verified)
        account credentials but skip stages that require an active session.
        """
        # CHECKPOINT: the account is verified and logged in from here on.
        # If the browser/driver crashes in a later stage, register_one can
        # still salvage the credentials from `pending`.
        pending["active"] = post_login
        pending["username"] = username
        totp_secret = ""
        recovery = ""
        pat = ""
        if post_login:
            # ---- stage 4: create first repository ----
            if cfg.create_repo:
                try:
                    _create_repository(page, username, cfg.repo_name, log)
                except Exception as exc:
                    log(f"[i] create repo stage skipped: {exc}")
            # ---- stage 5: enable TOTP 2FA ----
            if cfg.enable_2fa:
                try:
                    totp_secret, recovery = _enable_2fa(page, password, log, username, email)
                except Exception as exc:
                    log(f"[i] 2FA stage failed (account still saved): {exc}")
            # ---- stage 6: classic PAT (repo+workflow scopes) ----
            if getattr(cfg, "create_pat", False):
                try:
                    pat = _create_pat(page, password, log, username, email)
                except Exception as exc:
                    pat = ""
                    log(f"[i] PAT stage failed (account still saved): {exc}")
            else:
                pat = ""
            _save_recovery_per_account(email, recovery, log)
            try:
                _complete_profile(page, username, cfg, log)
            except Exception as exc:
                log(f"[i] profile stage skipped (account still saved): {exc}")
        try:
            _save_trust_cookie(context, log)  # persist DataDome trust for the next fresh run
        except Exception as exc:
            log(f"[i] trust-cookie save skipped: {exc}")
        return username, totp_secret, recovery, pat

    # state 'done' required — no more accepting bare redirects
    deadline = time.time() + 60
    while time.time() < deadline:
        _raise_if_cancelled(stop)
        _raise_if_rate_limited(page)
        if _logged_in(context):
            log("[*] logged_in cookie confirmed — account is active")
            return _finalize(post_login=True)
        # GitHub sends fresh signups to /login: sign in with the new creds
        if "/login" in (page.url or ""):
            if _try_login(
                page, email, password, context, log,
                mail=mail, order_id=order_id, email=email,
                otp_timeout=cfg.otp_timeout_sec,
                used_codes=used_codes, stop=stop,
            ):
                log("[*] logged_in cookie confirmed after auto-login")
                return _finalize(post_login=True)
            # The account exists on GitHub and its email is verified —
            # matching the README's post-signup-failure policy, keep the
            # credentials instead of discarding them. Stages 4/5 need an
            # active session so they are skipped.
            if "suspended" in (page.url or ""):
                pending["suspended"] = True
                log("[!] account went to /suspended — marked SUSPENDED in output")
            log("[!] auto-login not completed — saving the verified account "
                "without repo/2FA/profile stages")
            return _finalize(post_login=False)
        if _post_submit_state(page, context) == "pending":
            _sleep_with_cancel(2, stop)
            continue
        if _wait_post_submit(page, context, timeout=20, log=log, stop=stop) == "done":
            continue  # loop will hit the _logged_in check above
        _sleep_with_cancel(2, stop)
    # deadline exhausted: the account is created and email-verified, but the
    # session cookie never appeared and no /login redirect brought us there.
    # Preserve the account rather than discarding it.
    log(f"[!] session cookie not confirmed within 60s — saving the verified "
        f"account (url={page.url})")
    return _finalize(post_login=False)


def _run_signup(
    cfg: Config,
    password: str,
    mail: MailCxClient,
    provider: str,
    pending: dict,
    log,
    stop,
) -> tuple[str, str]:
    """Run the whole sign-up; returns (username, totp).

    GitHub's signup is now a SINGLE page: Email* / Password* / Username* in one
    form (action=/signup?social=false), submit = "Create account" button.
    OAuth (Google/Apple) buttons live in separate <form> tags — never click them.

    The Octocaptcha token sometimes never settles on a given page load — the
    Create account button stays disabled forever. Two-tier retry strategy:

    Tier 1 (fast, cheap): within the SAME browser session, do `page.reload()`
    (Cmd+R equivalent) and re-fill the form with the SAME data (email +
    password + username). Up to `page_reloads` in-session retries.

    Tier 2 (slow, expensive): if Tier 1 exhausts, close the browser and open
    a completely fresh session (new fingerprint / cookies) and try again. Up
    to `session_reloads` full-session restarts.
    """
    page_reloads = 3      # in-session refresh (Cmd+R) attempts before switching session
    session_reloads = 2   # full browser restarts (new fingerprint) after page reloads fail
    last_exc: Exception | None = None
    for session_attempt in range(1, session_reloads + 2):
        _raise_if_cancelled(stop)
        if session_attempt > 1:
            log(f"[*] SESSION switch {session_attempt - 1}/{session_reloads} "
                f"(fresh browser + new fingerprint)")
        with Camoufox(**_browser_ctx_options(cfg, log=log if session_attempt == 1 else None)) as browser:
            # works for BOTH modes: persistent context (BrowserContext) and fresh
            # launch (Browser -> new context/page per account)
            context, page = _context_and_page(browser)
            if getattr(cfg, "fresh_profile", False):
                # fresh mode: inject ONLY the DataDome trust cookie (no GitHub state)
                _restore_trust_cookie(context, log)
            else:
                # persistent mode: wipe login state, keep DataDome trust cookies
                _clean_github_session_cookies(context, log)
            page.set_default_timeout(20_000)
            _open_signup(page, log, stop=stop, attempts=2 if session_attempt > 1 else 3, headless=cfg.headless)
            _reject_blocked(page)

            fresh_mail_needed = "email" not in pending
            if not fresh_mail_needed and session_attempt > 1 and provider in ("mailcx", "gmail", "outlook", "temptf"):
                # Session switch means the old username is likely burned; with
                # free mail.cx grab a NEW mailbox so the derived base username
                # changes too (prevents endless 'Username X is not available').
                fresh_mail_needed = True
                log("[*] session switch: ordering a fresh mailbox (free mail.cx)")
            if fresh_mail_needed:
                # Order the mailbox ONLY now that the form is ready — a Litensi
                # order costs balance and expires in minutes, so never open it
                # while DataDome may still burn time.
                # Provider errors (empty balance, bad key) propagate as-is so
                # the caller aborts the job instead of failing every account.
                pending["email"], pending["order_id"] = mail.create_mailbox()
                log(f"[*] mailbox: {pending['email']} ({provider})")
            email = pending["email"]

            # --- Tier 1: in-session page reloads with same data ---
            page_last_exc: Exception | None = None
            username: str | None = None
            for page_attempt in range(1, page_reloads + 1):
                _raise_if_cancelled(stop)
                if page_attempt > 1:
                    log(f"[*] PAGE reload {page_attempt - 1}/{page_reloads - 1} "
                        f"(Reload with same data)")
                    try:
                        page.reload(wait_until="domcontentloaded", timeout=60_000)
                    except Exception as exc:
                        log(f"[!] page.reload() failed ({exc}); falling back to goto()")
                        try:
                            page.goto(
                                "https://github.com/signup",
                                wait_until="domcontentloaded",
                                timeout=60_000,
                            )
                        except Exception as exc2:
                            page_last_exc = SignupError(f"page reload/goto failed: {exc2}")
                            break
                    # wait for the form to be ready again on the reloaded page
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        _raise_if_cancelled(stop)
                        _raise_if_rate_limited(page)
                        if _form_ready(page):
                            break
                        _sleep_with_cancel(1, stop)
                    else:
                        page_last_exc = SignupError("form not ready after page reload")
                        continue
                    _reject_blocked(page)

                try:
                    username = _fill_signup_form(page, cfg, email, password, log, stop)
                    log(f"[*] form submitted: email + password + username={username}")
                    break  # success — leave Tier 1 loop
                except SignupError as exc:
                    msg = str(exc)
                    reloadable = (
                        "stayed disabled" in msg
                        or "click" in msg.lower()
                        or "overlay" in msg.lower()
                        or "form" in msg.lower()
                    )
                    if reloadable and page_attempt < page_reloads:
                        page_last_exc = exc
                        log(f"[!] page attempt {page_attempt}/{page_reloads} failed "
                            f"({msg[:120]}); will refresh page and retry with same data")
                        continue
                    # either not-reloadable, or Tier 1 exhausted -> propagate to Tier 2 handler
                    page_last_exc = exc
                    break

            if username is None:
                # Tier 1 failed — decide whether to switch session (Tier 2)
                exc = page_last_exc or SignupError("form submit failed with unknown reason")
                msg = str(exc)
                reloadable = (
                    "stayed disabled" in msg
                    or "click" in msg.lower()
                    or "overlay" in msg.lower()
                    or "form" in msg.lower()
                )
                if reloadable and session_attempt <= session_reloads:
                    last_exc = exc
                    log(f"[!] {page_reloads} page-reloads exhausted; switching SESSION "
                        f"({msg[:120]})")
                    continue  # browser closes here; outer loop starts a fresh one
                raise exc

            # form accepted — continue with the rest of the flow in this same session
            return _post_form_flow(
                page, context, cfg, email, password, username,
                mail, pending["order_id"], log, stop, pending=pending,
            )
            # non-SignupError exceptions propagate immediately (with-block closes browser)
    raise SignupError(
        f"signup form never completed after {page_reloads} page-reloads x "
        f"{session_reloads + 1} sessions: {last_exc}"
    )


def register_one(
    cfg: Config, log: Callable[[str], None], cancel_cb: Optional[Callable[[], bool]] = None
) -> Optional[str]:
    """Register one account; returns its one-line account record or None."""
    stop = cancel_cb or (lambda: False)

    # --- create mail client based on provider (order itself is deferred
    # until the signup form is ready — see _run_signup) ---
    provider = getattr(cfg, "mail_provider", "mailcx") or "mailcx"
    if provider == "litensi":
        mail = LitensiClient(
            api_id=cfg.litensi_api_id,
            api_key=cfg.litensi_api_key,
            site=cfg.litensi_site,
            zone=cfg.litensi_zone,
        )
    elif provider in ("gmail", "outlook"):
        mail = ImapMailClient(
            provider=provider,
            user=cfg.imap_user,
            password=cfg.imap_password,
            host=cfg.imap_host,
            port=cfg.imap_port,
            alias_domain=cfg.imap_alias_domain,
        )
    elif provider == "temptf":
        mail = TempTfClient(
            providers=cfg.temptf_providers,
            dot=cfg.temptf_dot,
            plus=cfg.temptf_plus,
        )
    else:
        mail = MailCxClient(domain=cfg.mailcx_domain)
    pending: dict = {}

    succeeded = False
    try:
        password = generate_password()
        has_proxy = bool((cfg.proxy or "").strip() or (getattr(cfg, "proxy_file", "") or "").strip())
        hard_left = int(getattr(cfg, "proxy_hard_block_retries", 0) or 0) if has_proxy else 0
        rate_left = int(getattr(cfg, "proxy_rate_limit_retries", 0) or 0) if has_proxy else 0
        while True:
            _raise_if_cancelled(stop)
            try:
                username, totp_secret, recovery, pat = _run_signup(
                    cfg, password, mail, provider, pending, log, stop
                )
                break
            except SignupBlocked as exc:
                if hard_left <= 0:
                    raise
                hard_left -= 1
                log(f"[!] DataDome hard block ({exc}); disabling proxy + rotating, {hard_left} retries left")
                _disable_blocked_proxy(log)
                _rotate_sticky_proxy()
                _sleep_with_cancel(5, stop)
            except GitHubRateLimited as exc:
                if rate_left <= 0:
                    raise
                rate_left -= 1
                log(f"[!] GitHub secondary rate limit ({exc}); rotating sticky proxy/IP, "
                    f"{rate_left} retries left")
                _rotate_sticky_proxy()
                _sleep_with_cancel(8, stop)
        # Recovery codes are stored in accounts/recovery/<email-hash>.txt.
        # This fifth marker lets the account UI show the recovery-code action
        # without exposing the codes in the main account list.
        succeeded = True
        email = pending["email"]
        line = f"{email}----{password}----{username}----{totp_secret}----{int(bool(recovery))}----{pat}"
        if pending.get("suspended"):
            line += "----SUSPENDED"
        return line
    except KeyboardInterrupt:
        raise
    except RegistrationCancelled:
        raise
    except GitHubRateLimited:
        raise
    except MailboxCancelled:
        # Stop was pressed while waiting for the verification email — this is
        # a clean cancellation, not a provider failure.
        raise RegistrationCancelled("cancelled while waiting for mail")
    except MailboxTimeoutError as exc:
        # ONE mailbox never received the GitHub code in time. This is a
        # per-account transient failure — fail only this account and let the
        # batch continue. (Fatal provider errors such as a bad key or an empty
        # balance are LitensiError/MailCxError and still abort below.)
        log(f"[-] account failed: mailbox timeout ({exc}); continuing with the next account")
        return None
    except (MailCxError, LitensiError) as exc:
        # Provider failure (empty balance, bad key, no stock): surface the
        # error and stop — retrying the next account would fail identically.
        log(f"[!] mail provider error, aborting: {exc}")
        raise
    except Exception as exc:
        # SALVAGE: if the browser/driver crashed AFTER the account was verified
        # and logged in (checkpoint in _finalize), keep the credentials — the
        # account exists on GitHub and would otherwise be lost.
        if pending.get("active") and pending.get("email"):
            log(f"[!] post-login crash ({str(exc)[:80]}) — salvaging verified account")
            succeeded = True
            return (f"{pending['email']}----{password}----{pending.get('username','')}"
                    f"------0----")
        log(f"[-] account failed: {exc}")
        return None
    finally:
        order_id = pending.get("order_id")
        if provider == "litensi" and order_id is not None:
            # Confirm or cancel the Litensi order based on the actual outcome.
            # Before: this branch always canceled — that discarded successful
            # orders (docs say the caller MUST setstatus SUCCESS once the
            # code has been consumed) and produced misleading logs on both
            # sides.
            if succeeded:
                _confirm_order(mail, order_id, log)
            else:
                _cancel_order(mail, order_id, log)
        elif provider != "litensi":
            log(f"[*] mailbox cleanup: no action needed ({provider})")
        # else: form never became ready — no order was ever placed, nothing to settle


def run_job(
    cfg: Config,
    cancel_cb: Optional[Callable[[], bool]] = None,
    log: Optional[Callable[[str], None]] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> tuple[int, int, Path]:
    """Register `register_count` accounts; returns (ok, fail, output_file).

    `progress_cb(ok, fail)` (optional) is invoked after each account attempt so
    external observers (e.g. the web UI) can render live stats instead of only
    seeing the final totals when the job returns.
    """
    if log is None:
        log = lambda msg: print(f"[{_now()}] {msg}")  # noqa: E731
    stop = cancel_cb or (lambda: False)

    def _emit_progress(ok_count: int, fail_count: int) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb(ok_count, fail_count)
        except Exception as exc:
            # progress reporting must never break the job
            log(f"[i] progress_cb error ignored: {exc}")

    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    out = ACCOUNTS_DIR / f"github_accounts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    ok = fail = 0
    provider = (getattr(cfg, "mail_provider", "mailcx") or "mailcx").strip().lower()
    log(f"[*] github-regkit | engine=Camoufox (Firefox anti-detect) | mail_provider={provider} "
        f"| headless={cfg.headless} | target={cfg.register_count} | output={out.name}")
    _emit_progress(ok, fail)  # initial snapshot: 0/0
    try:
        for i in range(1, cfg.register_count + 1):
            if stop():
                break
            log(f"--- account {i}/{cfg.register_count} ---")
            line = None
            try:
                line = register_one(cfg, log, stop)
            except KeyboardInterrupt:
                raise
            except RegistrationCancelled:
                log("[!] stop requested — browser flow cancelled")
                break
            except GitHubRateLimited as exc:
                log(f"[!] rate-limit retries exhausted — stopping job: {exc}")
                break
            except (MailCxError, LitensiError) as exc:  # provider-level error: abort job
                log(f"[!] mail provider error, aborting: {exc}")
                break
            if line:
                with out.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
                ok += 1
                log(f"[+] {line.split('----')[0]} saved to {out.name}")
            else:
                fail += 1
            log(f"[*] stats: OK {ok} | FAIL {fail}")
            _emit_progress(ok, fail)  # live update after each account
            if i < cfg.register_count and not stop():
                _sleep_with_cancel(cfg.delay_sec, stop)
    except RegistrationCancelled:
        # A web Stop click may arrive during inter-account delay, not only
        # inside register_one. This is expected control flow, not a job error.
        log("[!] stop requested — job ended cleanly")
    finally:
        _stop_proxy_bridge()  # stop the local auth bridge if it was started
        log(f"[*] done: OK {ok} | FAIL {fail}")
        _emit_progress(ok, fail)  # final snapshot
    return ok, fail, out
