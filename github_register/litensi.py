"""Litensi Mail API client.

Endpoints (docs):
  POST /api/profile          -> balance info
  POST /api/mail/prices      -> zones for a site
  POST /api/mail/order       -> create mailbox
  POST /api/mail/getstatus   -> poll message (min 5s interval!)
  POST /api/mail/setstatus   -> SUCCESS (code used) / CANCELED (abort)
  POST /api/mail/reorder     -> re-order the SAME email for another window
"""
from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

import requests

from .mail_errors import MailboxCancelled, MailboxTimeoutError

API_BASE = "https://litensi.id/api/mail"
PROFILE_BASE = "https://litensi.id/api/profile"


class LitensiError(RuntimeError):
    pass


class LitensiClient:
    def __init__(self, api_id: str, api_key: str, site: str, zone: str = ""):
        if not api_id or not api_key:
            raise LitensiError("litensi_api_id / litensi_api_key not configured")
        if not site:
            raise LitensiError("litensi_site not configured")
        self.api_id = api_id
        self.api_key = api_key
        self.site = site
        self.zone = zone
        self.session = requests.Session()

    def _post(self, path: str, data: dict, base: Optional[str] = None) -> dict:
        url = f"{base or API_BASE}/{path}" if path else (base or API_BASE)
        last_exc: Exception | None = None
        for attempt in range(3):  # transient network hiccups: retry
            try:
                resp = self.session.post(url, data=data, timeout=30)
                break
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(2 * (attempt + 1))
        else:
            raise LitensiError(f"litensi {url} unreachable: {last_exc}")
        try:
            payload = resp.json()
        except ValueError:
            payload = None
        if not resp.ok or not (payload and payload.get("success")):
            reason = payload.get("data") if isinstance(payload, dict) else None
            # Litensi error codes (docs: {"success": false, "data": "XXXXXX"})
            hints = {
                "BAD SITE": " — litensi_site must be a domain (for example: github.com)",
                "BAD API": " — check litensi_api_id / litensi_api_key",
                "BAD API ID": " — litensi_api_id is invalid or inactive",
                "BAD API KEY": " — litensi_api_key is invalid",
                "BAD ZONE": " — zone is unavailable for this site (leave blank for automatic selection)",
                "OUT OF STOCK": " — mailbox stock is empty for this zone/site",
                "NOT ENOUGH BALANCE": " — Litensi balance is insufficient",
                "IP NOT ALLOWED": " — server IP is not whitelisted in the Litensi dashboard",
            }
            hint = hints.get(str(reason).strip().upper(), "")
            raise LitensiError(
                f"litensi {path or 'profile'} failed (HTTP {resp.status_code}): "
                f"{reason or payload or resp.text[:200]}{hint}"
            )
        return payload.get("data") if payload.get("data") is not None else {}

    def profile(self) -> dict:
        """GET /api/profile — username, full_name, balance."""
        return self._post(
            "",
            {"api_id": self.api_id, "api_key": self.api_key},
            base=PROFILE_BASE,
        )

    def prices(self) -> list[dict]:
        data = self._post(
            "prices",
            {"api_id": self.api_id, "api_key": self.api_key, "site": self.site},
        )
        return data if isinstance(data, list) else []

    def pick_zone(self) -> str:
        stock = [z for z in self.prices() if float(z.get("stock") or 0) > 0]
        if not stock:
            raise LitensiError(f"litensi has no zones in stock for site {self.site!r}")
        return min(stock, key=lambda z: float(z.get("price") or 0))["zone"]

    def create_mailbox(self) -> tuple[str, str]:
        zone = self.zone or self.pick_zone()
        data = self._post(
            "order",
            {
                "api_id": self.api_id,
                "api_key": self.api_key,
                "zone": zone,
                "site": self.site,
            },
        )
        email = data.get("email")
        order_id = data.get("order_id")
        if not email or order_id is None:
            raise LitensiError(f"litensi order bad response: {data}")
        return email, str(order_id)

    def get_status(self, order_id: str) -> dict:
        return self._post(
            "getstatus",
            {"api_id": self.api_id, "api_key": self.api_key, "order_id": order_id},
        )

    def set_status(self, order_id: str, status: str) -> dict:
        """setstatus: only SUCCESS (code used) or CANCELED (abort)."""
        if status not in ("SUCCESS", "CANCELED"):
            raise LitensiError(f"invalid setstatus value: {status}")
        return self._post(
            "setstatus",
            {
                "api_id": self.api_id,
                "api_key": self.api_key,
                "order_id": order_id,
                "status": status,
            },
        )

    def mark_success(self, order_id: str) -> dict:
        """Confirm the activation code was used (docs: setstatus SUCCESS)."""
        return self.set_status(order_id, "SUCCESS")

    def reorder(self, email: str) -> dict:
        """Re-order the SAME email for a fresh window (docs: /api/mail/reorder).

        Returns {'order_id', 'email', 'expired_at'} — use the new order_id for
        further getstatus polling.
        """
        return self._post(
            "reorder",
            {
                "api_id": self.api_id,
                "api_key": self.api_key,
                "site": self.site,
                "email": email,
            },
        )

    def wait_for_code(
        self,
        order_id: str,
        email: str = "",
        timeout: int = 240,
        poll_interval: int = 5,
        reorder_after: int = 150,
        log: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        exclude_codes: Optional[Iterable[str]] = None,
    ) -> str:
        """Poll the mailbox until the GitHub code arrives.

        Litensi mailboxes expire fast (minutes). If no code arrives within
        `reorder_after` seconds, automatically re-order the SAME email for a
        fresh window and keep polling under the new order_id.

        ``exclude_codes`` — codes already consumed (e.g. the signup launch
        code). When GitHub asks for a SECOND launch code (device verification
        on login), skipping those already-used codes lets us wait for the new
        one instead of returning the same message again.

        IMPORTANT: returns only; setstatus SUCCESS is the CALLER's job once the
        code has actually been submitted to GitHub (see runner).
        """
        from .profiles import extract_github_code

        poll_interval = max(5, poll_interval)  # litensi: >= 5s between getstatus
        started = time.time()
        current_order = str(order_id)
        reordered_at: Optional[float] = None
        # Once a reorder call has failed with a definitive error (e.g. the
        # provider returns UNSUPPORT ACTIVATION, or the plan does not allow
        # reorder for this zone), don't retry it every poll — otherwise the
        # log fills with dozens of identical failures. We keep polling the
        # original order until the total ``timeout`` expires.
        reorder_disabled = False
        skip = {str(c).strip() for c in (exclude_codes or ()) if str(c).strip()}
        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailboxCancelled("cancelled while waiting for mail")
            try:
                data = self.get_status(current_order)
            except Exception as exc:
                msg = str(exc).lower()
                if "activation does not exist" in msg or "email activation expired" in msg:
                    # mailbox window closed — re-order the same email if we can
                    if email and not reorder_disabled:
                        if log:
                            log(f"[*] litensi order {current_order} expired — reordering {email}")
                        try:
                            data = self.reorder(email)
                            current_order = str(data.get("order_id") or current_order)
                            reordered_at = time.time()
                            continue
                        except Exception as reorder_exc:
                            reorder_disabled = True
                            if log:
                                log(f"[!] litensi reorder failed permanently: {reorder_exc} — "
                                    f"will keep polling the original order until timeout")
                if log:
                    log(f"[!] litensi getstatus failed: {exc}")
                time.sleep(poll_interval)
                continue
            status = str(data.get("status") or "")
            if log:
                log(f"[*] litensi order {current_order} status: {status}")
            if status == "CANCELED":
                raise LitensiError("litensi order canceled")
            text = "\n".join(
                x for x in (data.get("message", ""), data.get("full_message", "")) if x
            )
            code = extract_github_code(text)
            if code:
                if code in skip:
                    if log:
                        log(f"[*] litensi skipped already-used code {code}")
                else:
                    self._last_order_id = current_order
                    return code
            # no code yet and the window is running out -> reorder the same email
            elapsed = time.time() - (reordered_at or started)
            if email and not reorder_disabled and elapsed >= reorder_after:
                if log:
                    log(f"[*] no code after {int(elapsed)}s — reordering mailbox {email}")
                try:
                    data = self.reorder(email)
                    current_order = str(data.get("order_id") or current_order)
                    reordered_at = time.time()
                except Exception as exc:
                    # Reorder is not supported for this order / plan / zone.
                    # Disable further reorder attempts so we don't spam the
                    # provider every poll_interval seconds until timeout.
                    reorder_disabled = True
                    if log:
                        log(f"[!] reorder failed: {exc} — reorder disabled, "
                            f"will keep polling original order")
            time.sleep(poll_interval)
        # Per-mailbox timeout — NOT a fatal provider error. One mailbox that
        # never received the GitHub code must fail only this account; the job
        # continues with the next one (see github_register.mail_errors).
        raise MailboxTimeoutError(f"no GitHub code after {timeout}s")

    @property
    def last_order_id(self) -> str:
        """Order id that actually delivered the code (may differ after reorder)."""
        return getattr(self, "_last_order_id", "")
