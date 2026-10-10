# -*- coding: utf-8 -*-
"""temp.tf mailboxes — free, no keys, gmail/outlook/hotmail/high.edu.pl pool.

Duck-typed like MailCxClient so the runner can swap providers:
  create_mailbox() -> (address, order_id)
  wait_for_code(address, ...) -> code
  set_status / mark_success / last_order_id (no-ops)

NOTE: temp.tf addresses are SHARED (not reserved) — fine for GitHub launch
codes, not for sensitive mail. Providers list is configurable; when a
provider pool is empty the API returns {"email": null} — we rotate the
requested providers until one yields an address.
"""
from __future__ import annotations

import random
import re
import time
from typing import Callable, Iterable, Optional

import requests

from .mail_errors import MailboxCancelled, MailboxTimeoutError

BASE = "https://temp.tf"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
DEFAULT_PROVIDERS = "gmail.com,outlook.com,hotmail.com,high.edu.pl"

_CODE_RE = re.compile(r"\b(\d{4}[-\s]?\d{4}|\d{8})\b")


class TempTfError(RuntimeError):
    pass


class TempTfClient:
    def __init__(self, providers: str = DEFAULT_PROVIDERS,
                 dot: bool = True, plus: bool = True, timeout: int = 30):
        self.providers = [p.strip() for p in (providers or DEFAULT_PROVIDERS).split(",") if p.strip()]
        self.dot = dot
        self.plus = plus
        self.timeout = timeout
        self._last_order_id = ""
        self._session = requests.Session()
        self._session.headers.update(HEADERS)

    # --- mailbox creation ---
    def _request_email(self, providers: list[str]) -> str:
        url = (f"{BASE}/api/account?providers={','.join(providers)}"
               f"&dot={1 if self.dot else 0}&plus={1 if self.plus else 0}")
        r = self._session.get(url, timeout=self.timeout)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", "5") or 5)
            time.sleep(min(wait, 30))
            r = self._session.get(url, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return (data or {}).get("email") or ""

    def create_mailbox(self) -> tuple[str, str]:
        # try the full provider list first, then fall back one-by-one
        attempts: list[list[str]] = [self.providers] + [[p] for p in self.providers]
        last_err = ""
        for provs in attempts:
            try:
                email = self._request_email(provs)
            except requests.RequestException as exc:
                last_err = str(exc)
                continue
            if email and "@" in email:
                self._last_order_id = email
                return email, email
            last_err = "pool empty for " + ",".join(provs)
        raise TempTfError(f"temp.tf could not issue an address: {last_err}")

    # --- inbox polling ---
    def get_messages(self, address: str) -> list[dict]:
        r = self._session.post(f"{BASE}/api/check",
                               json={"email": address, "wait": False},
                               timeout=self.timeout)
        r.raise_for_status()
        data = r.json() or {}
        msgs = data.get("data") or []
        out = []
        for m in msgs:
            out.append({
                "subject": m.get("subject") or "",
                "from": m.get("from") or "",
                "body": (m.get("text") or "") + "\n" + (m.get("html") or ""),
            })
        return out

    @staticmethod
    def extract_github_code(body: str) -> str:
        if not body:
            return ""
        text = re.sub(r"<[^>]+>", " ", body)
        for kw in ("launch code", "verification code", "confirm"):
            idx = text.lower().find(kw)
            if idx >= 0:
                m = _CODE_RE.search(text[idx:idx + 200])
                if m:
                    return re.sub(r"[-\s]", "", m.group(1))
        m = _CODE_RE.search(text)
        if m:
            return re.sub(r"[-\s]", "", m.group(1))
        return ""

    def wait_for_code(
        self,
        address: str,
        timeout: int = 240,
        poll_interval: int = 8,
        log: Optional[Callable[[str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
        email: str = "",
        exclude_codes: Optional[Iterable[str]] = None,
    ) -> str:
        started = time.time()
        attempts = 0
        skip = {str(c).strip() for c in (exclude_codes or ()) if str(c).strip()}
        seen: set[str] = set()
        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailboxCancelled("cancelled while waiting for mail")
            try:
                messages = self.get_messages(address)
            except requests.RequestException as exc:
                if log:
                    log(f"[!] temp.tf check failed ({exc}); retrying")
                messages = []
            attempts += 1
            for msg in messages:
                key = msg.get("subject", "") + msg.get("from", "")
                if log and key not in seen:
                    log(f"[*] temptf message from={msg.get('from','')} "
                        f"subject={msg.get('subject','')[:60]}")
                seen.add(key)
                code = self.extract_github_code(msg.get("body", ""))
                if not code or code in skip:
                    continue
                return code
            if log:
                elapsed = int(time.time() - started)
                log(f"[*] temptf poll #{attempts} — no code yet ({elapsed}s/{timeout}s)")
            time.sleep(max(poll_interval, 5))
        raise MailboxTimeoutError(
            f"no GitHub code after {timeout}s ({attempts} polls)")

    # --- order lifecycle: no-ops ---
    def set_status(self, order_id: str, status: str) -> dict:
        return {"ok": True}

    def mark_success(self, order_id: str) -> dict:
        return {"ok": True}

    @property
    def last_order_id(self) -> str:
        return self._last_order_id
