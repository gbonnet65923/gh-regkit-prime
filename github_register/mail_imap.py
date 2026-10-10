# -*- coding: utf-8 -*-
"""IMAP mail providers: Gmail (+alias) and Outlook (+alias).

Same duck-typed interface as MailCxClient so the runner can swap providers:
  create_mailbox() -> (address, order_id)
  wait_for_code(address, ...) -> code
  set_status / mark_success / last_order_id (no-ops here)

Gmail: base+<random>@gmail.com — Google delivers plus-addressed mail to the
base inbox; we match the To: header. Requires an App Password (2FA on).
Outlook: base+<random>@outlook.com — Outlook.com supports plus addressing
the same way. Also App Password or OAuth; IMAP must be enabled.
"""
from __future__ import annotations

import email
import email.header
import email.utils
import imaplib
import random
import re
import string
import time
from typing import Callable, Iterable, Optional

from .mail_errors import MailboxCancelled, MailboxTimeoutError

GMAIL_IMAP = ("imap.gmail.com", 993)
OUTLOOK_IMAP = ("outlook.office365.com", 993)

_CODE_RE = re.compile(r"\b(\d{4}[-\s]?\d{4}|\d{8})\b")


class ImapMailError(RuntimeError):
    pass


class ImapMailClient:
    """One real mailbox, unlimited +alias addresses."""

    def __init__(self, provider: str, user: str, password: str,
                 host: str = "", port: int = 993, alias_domain: str = ""):
        self.provider = (provider or "").strip().lower()
        self.user = (user or "").strip()
        self.password = password or ""
        self.alias_domain = (alias_domain or "").strip().lstrip("@")
        if self.provider == "gmail":
            default_host, default_port = GMAIL_IMAP
            self.alias_domain = self.alias_domain or "gmail.com"
        elif self.provider == "outlook":
            default_host, default_port = OUTLOOK_IMAP
            self.alias_domain = self.alias_domain or "outlook.com"
        else:
            raise ImapMailError(f"unknown imap provider: {provider}")
        self.host = (host or "").strip() or default_host
        self.port = int(port or default_port)
        if not self.user or not self.password:
            raise ImapMailError(
                f"{self.provider}: imap_user and imap_password (App Password) are required")
        self._last_order_id = ""
        self._used_suffixes: set[str] = set()

    # --- mailbox creation: just mint a fresh +alias ---
    @staticmethod
    def _random_suffix(n: int = 10) -> str:
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

    def create_mailbox(self) -> tuple[str, str]:
        base = self.user.split("@")[0]
        for _ in range(50):
            suffix = self._random_suffix()
            if suffix in self._used_suffixes:
                continue
            self._used_suffixes.add(suffix)
            address = f"{base}+{suffix}@{self.alias_domain}"
            self._last_order_id = address
            return address, address
        raise ImapMailError("could not mint a unique alias suffix")

    # --- IMAP helpers ---
    def _connect(self) -> imaplib.IMAP4_SSL:
        conn = imaplib.IMAP4_SSL(self.host, self.port, timeout=30)
        conn.login(self.user, self.password)
        conn.select("INBOX")
        return conn

    @staticmethod
    def _decode_hdr(raw) -> str:
        if not raw:
            return ""
        parts = email.header.decode_header(raw)
        out = []
        for txt, enc in parts:
            if isinstance(txt, bytes):
                out.append(txt.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(txt)
        return "".join(out)

    @staticmethod
    def _body_of(msg) -> str:
        chunks = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            chunks.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    chunks.append(payload.decode(charset, errors="replace"))
            except Exception:
                pass
        return "\n".join(chunks)

    @staticmethod
    def extract_github_code(body: str) -> str:
        """GitHub launch code: 8 digits (XXXX-XXXX or plain). Prefer the
        context around 'launch code' / 'verification'."""
        if not body:
            return ""
        text = re.sub(r"<[^>]+>", " ", body)
        # window around keywords first
        for kw in ("launch code", "verification code", "confirm"):
            idx = text.lower().find(kw)
            if idx >= 0:
                window = text[idx:idx + 200]
                m = _CODE_RE.search(window)
                if m:
                    return re.sub(r"[-\s]", "", m.group(1))
        m = _CODE_RE.search(text)
        if m:
            return re.sub(r"[-\s]", "", m.group(1))
        return ""

    def get_messages(self, address: str, limit: int = 15) -> list[dict]:
        """Fetch the newest messages whose To: matches the alias address."""
        try:
            conn = self._connect()
        except imaplib.IMAP4.error as exc:
            raise ImapMailError(f"{self.provider} IMAP login failed: {exc}") from exc
        out = []
        try:
            status, data = conn.search(None, "ALL")
            if status != "OK":
                return out
            ids = data[0].split()
            target = address.lower()
            for num in reversed(ids[-60:]):
                status, mdata = conn.fetch(num, "(RFC822)")
                if status != "OK" or not mdata or not mdata[0]:
                    continue
                raw = mdata[0][1]
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                msg = email.message_from_bytes(raw)
                to_hdr = self._decode_hdr(msg.get("To", "")).lower()
                if target not in to_hdr:
                    continue
                subj = self._decode_hdr(msg.get("Subject", ""))
                frm = self._decode_hdr(msg.get("From", ""))
                out.append({
                    "subject": subj,
                    "from": frm,
                    "body": self._body_of(msg),
                })
                if len(out) >= limit:
                    break
        finally:
            try:
                conn.logout()
            except Exception:
                pass
        return out

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
        while time.time() - started < timeout:
            if cancel_cb and cancel_cb():
                raise MailboxCancelled("cancelled while waiting for mail")
            try:
                messages = self.get_messages(address)
            except ImapMailError as exc:
                if log:
                    log(f"[!] {exc}; retrying")
                messages = []
            attempts += 1
            for msg in messages:
                if log:
                    log(f"[*] {self.provider} message from={msg.get('from','')} "
                        f"subject={msg.get('subject','')[:60]}")
                code = self.extract_github_code(msg.get("body", ""))
                if not code or code in skip:
                    if code and code in skip and log:
                        log(f"[*] {self.provider} skipped already-used code {code}")
                    continue
                return code
            elapsed = int(time.time() - started)
            if log:
                log(f"[*] {self.provider} imap poll #{attempts} — no code yet "
                    f"({elapsed}s/{timeout}s)")
            time.sleep(max(poll_interval, 5))
        raise MailboxTimeoutError(
            f"no GitHub code after {timeout}s ({attempts} polls)")

    # --- order lifecycle: no-ops for a personal mailbox ---
    def set_status(self, order_id: str, status: str) -> dict:
        return {"ok": True}

    def mark_success(self, order_id: str) -> dict:
        return {"ok": True}

    @property
    def last_order_id(self) -> str:
        return self._last_order_id
