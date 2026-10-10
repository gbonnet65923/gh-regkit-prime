"""Profile helpers: passwords, GitHub usernames, OTP extraction."""
from __future__ import annotations

import re
import secrets
import string
from typing import Any

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*"

_WORDS = [
    "novak", "rava", "kelby", "orin", "zephyr", "marlow", "quill", "sable",
    "tenzin", "fable", "gable", "harlow", "irwin", "jasper", "keaton",
    "landry", "moss", "nolan", "otter", "pascal", "quinn", "rivers", "silas",
    "tobin", "ulric", "vance", "wren", "xander", "yates", "zane",
]

_USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*[a-z0-9]$")


def generate_password(length: int = 16) -> str:
    """Random password that clears GitHub's strength/blocklist checks."""
    charset = _LOWER + _UPPER + _DIGITS + _SYMBOLS
    while True:
        pw = "".join(secrets.choice(charset) for _ in range(length))
        if (
            any(c in _LOWER for c in pw)
            and any(c in _UPPER for c in pw)
            and any(c in _DIGITS for c in pw)
        ):
            return pw


def generate_username() -> str:
    """GitHub-safe username: [a-z0-9-], no consecutive hyphens, <= 39 chars."""
    suffix = "".join(secrets.choice(_LOWER + _DIGITS) for _ in range(6))
    return f"{secrets.choice(_WORDS)}{suffix}"


def username_from_email(email: str, suffix: str = "") -> str:
    """Derive a GitHub username from the mailbox local-part.

    myname123@mail.example.com -> 'myname123'
    Falls back to a random username when the local-part is unusable.
    A short random suffix can be appended when the name is taken.

    Short local-parts (mail.cx issues 4-char ones like 'kt78') collide
    constantly on GitHub — always pad them with random alnum chars so the
    base name is unique before the first attempt.
    """
    local = (email or "").split("@", 1)[0].strip().lower()
    local = re.sub(r"[^a-z0-9-]", "", local)
    local = local.strip("-").replace("--", "-")
    if not is_valid_username(local):
        return generate_username()
    if len(local) < 10:
        local += "".join(secrets.choice(_LOWER + _DIGITS) for _ in range(10 - len(local)))
    name = (local + suffix)[:39]
    return name if is_valid_username(name) else generate_username()


def is_valid_username(name: str) -> bool:
    return 1 <= len(name) <= 39 and bool(_USERNAME_RE.match(name))


def extract_github_code(text: str) -> str | None:
    """8-digit GitHub code; the email body may separate the halves with a space."""
    if not text:
        return None
    m = re.search(r"\b(\d{4})\s*(\d{4})\b", text)
    if m:
        return m.group(1) + m.group(2)
    for pat in (
        r"verification\s+code[:\s]+(\d{4,8})",
        r"your\s+code[:\s]+(\d{4,8})",
        r"enter\s+this\s+code[:\s]+(\d{4,8})",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def parse_public_profile(random_user: Any, quote: Any) -> dict[str, str]:
    """Extract public display fields from Random User and ZenQuotes payloads.

    Contact details and generated credentials in the Random User response are
    intentionally ignored.
    """
    try:
        user = random_user["results"][0]
        person = user["name"]
        full_name = " ".join(
            part.strip()
            for part in (person.get("title", ""), person["first"], person["last"])
            if part.strip()
        )
        location = str(user["location"]["country"]).strip()
        bio = str(quote[0]["q"]).strip()
    except (IndexError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"invalid public profile payload: {exc}") from exc
    if not full_name or not location or not bio:
        raise ValueError("public profile payload has an empty required field")
    return {"name": full_name, "location": location, "bio": bio}
