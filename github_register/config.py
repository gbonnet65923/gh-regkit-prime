"""Configuration loading for the GitHub register toolkit."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Config:
    # Mail provider: "mailcx" (free, default), "litensi" (paid, reliable),
    # "gmail" / "outlook" — your own mailbox via IMAP with +alias addresses
    # "temptf" — temp.tf free pool (gmail/outlook/hotmail/high.edu.pl aliases)
    mail_provider: str = "mailcx"  # "mailcx" | "litensi" | "gmail" | "outlook" | "temptf"
    # temp.tf providers (comma list; pools can be empty -> rotated)
    temptf_providers: str = "gmail.com,outlook.com,hotmail.com,high.edu.pl"
    temptf_dot: bool = True   # gmail dot-aliases
    temptf_plus: bool = True  # +tag aliases
    # IMAP (gmail/outlook providers): App Password recommended, IMAP enabled
    imap_user: str = ""          # e.g. mybox@gmail.com or mybox@outlook.com
    imap_password: str = ""      # App Password (NOT the account password)
    imap_host: str = ""          # blank = provider default
    imap_port: int = 993
    imap_alias_domain: str = ""  # blank = gmail.com / outlook.com
    # Mail.cx temp email settings
    mailcx_domain: str = ""  # empty = auto-pick from uqu.me, ddker.com, 9k3r.com
    # Litensi Mail settings
    litensi_api_id: str = ""
    litensi_api_key: str = ""
    litensi_site: str = ""   # e.g. "github.com"
    litensi_zone: str = ""   # blank = auto-pick cheapest in-stock zone
    register_count: int = 1
    proxy: str = ""
    proxy_file: str = ""     # proxy pool file in project root (one URL per line); overrides proxy
    headless: bool = False
    delay_sec: float = 5.0
    max_username_tries: int = 6
    otp_timeout_sec: int = 240
    browser_profile_dir: str = ".browser-profile"
    # fresh browser per account (incognito-like, zero cached state); the
    # DataDome trust cookie is carried over via .datadome-trust.json so the
    # signup page keeps loading without hard 403s
    fresh_profile: bool = True
    proxy_hard_block_retries: int = 2
    proxy_rate_limit_retries: int = 2
    # post-signup stages (from user recording)
    # PRIME: Arkose FunCaptcha multi-LLM voting solver ($0 qwen pool by default)
    solve_captcha: bool = True
    captcha_max_rounds: int = 12
    create_repo: bool = True          # stage 4: create first repository
    repo_name: str = "hello"          # repo name prefix (username-suffix appended on conflict)
    enable_2fa: bool = True           # stage 5: enable TOTP 2FA and store the secret
    create_pat: bool = False          # stage 6: classic PAT (repo+workflow scopes)
    set_profile_status: bool = True
    profile_status: str = "On vacation"  # blank disables custom status text
    complete_profile: bool = True
    profile_name: str = ""            # blank = Random User
    profile_bio: str = ""             # blank = ZenQuotes
    profile_location: str = ""        # blank = Random User country

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = set(cls.__dataclass_fields__)
        mapped = {k: v for k, v in data.items() if k in known}
        return cls(**mapped)


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(
            f"config not found: {p} (copy config.example.json to config.json and fill it in)"
        )
    data = json.loads(p.read_text(encoding="utf-8"))
    return Config.from_dict(data)
