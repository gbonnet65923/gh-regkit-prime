#!/usr/bin/env python3
"""CLI entry: automated GitHub sign-up with Camoufox + Litensi mail."""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from github_register.config import load_config
from github_register.runner import run_job, silence_playwright_noise


def main() -> int:
    silence_playwright_noise()  # hide TargetClosedError spam on browser exit
    ap = argparse.ArgumentParser(
        prog="github-regkit",
        description="Auto-register GitHub accounts (Camoufox + Litensi mail).",
    )
    ap.add_argument("--config", default="config.json", help="path to config json")
    ap.add_argument("--count", type=int, default=None, help="override register_count")
    ap.add_argument("--headless", action="store_true", help="run browsers hidden")
    ap.add_argument("--proxy", default="", help="override proxy, e.g. http://user:pass@host:port")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_file() and Path("config.example.json").is_file():
        shutil.copy("config.example.json", cfg_path)
        print(f"[!] created {cfg_path} from config.example.json — enter your Litensi credentials")

    cfg = load_config(cfg_path)
    if args.count is not None:
        cfg.register_count = max(1, args.count)
    if args.headless:
        cfg.headless = True
    if args.proxy:
        cfg.proxy = args.proxy

    try:
        ok, fail, out = run_job(cfg)
    except KeyboardInterrupt:
        print("[!] interrupted")
        return 130
    print(f"[*] output: {out}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
