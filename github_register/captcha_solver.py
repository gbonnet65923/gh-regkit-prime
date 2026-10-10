# -*- coding: utf-8 -*-
"""Sync Arkose FunCaptcha solver — multi-LLM voting, $0.

Adapted from GoubaLab/reg-factory-github `common/agent_captcha.py`
(10/10 field-verified voting solver) to the SYNC Playwright/Camoufox API
used by this project's runner.

Flow:
  1. Wait for Arkose proof-of-work, click "Visual puzzle" inside octocaptcha iframe
  2. Per round: detect variant (sequence/rotate/character/wires)
  3. Screenshot reference + N candidates, stitch numbered grid, enhance (PIL)
  4. Parallel vote: qwen3-vl-flash / qwen-vl-max / qwen-vl-plus via local
     dashscope proxy (free) + any configured premium gateways
  5. Majority wins -> navigate back to winning candidate -> Submit
  6. Repeat until octocaptcha disappears (passed) or max_rounds

Env overrides:
  VOTE_BASE   default http://127.0.0.1:16432/v1  (OpenAI-compatible vision gateway)
  VOTE_KEY    default "free"
  VOTE_MODELS default qwen3-vl-flash,qwen-vl-max,qwen-vl-plus (comma separated)
"""
from __future__ import annotations

import base64
import os
import time
from pathlib import Path

from . import agent_captcha as AC

_DEFAULT_BASE = os.environ.get("VOTE_BASE", "http://127.0.0.1:16432/v1")
_DEFAULT_KEY = os.environ.get("VOTE_KEY", "free")
_DEFAULT_MODELS = [
    m.strip() for m in
    os.environ.get("VOTE_MODELS", "qwen3-vl-flash,qwen-vl-max,qwen-vl-plus").split(",")
    if m.strip()
]

SEL_REF = ".key-frame-image"
SEL_CAND = ".answer-frame img, .answer-frame canvas, .answer-frame"


def _frames(page):
    try:
        return list(page.frames)
    except Exception:
        return []


def _is_arkose_frame(f):
    u = (f.url or "").lower()
    return any(k in u for k in ("octocaptcha", "arkose", "funcaptcha"))


def _find_game(page):
    """Return (frame, question_text) of the real puzzle game frame or (None, '')."""
    for f in _frames(page):
        u = f.url or ""
        if "index.html" in u and ("arkose" in u.lower() or "funcaptcha" in u.lower()):
            try:
                if f.get_by_role("button", name="Navigate to next image").count() > 0:
                    t = f.evaluate("() => document.body.innerText || ''")
                    return f, t
            except Exception:
                pass
    return None, ""


def _count_options(game) -> int:
    try:
        n = game.evaluate("() => document.querySelectorAll('.pip').length")
        if isinstance(n, int) and 2 <= n <= 12:
            return n
    except Exception:
        pass
    return 6


def _shot_element(frame, selector, path, scale=3):
    """Screenshot an element inside the game frame, upscaled. Returns b64 or None."""
    try:
        el = frame.locator(selector).first
        if el.count() == 0:
            return None
        el.screenshot(path=path)
    except Exception as exc:
        print(f"  [vote] shot_element({selector}) err: {str(exc)[:60]}")
        return None
    try:
        from PIL import Image
        im = Image.open(path).convert("RGB")
        im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
        im.save(path)
        with open(path, "rb") as fh:
            return base64.b64encode(fh.read()).decode()
    except Exception:
        with open(path, "rb") as fh:
            return base64.b64encode(fh.read()).decode()


def arkose_present(page) -> bool:
    """Is an Arkose/Octocaptcha challenge frame on the page right now?"""
    return any(_is_arkose_frame(f) for f in _frames(page))


def _click_visual_puzzle(page, deadline_s: float) -> bool:
    """Wait out the Arkose PoW and click 'Visual puzzle'. Returns True on click."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        for f in _frames(page):
            if _is_arkose_frame(f):
                try:
                    el = f.get_by_text("Visual puzzle", exact=False).first
                    if el.count() > 0:
                        el.click(timeout=4000)
                        print("  [vote] clicked 'Visual puzzle'")
                        return True
                except Exception:
                    pass
        time.sleep(3)
    return False


def solve_arkose_voting(page, shot_dir: str = "screenshots_captcha",
                        max_rounds: int = 12, log=print,
                        skip_variants=("character",)) -> bool:
    """Solve the GitHub Arkose FunCaptcha via multi-model voting (sync API).

    Call AFTER 'Create account' was clicked and the challenge appeared.
    Returns True when the octocaptcha frame disappears (verification passed).
    Returns 'SKIP_VARIANT' when round 0 is the hard character variant
    (caller should reload for a new challenge). Returns False on failure.
    """
    Path(shot_dir).mkdir(parents=True, exist_ok=True)

    # --- trigger / wait for the game ---
    for it in range(16):  # up to ~48s of PoW + settle
        game, qt = _find_game(page)
        if game:
            break
        if not arkose_present(page):
            log("[vote] no arkose frame — nothing to solve")
            return True
        _click_visual_puzzle(page, deadline_s=6)
        time.sleep(3)
    else:
        log("[vote] game frame never appeared")
        return False

    rnd = -1
    while True:
        rnd += 1
        if rnd > max_rounds:
            log("[vote] max rounds exhausted")
            return False
        game = None
        for _w in range(16):
            game, qt = _find_game(page)
            if game:
                break
            if not arkose_present(page):
                log(f"[vote] octocaptcha gone @ R{rnd} — PASSED")
                return True
            _click_visual_puzzle(page, deadline_s=3)
            time.sleep(3)
        if not game:
            if not arkose_present(page):
                return True
            log(f"[vote] R{rnd}: cannot grab puzzle frame")
            return False

        qfull = (qt or "").replace("\n", " ").strip()
        qline = qfull[:200]
        variant = AC.gh_variant(qfull)
        N = _count_options(game)
        log(f"[vote] R{rnd} variant={variant} N={N} q={qline!r}")

        if rnd == 0 and variant in skip_variants:
            log(f"[vote] hard variant '{variant}' on first round — skip window")
            return "SKIP_VARIANT"

        # wait for reference image to render
        for _ld in range(8):
            try:
                rel = game.locator(SEL_REF).first
                if rel.count() > 0:
                    bx = rel.bounding_box()
                    if bx and bx["width"] > 20 and bx["height"] > 20:
                        break
            except Exception:
                pass
            time.sleep(1)
        time.sleep(2.5 if rnd == 0 else 1.0)

        nxt = game.get_by_role("button", name="Navigate to next image")
        ref = _shot_element(game, SEL_REF, f"{shot_dir}/v_ref{rnd}.png", scale=3)
        cands = []
        for i in range(N):
            c = _shot_element(game, SEL_CAND, f"{shot_dir}/v_c{rnd}_{i}.png", scale=3)
            if c:
                cands.append(c)
            if i < N - 1:
                try:
                    nxt.first.click(timeout=3000)
                except Exception:
                    break
                time.sleep(0.8)
        grid, geom = AC.stitch_options_grid(
            cands, f"{shot_dir}/v_grid{rnd}.png", reference_b64=ref,
            cols=3, return_geom=True)
        if not grid:
            log("[vote] grid stitch failed")
            return False
        if variant == "character":
            grid_hd = AC.enhance_local(grid, f"{shot_dir}/v_grid{rnd}_hd.png",
                                       scale=2, max_side=1000, jpeg_quality=72)
        else:
            grid_hd = AC.enhance_local(grid, f"{shot_dir}/v_grid{rnd}_hd.png", scale=2)

        prm = AC.gh_pick_prompt(qline, len(cands), variant)

        # vote with the FREE qwen pool unless premium gateways are configured
        models = [(_DEFAULT_BASE, _DEFAULT_KEY, m) for m in _DEFAULT_MODELS]
        if AC.VOTER_MODELS:
            models = list(AC.VOTER_MODELS) + models
        saved = AC.VOTER_MODELS
        try:
            AC.VOTER_MODELS = models
            best, votes, raws = AC.vote_answer(prm, grid_hd, len(cands), max_tokens=900)
            if not votes:
                time.sleep(2)
                best, votes, raws = AC.vote_answer(prm, grid_hd, len(cands), max_tokens=900)
        finally:
            AC.VOTER_MODELS = saved
        if best is None or best < 0 or best >= len(cands):
            best = 0
        log(f"[vote] R{rnd} -> #{best} votes={votes}")

        try:
            AC.annotate_choice(f"{shot_dir}/v_grid{rnd}.png", geom, best,
                               f"{shot_dir}/REVIEW_r{rnd}.png",
                               note=f"r{rnd} #{best} {votes}", votes_raw=raws)
        except Exception:
            pass

        # re-acquire the game frame (it may have re-rendered)
        game = None
        for _w in range(8):
            game, _ = _find_game(page)
            if game:
                break
            if not arkose_present(page):
                return True
            time.sleep(2)
        if not game:
            if not arkose_present(page):
                return True
            continue

        # navigate back from the last candidate to the winning one, then Submit
        back = (N - 1 - best)
        prv = game.get_by_role("button", name="Navigate to previous image")
        for _ in range(back):
            try:
                prv.first.click(timeout=3000)
            except Exception:
                pass
            time.sleep(0.6)
        time.sleep(1)
        for attempt in range(4):
            try:
                game.get_by_role("button", name="Submit").first.click(timeout=4000)
                break
            except Exception:
                game, _ = _find_game(page)
                if not game:
                    break
                time.sleep(1.5)
        time.sleep(4)
        if not arkose_present(page):
            log("[vote] verification PASSED")
            return True
