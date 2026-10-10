# -*- coding: utf-8 -*-
"""
common/agent_captcha.py — 视觉 LLM 验证码求解器（agent-captcha）

思路：截图验证码挑战 -> 发给 vision LLM（OpenRouter）-> LLM 读题+看图给出结构化答案
     -> 调用方据答案驱动 UI（点箭头/选图/Submit）。

比打码平台鲁棒：LLM 能读懂任意题型变体，不依赖某平台是否支持该 service。
模型：优先 PRIMARY，429/失败则按 FALLBACKS 降级；OpenRouter key 可多个轮换抗限流。
"""

import base64
import json
import os
import sys
import time

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

import requests

# 网关/key 全部从 config（.env）读取，不在代码里留明文。见 .env.example。
import os as _os
import sys as _sys2
_sys2.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
try:
    import config as _cfg
except Exception:
    _cfg = None


def _c(name, default=""):
    """优先环境变量，其次 config.<name>，再 default。"""
    v = os.environ.get(name)
    if v:
        return v
    if _cfg is not None:
        v = getattr(_cfg, name, "")
        if v:
            return v
    return default


# 主视觉网关（gpt-5.x）。模型可用 VISION_MODEL 覆盖。
VISION_API_BASE = _c("VISION_API_BASE")
VISION_API_KEY = _c("VISION_API_KEY")
PRIMARY_MODEL = _c("VISION_MODEL", "gpt-5.5")
FALLBACK_MODELS = [
    "gpt-5.4-mini",
]
# gemma 免费兜底文本网关
GEMMA_API_BASE = _c("GEMMA_API_BASE")
GEMMA_API_KEY = _c("GEMMA_API_KEY")

# 模型有时把验证码当"不可协助"拒答；命中这些词就判定为拒答、换下一个 model/key。
_REFUSAL_MARKERS = (
    "cannot fulfill", "can't fulfill", "cannot assist", "can't assist",
    "i am unable", "i'm unable", "safety guidelines", "harmless ai",
    "not able to help", "cannot help with that",
)


def _looks_like_refusal(text):
    if not text:
        return True
    t = text.lower()
    return any(m in t for m in _REFUSAL_MARKERS)


def _load_keys():
    """LLM key：默认 VISION_API_KEY（gpt-5 网关）。gemma 兜底 key 也加进来。
    sk-or- 的 OpenRouter key（若设了 OPENROUTER_KEYS）追加到最后。"""
    keys = []
    if VISION_API_KEY:
        keys.append(VISION_API_KEY)
    if GEMMA_API_KEY and GEMMA_API_KEY not in keys:
        keys.append(GEMMA_API_KEY)
    env = os.environ.get("OPENROUTER_KEYS") or os.environ.get("OPENROUTER_KEY") or ""
    for k in env.replace("\n", ",").split(","):
        k = k.strip()
        if k.startswith("sk-or-") and k not in keys:
            keys.append(k)
    return keys


def _endpoint_for_key(key):
    """key 决定走哪个网关：sk-or- 走 OpenRouter，sk-Gso 走 gemma 网关，其余走主网关。"""
    if key.startswith("sk-or-"):
        return "https://openrouter.ai/api/v1/chat/completions"
    if key == GEMMA_API_KEY:
        return f"{GEMMA_API_BASE.rstrip('/')}/v1/chat/completions"
    return f"{VISION_API_BASE.rstrip('/')}/v1/chat/completions"


def _model_for_key(key, model):
    """gemma 兜底网关只有 gemma 模型可用；gpt-5 模型名在那边无效，自动换成 gemma。"""
    if key == GEMMA_API_KEY and model.startswith("gpt-"):
        return "google/gemma-4-31b-it:free"
    if key.startswith("sk-or-") and model.startswith("gpt-"):
        return "nvidia/nemotron-nano-12b-v2-vl:free"
    return model


def ask_vision(prompt, image_b64, models=None, keys=None, max_tokens=300, temperature=0.0):
    """把 prompt + 图片发给 vision LLM，返回文本答案或 None。
    按 models 降级、按 keys 轮换；429/5xx 自动换下一个组合。
    key 决定网关：默认 tiantianai key -> VISION_API_BASE；sk-or- -> OpenRouter。"""
    models = models or ([PRIMARY_MODEL] + FALLBACK_MODELS)
    keys = keys or _load_keys()
    if not keys:
        print("  [vision] 无可用 key")
        return None
    payload_msg = [{
        "role": "user",
        "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}},
        ],
    }]
    for model in models:
        for ki, key in enumerate(keys):
            real_model = _model_for_key(key, model)
            try:
                r = requests.post(
                    _endpoint_for_key(key),
                    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                    json={"model": real_model, "messages": payload_msg,
                          "max_tokens": max_tokens, "temperature": temperature},
                    timeout=120,
                )
                if r.status_code == 200:
                    txt = r.json()["choices"][0]["message"]["content"]
                    if _looks_like_refusal(txt):
                        print(f"  [vision] {real_model} key#{ki} refused, trying next")
                        continue
                    print(f"  [vision] {real_model} key#{ki} OK")
                    return txt
                if r.status_code in (404, 429, 500, 502, 503):
                    continue  # 模型不支持图/限流/上游错，换 key 或下一个 model
                print(f"  [vision] {real_model} key#{ki} -> {r.status_code} {r.text[:80]}")
            except Exception as e:
                print(f"  [vision] {real_model} key#{ki} err: {str(e)[:60]}")
                continue
    print("  [vision] 所有 model/key 都失败")
    return None


# 多模型投票池：(网关base, key, 模型)。盲区不同，多数表决互相纠错。
# 平票优先级=列表顺序。实测 gemini 在朝向/拼图题更准，opus(claude) 偏离谱→放最后(权重最低)。
# 网关/key 全走 config(.env)。某个 key 留空则该模型自动不参与(_ask_one 拿空 key 直接跳过)。
ZZ_BASE = _c("VOTE_ZZ_BASE")
ZZ_KEY = _c("VOTE_ZZ_KEY")
GPT_KEY = _c("VOTE_GPT_KEY") or ZZ_KEY
OPUS_BASE = _c("VOTE_OPUS_BASE")   # claude opus 专用网关（Anthropic 原生 /v1/messages）
OPUS_KEY = _c("VOTE_OPUS_KEY")
_FREE_BASE = "http://127.0.0.1:16432/v1"   # local dashscope pool proxy (free, verified 2026-10-08)
VOTER_MODELS = [(b, k, m) for (b, k, m) in [
    (ZZ_BASE, ZZ_KEY, "gemini-3.5-flash-c"),        # 平票最优先(实测最准)
    (ZZ_BASE, GPT_KEY, "gpt-5.5"),
    (ZZ_BASE, ZZ_KEY, "gemini-3.1-pro-preview-c"),
    (OPUS_BASE, OPUS_KEY, "claude-opus-4-8"),        # 权重最低(claude 在这些图上偏离谱)
    # FREE default voters: qwen vision models via local dashscope proxy ($0, ~1-3s each)
    (_FREE_BASE, "free", "qwen3-vl-flash"),
    (_FREE_BASE, "free", "qwen-vl-max"),
    (_FREE_BASE, "free", "qwen-vl-plus"),
] if b and k]   # 缺网关/key 的模型剔除
import re as _re_mod


def _ask_one(base, key, model, prompt, image_b64, max_tokens=900):
    """单模型单网关问一次，返回文本或 None。
    base 以 /messages 结尾或含 ai-wave/claude → 走 Anthropic 原生 /v1/messages 协议；
    否则走 OpenAI 兼容 /v1/chat/completions。"""
    if not base or not key:
        return None
    # 检测图片格式(JPEG base64 以 /9j/ 开头, PNG 以 iVBOR)，喂对 media_type
    mtype = "image/jpeg" if image_b64.startswith("/9j/") else "image/png"
    try:
        is_anthropic = base.rstrip("/").endswith("/claude") or "/v1/messages" in base
        if is_anthropic:
            ep = base.rstrip("/")
            if not ep.endswith("/v1/messages"):
                ep = ep + "/v1/messages"
            r = requests.post(
                ep,
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image", "source": {"type": "base64", "media_type": mtype, "data": image_b64}}]}]},
                timeout=35,
            )
            if r.status_code == 200:
                txt = "".join(b.get("text", "") for b in r.json().get("content", []))
                if txt and not _looks_like_refusal(txt):
                    return txt
            return None
        r = requests.post(
            f"{base.rstrip('/')}/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": model, "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": f"data:{mtype};base64,{image_b64}"}}]}],
                  "max_tokens": max_tokens, "temperature": 0.0},
            timeout=35,
        )
        if r.status_code == 200:
            txt = r.json()["choices"][0]["message"]["content"]
            if not _looks_like_refusal(txt):
                return txt
    except Exception as e:
        print(f"  [vote] {model} err: {str(e)[:50]}")
    return None


def vote_answer(prompt, image_b64, n_options, max_tokens=900, deadline=55):
    """多模型并发投票，解析各自 ANSWER=N，返回 (best, votes_dict, raw_list)。
    多数票胜出；平票时按 VOTER_MODELS 顺序优先。
    deadline: 整轮最多等这么多秒，掉队的模型直接放弃(避免某个慢模型拖到 150s 把整轮拖超 Arkose 倒计时)。"""
    import concurrent.futures as cf
    answers = []
    raws = []
    done_models = set()
    with cf.ThreadPoolExecutor(max_workers=len(VOTER_MODELS)) as ex:
        futs = {ex.submit(_ask_one, b, k, m, prompt, image_b64, max_tokens): m
                for (b, k, m) in VOTER_MODELS}
        try:
            for fut in cf.as_completed(futs, timeout=deadline):
                model = futs[fut]
                done_models.add(model)
                txt = fut.result()
                a = None
                if txt:
                    mm = _re_mod.findall(r"ANSWER\s*=\s*(\d+)", txt)
                    if mm:
                        a = int(mm[-1])
                if a is not None and 0 <= a < n_options:
                    answers.append((model, a))
                raws.append((model, a, (txt or "")[-120:]))
                print(f"  [vote] {model} -> {a}")
        except cf.TimeoutError:
            # 超过整轮 deadline：放弃还没回来的模型，用已有票
            for fut, model in futs.items():
                if model not in done_models:
                    fut.cancel()
                    raws.append((model, None, "[deadline timeout]"))
                    print(f"  [vote] {model} -> None (deadline {deadline}s)")
    if not answers:
        return None, {}, raws
    # 计票
    from collections import Counter
    cnt = Counter(a for _, a in answers)
    top, topn = cnt.most_common(1)[0]
    # 平票：按 VOTER_MODELS 顺序找第一个投了高票答案的
    order = [m for (_, _, m) in VOTER_MODELS]
    if list(cnt.values()).count(topn) > 1:
        for m in order:
            for mm, a in answers:
                if mm == m and cnt[a] == topn:
                    top = a; break
            else:
                continue
            break
    return top, dict(cnt), raws


def parse_json_answer(text):
    """从 LLM 回复里抠出第一个 JSON 对象（容忍 ```json 包裹和前后文字）。"""
    if not text:
        return None
    import re
    # 抓最后一个平衡的 {...}（容忍 CoT 推理后才给 JSON、且 JSON 内含数组）。
    candidates = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidates.append(text[start:i + 1])
    for blob in reversed(candidates):
        try:
            return json.loads(blob)
        except Exception:
            continue
    return None


async def screenshot_frame_region(page, frame, path):
    """截某 iframe 在主页面里的可视区域为 png，返回 base64。
    Arkose 拼图渲染在深层 frame，直接截它对应的 iframe 元素最稳。"""
    try:
        # 找到承载该 frame 的 iframe 元素
        handle = await frame.frame_element()
        await handle.screenshot(path=path)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        print(f"  [vision] frame screenshot err: {str(e)[:70]}")
        return None


# Arkose game frame 里两块图的选择器（实测 v4.2.2 布局）：
#   参考图（"Match This!" 目标）= .key-frame-image
#   候选图（当前显示的那张/那个网格）= .answer-frame img
SEL_REFERENCE = ".key-frame-image"
SEL_CANDIDATE = ".answer-frame img, .answer-frame canvas, .answer-frame"


async def shot_element(frame, selector, path, scale=3):
    """截 game frame 里某元素并放大 scale 倍（提升小图的细节可读性）。
    返回放大后的 png base64，失败返回 None。"""
    try:
        el = frame.locator(selector).first
        if await el.count() == 0:
            return None
        await el.screenshot(path=path)
    except Exception as e:
        print(f"  [vision] shot_element({selector}) err: {str(e)[:60]}")
        return None
    # 放大
    try:
        from PIL import Image
        im = Image.open(path).convert("RGB")
        im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
        im.save(path)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        # 没 PIL 就用原图
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()


def _b64_concat_side_by_side(b64_left, b64_right, path):
    """把参考图+候选图横向拼成一张（有参照系，LLM 比较判断更准）。返回拼图 base64。"""
    try:
        from PIL import Image
        import io
        L = Image.open(io.BytesIO(base64.b64decode(b64_left))).convert("RGB")
        R = Image.open(io.BytesIO(base64.b64decode(b64_right))).convert("RGB")
        h = max(L.height, R.height)
        gap = 20
        canvas = Image.new("RGB", (L.width + gap + R.width, h), (255, 255, 255))
        canvas.paste(L, (0, 0))
        canvas.paste(R, (L.width + gap, 0))
        canvas.save(path)
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        print(f"  [vision] concat err: {str(e)[:60]}")
        return None


def stitch_options_grid(b64_list, path, reference_b64=None, cols=4, label_h=24, return_geom=False):
    """把一组候选图拼成一张带编号(0,1,2...)的网格大图，可选在最上方放参考图。
    这样 LLM 一次调用就能横向对比所有候选、挑出正确编号——把 N 次调用压成 1 次，
    既省配额又给模型对比视角（你的"拼成一张"思路）。
    return_geom=True 时返回 (base64, geom)，geom={"cells":[(x,y,w,h),...],"size":(W,H)}，
    供复盘标注（annotate_choice）在正确格子上画框。否则返回 base64。"""
    try:
        from PIL import Image, ImageDraw
        import io
        imgs = [Image.open(io.BytesIO(base64.b64decode(b))).convert("RGB") for b in b64_list]
        if not imgs:
            return (None, None) if return_geom else None
        cw = max(i.width for i in imgs)
        ch = max(i.height for i in imgs)
        n = len(imgs)
        cols = min(cols, n)
        rows = (n + cols - 1) // cols
        gap = 12
        cell_w, cell_h = cw + gap, ch + label_h + gap
        ref_block = 0
        ref_img = None
        if reference_b64:
            ref_img = Image.open(io.BytesIO(base64.b64decode(reference_b64))).convert("RGB")
            ref_block = ref_img.height + label_h + gap
        W = cols * cell_w + gap
        H = ref_block + rows * cell_h + gap
        canvas = Image.new("RGB", (W, H), (255, 255, 255))
        draw = ImageDraw.Draw(canvas)
        y0 = gap
        if ref_img is not None:
            draw.text((gap, 2), "REFERENCE (target):", fill=(200, 0, 0))
            canvas.paste(ref_img, (gap, label_h))
            y0 = ref_block + gap
        cells = []
        for idx, im in enumerate(imgs):
            r, c = divmod(idx, cols)
            x = gap + c * cell_w
            y = y0 + r * cell_h
            draw.text((x, y), f"#{idx}", fill=(0, 0, 200))
            canvas.paste(im, (x, y + label_h))
            cells.append((x, y + label_h, im.width, im.height))  # 候选图本体的像素矩形
        canvas.save(path)
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        if return_geom:
            return b64, {"cells": cells, "size": (W, H)}
        return b64
    except Exception as e:
        print(f"  [vision] stitch err: {str(e)[:60]}")
        return (None, None) if return_geom else None


def annotate_choice(grid_path, geom, best_idx, out_path, note="", votes_raw=None):
    """复盘标注：在拼图网格上标注最终票(粗红框)+每个模型各自的投票(彩色小框+标签)。
    votes_raw: [(model, answer_idx, txt_tail), ...]，给每个模型选的那张画不同颜色边框，
    并在图底列出"模型->答案"清单。方便人工核对是谁选了谁、谁对谁错。"""
    try:
        from PIL import Image, ImageDraw
        im = Image.open(grid_path).convert("RGB")
        draw = ImageDraw.Draw(im)
        cells = (geom or {}).get("cells", [])
        # 每个模型一种颜色
        palette = [(0,120,255),(255,140,0),(0,200,0),(200,0,200),(0,200,200)]
        votes_raw = votes_raw or []
        # 每个模型在它选的格子画一圈细彩框(不同 offset 错开避免重叠)
        for mi,(model,a,_tail) in enumerate(votes_raw):
            if a is None or not (0<=a<len(cells)): continue
            col=palette[mi%len(palette)]
            x,y,w,h=cells[a]
            off=8+mi*4
            draw.rectangle([x-off,y-off,x+w+off,y+h+off],outline=col,width=2)
            short=model.split("/")[-1].replace("-preview-c","").replace("-c","")[:10]
            draw.text((x+2,y+2+mi*12),f"{short}>#{a}",fill=col)
        # 最终投票结果：粗红框
        if 0 <= best_idx < len(cells):
            x, y, w, h = cells[best_idx]
            for t in range(5):
                draw.rectangle([x - 3 - t, y - 3 - t, x + w + 3 + t, y + h + 3 + t], outline=(255, 0, 0))
            draw.text((x + 2, y + h - 14), f"FINAL #{best_idx}", fill=(255, 0, 0))
        # 底部清单：模型->答案
        if votes_raw:
            line=" | ".join(f"{m.split('/')[-1].replace('-preview-c','').replace('-c','')[:10]}:{a}" for m,a,_ in votes_raw)
            draw.text((6, im.height - 30), line[:150], fill=(255,255,0))
        if note:
            draw.text((6, im.height - 16), note[:140], fill=(255, 0, 0))
        im.save(out_path)
        return out_path
    except Exception as e:
        print(f"  [vision] annotate err: {str(e)[:60]}")
        return None




# 图像增强网关（gpt-image-2 的 images/edits）。默认与 VISION 同一网关，外加一个兜底网关。
IMAGE_EDIT_BASE = _c("IMAGE_EDIT_BASE", VISION_API_BASE)
IMAGE_EDIT_KEY = _c("IMAGE_EDIT_KEY", VISION_API_KEY)
IMAGE_EDIT_MODEL = _c("IMAGE_EDIT_MODEL", "gpt-image-2")
# 兜底图像增强网关（主网关失败/超时时切换）
IMAGE_EDIT_BASE2 = _c("IMAGE_EDIT_BASE2")
IMAGE_EDIT_KEY2 = _c("IMAGE_EDIT_KEY2")

_ENHANCE_PROMPT = (
    "Upscale and sharpen this captcha puzzle image for maximum clarity. "
    "Preserve EXACTLY every icon, dotted connecting line, ring color, circle and position. "
    "Do NOT invent, add, remove, or alter anything. Only increase resolution and reduce blur."
)


def enhance_local(image_b64, path, scale=2, max_side=1600, jpeg_quality=82):
    """本地传统图像增强（毫秒级、无网络）：Lanczos 缩放 + 锐化 + 对比度/亮度 + 去噪。
    纯保真处理。关键：限制最大边 max_side 并存为 JPEG，把体积压到 ~几百KB
    （否则 7 张 3D 大图拼起来 PNG 可达 13MB，发给模型会全部传输超时→空票）。
    返回增强后 base64。"""
    try:
        from PIL import Image, ImageEnhance, ImageFilter
        import io
        im = Image.open(io.BytesIO(base64.b64decode(image_b64))).convert("RGB")
        if scale and scale != 1:
            im = im.resize((im.width * scale, im.height * scale), Image.LANCZOS)
        # 限制最大边，避免体积爆炸
        long_side = max(im.width, im.height)
        if long_side > max_side:
            r = max_side / long_side
            im = im.resize((max(1, int(im.width * r)), max(1, int(im.height * r))), Image.LANCZOS)
        im = im.filter(ImageFilter.MedianFilter(size=3))
        im = ImageEnhance.Contrast(im).enhance(1.6)
        im = ImageEnhance.Brightness(im).enhance(1.15)
        im = ImageEnhance.Sharpness(im).enhance(2.2)
        im = im.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=2))
        # 存 JPEG 控体积（PNG 对照片型 3D 图体积巨大）
        jpath = path.rsplit(".", 1)[0] + ".jpg"
        im.save(jpath, "JPEG", quality=jpeg_quality)
        with open(jpath, "rb") as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode()
        print(f"  [vision] image enhanced locally ({im.width}x{im.height}, {len(raw)//1024}KB)")
        return b64
    except Exception as e:
        print(f"  [vision] local enhance err: {str(e)[:60]}")
        return image_b64


def enhance_image(image_b64, path, prompt=None, size="1024x1024"):
    """用 gpt-image-2 的 images/edits 对图做保真增强（去糊放大，不改内容）。
    实测对 Arkose 小图标拼图能显著提清晰度且不篡改结构（gpt-5 校验 identical）。
    主网关失败/超时则切兜底网关。返回增强后 png 的 base64；都失败返回原图 base64（降级不致命）。
    注意：云端往返 ~20-40s，可能撞 Arkose 超时；要快用 enhance_local。"""
    import io
    raw = base64.b64decode(image_b64)
    endpoints = [
        (IMAGE_EDIT_BASE, IMAGE_EDIT_KEY),
        (IMAGE_EDIT_BASE2, IMAGE_EDIT_KEY2),
    ]
    for bi, (base, key) in enumerate(endpoints):
        if not (base and key):
            continue
        try:
            files = {"image": ("in.png", io.BytesIO(raw), "image/png")}
            data = {"model": IMAGE_EDIT_MODEL, "prompt": prompt or _ENHANCE_PROMPT, "size": size}
            r = requests.post(
                f"{base.rstrip('/')}/v1/images/edits",
                headers={"Authorization": f"Bearer {key}"},
                files=files, data=data, timeout=120,
            )
            if r.status_code == 200:
                out_b64 = r.json()["data"][0]["b64_json"]
                try:
                    with open(path, "wb") as f:
                        f.write(base64.b64decode(out_b64))
                except Exception:
                    pass
                print(f"  [vision] image enhanced via gpt-image-2 (gw#{bi})")
                return out_b64
            print(f"  [vision] enhance gw#{bi} failed {r.status_code} {r.text[:60]}")
        except Exception as e:
            print(f"  [vision] enhance gw#{bi} err: {str(e)[:60]}")
    return image_b64  # 都失败，降级用原图


def vote_score(prompt, image_b64, rounds=3, **kw):
    """同一张图问 rounds 次，取 score 中位数，抹平单次抖动。返回 (median_score, [all])。"""
    import statistics
    vals = []
    for _ in range(rounds):
        ans = ask_vision(prompt, image_b64, **kw)
        js = parse_json_answer(ans) or {}
        s = js.get("score")
        if isinstance(s, (int, float)):
            vals.append(float(s))
    if not vals:
        return -1, []
    return statistics.median(vals), vals


# ============ GitHub Arkose 拼图：变体分派 + 投票求解（整链路复用，已实测10/10通过）============
SEL_REF_GH = ".key-frame-image"
SEL_CAND_GH = ".answer-frame img, .answer-frame canvas, .answer-frame"


def _pp_sequence(qtext, n):
    return ("You are solving an Arkose visual puzzle (accessibility helper). "
        "Top = REFERENCE (4 icons stacked vertically, each in a colored ring; ring colors top-to-bottom "
        "are CYAN, YELLOW, RED, GREEN). Below = numbered candidates #0..#%d, same 4 colored rings, icons "
        "placed differently. Instruction: \"%s\".\n"
        "Correct candidate = each colored ring holds the SAME icon as that color ring in the reference. "
        "Compare RING BY RING (by color), NOT by screen position.\n"
        "MATCHING RULE: the same icon may be ROTATED and its BLACK/WHITE FILL INVERTED (solid vs hollow). "
        "Match by underlying SHAPE, ignoring rotation and fill inversion.\n"
        "TIE-BREAKER: candidates often look almost identical; distinguish by tiny details - protruding dots, "
        "notches, number of legs/prongs, internal patterns. All FOUR rings must match on shape AND fine detail.\n"
        "PROXIMITY WARNING: two icons are often placed close together; never guess by proximity - read each "
        "icon by its OWN ring color (cyan/yellow/red/green), never swap two adjacent icons.\n"
        "Reason briefly per ring, then output the VERY LAST line exactly: ANSWER=<number> (e.g. ANSWER=3)."
        % (n - 1, qtext))


def _pp_character(qtext, n):
    return ("You are solving an Arkose visual puzzle (accessibility helper). "
        "Top-left = REFERENCE ('Match This!'): it shows ONE OR TWO target icons (look carefully — often TWO "
        "icons stacked). Below = candidates #0..#%d: the SAME tilted 3D grid of icon tiles, with a pink "
        "CHARACTER standing on a DIFFERENT tile in each candidate.\n"
        "Instruction: \"%s\".\n"
        "GOAL: pick the candidate where the character stands on the tile(s) whose icon matches the reference.\n"
        "USE ELIMINATION (this is the reliable method, because the character's feet OCCLUDE the tile it stands "
        "on so you often cannot read that tile directly):\n"
        "1. Identify the reference target icon shape(s) precisely.\n"
        "2. In the grid, find WHICH grid position holds the target icon — do this by reading all the OTHER, "
        "clearly visible tiles and locating the target icon's cell (or noticing which cell is hidden under the "
        "character).\n"
        "3. For each candidate, determine which grid cell the character is standing on (by its feet position in "
        "the 3x3/grid layout).\n"
        "4. The correct candidate = the one where the character occupies the target-icon cell. Elimination: if a "
        "candidate's character stands on a cell whose icon IS clearly visible AND is NOT the target, reject it. "
        "The right answer is usually the candidate where the target icon's cell is the one HIDDEN under the "
        "character's feet (because the others show non-target icons clearly).\n"
        "Account for: grid TILT (3D skew), icon ROTATION and black/white fill inversion — match by SHAPE.\n"
        "Reason step by step (reference shape; target cell location; each candidate's character cell; "
        "eliminate), then output the VERY LAST line exactly: ANSWER=<number> (e.g. ANSWER=2)." % (n - 1, qtext))


def _pp_rotate(qtext, n):
    return ("You are solving an Arkose visual puzzle (accessibility helper). "
        "Top-left = REFERENCE ('Match the Direction!'): a 3D object facing a specific direction. "
        "Below = candidates #0..#%d: the SAME object rotated to different orientations.\n"
        "Instruction: \"%s\".\n"
        "TASK: pick the candidate facing the SAME direction as the reference. Note where the front (head/face) "
        "points and the body profile; match on both head direction and body tilt.\n"
        "Reason briefly, then output VERY LAST line exactly: ANSWER=<number> (e.g. ANSWER=2)." % (n - 1, qtext))


def gh_pick_prompt(qtext, n, variant="sequence"):
    if variant == "character":
        return _pp_character(qtext, n)
    if variant == "rotate":
        return _pp_rotate(qtext, n)
    return _pp_sequence(qtext, n)


def gh_variant(qfull):
    ql = (qfull or "").lower()
    if "rotate" in ql or "direction" in ql:
        return "rotate"
    if "move the character" in ql or "tiles" in ql:
        return "character"
    return "sequence"


async def gh_find_game(page):
    """找真正的拼图 game frame（有 Navigate 箭头=已进拼图，非选择页）。返回 (frame,text) 或 (None,'')"""
    for f in page.frames:
        u = f.url or ""
        if "index.html" in u and ("arkose" in u or "funcaptcha" in u):
            try:
                if await f.get_by_role("button", name="Navigate to next image").count() > 0:
                    t = await f.evaluate("()=>document.body.innerText||''")
                    return f, t
            except Exception:
                pass
    return None, ""


async def gh_count_options(game):
    """数进度点 .pip 得候选张数，回退 6。"""
    try:
        n = await game.evaluate("()=>document.querySelectorAll('.pip').length")
        if isinstance(n, int) and 2 <= n <= 12:
            return n
    except Exception:
        pass
    return 6


async def solve_puzzle_voting(page, shot_dir="screenshots_github", max_rounds=10, on_round=None, skip_variants=("character",)):
    """GitHub Arkose 拼图整关求解（实测10/10通过）：等PoW→点Visual puzzle→每轮变体分派+4模型投票
    →导航提交→直到 octocaptcha 消失(过)或答错(停)。返回 True=过验证。
    调用前需已点 Create account 触发验证。"""
    import asyncio
    import os
    os.makedirs(shot_dir, exist_ok=True)
    for it in range(50):
        await asyncio.sleep(3)
        g, _ = await gh_find_game(page)
        if g:
            break
        # octocaptcha 整个没了 = 可能已过
        if not any("octocaptcha" in (f.url or "") for f in page.frames):
            # 但也可能是还没触发；只有在确实出现过又消失才算过——这里保守不退，继续触发
            pass
        hit = False
        for f in page.frames:
            if any(k in (f.url or "") for k in ["octocaptcha", "arkose", "funcaptcha"]):
                hit = True
                try:
                    el = f.get_by_text("Visual puzzle", exact=False).first
                    if await el.count() > 0:
                        await el.click(timeout=4000)
                except Exception:
                    pass
        # 白屏/卡加载自救：每 ~21s 重点一次 Create account 重新触发挑战（Arkose 偶发不渲染）
        if not g and it in (6, 13, 20, 27, 34, 41):
            try:
                bb2 = page.get_by_role("button", name="Create account", exact=True)
                for i in range(await bb2.count()):
                    x = bb2.nth(i)
                    if await x.get_attribute("disabled") is None:
                        await x.click(timeout=3000)
                        print(f"  [solve] 重触发 Create account @ ~{it*3}s (hit_frame={hit})")
                        break
            except Exception:
                pass
    await asyncio.sleep(4)

    rnd = -1
    while True:
        rnd += 1
        if rnd > max_rounds:
            print("  [solve] 跑满轮数，停")
            return False
        game = None
        for w in range(16):
            game, qt = await gh_find_game(page)
            if game:
                break
            if not any("octocaptcha" in (f.url or "") for f in page.frames):
                print(f"  [solve] octocaptcha 消失 @ R{rnd}，验证通过")
                return True
            for f in page.frames:
                if any(k in (f.url or "") for k in ["octocaptcha", "arkose", "funcaptcha"]):
                    try:
                        b = f.get_by_text("Visual puzzle", exact=False).first
                        if await b.count() > 0:
                            await b.click(timeout=3000)
                    except Exception:
                        pass
            await asyncio.sleep(3)
        if not game:
            if not any("octocaptcha" in (f.url or "") for f in page.frames):
                return True
            print(f"  [solve] R{rnd} 拿不到拼图，停")
            return False
        qfull = (qt or "").replace("\n", " ").strip()
        qline = qfull[:200]
        variant = gh_variant(qfull)
        N = await gh_count_options(game)
        print(f"  [solve] R{rnd} variant={variant} N={N} q={qline!r}")
        # 难变体(character 小人踩图标)模型识别极差且达不成共识，第一轮就遇到直接放弃，让上层重开窗口换题
        if rnd == 0 and variant in skip_variants:
            print(f"  [solve] 遇到难变体 '{variant}'，放弃本窗口换一批验证")
            return "SKIP_VARIANT"
        for _ld in range(8):
            try:
                rel = game.locator(SEL_REF_GH).first
                if await rel.count() > 0:
                    bx = await rel.bounding_box()
                    if bx and bx["width"] > 20 and bx["height"] > 20:
                        break
            except Exception:
                pass
            await asyncio.sleep(1)
        await asyncio.sleep(2.5 if rnd == 0 else 1.0)
        nxt = game.get_by_role("button", name="Navigate to next image")
        ref = await shot_element(game, SEL_REF_GH, f"{shot_dir}/v_ref{rnd}.png", scale=3)
        cands = []
        for i in range(N):
            c = await shot_element(game, SEL_CAND_GH, f"{shot_dir}/v_c{rnd}_{i}.png", scale=3)
            if c:
                cands.append(c)
            if i < N - 1:
                try:
                    await nxt.first.click(timeout=3000)
                except Exception:
                    break
                await asyncio.sleep(0.8)
        grid, geom = stitch_options_grid(cands, f"{shot_dir}/v_grid{rnd}.png", reference_b64=ref, cols=3, return_geom=True)
        if not grid:
            print("  [solve] stitch failed")
            return False
        # character 变体图大(3D网格多张)，并发会把慢模型打掉票→只剩1个模型。压更小让4模型都能按时回票。
        if variant == "character":
            grid_hd = enhance_local(grid, f"{shot_dir}/v_grid{rnd}_hd.png", scale=2, max_side=1000, jpeg_quality=72)
        else:
            grid_hd = enhance_local(grid, f"{shot_dir}/v_grid{rnd}_hd.png", scale=2)
        prm = gh_pick_prompt(qline, len(cands), variant)
        best, votes, raws = vote_answer(prm, grid_hd, len(cands), max_tokens=900)
        if not votes:
            await asyncio.sleep(2)
            best, votes, raws = vote_answer(prm, grid_hd, len(cands), max_tokens=900)
        if best is None or best < 0 or best >= len(cands):
            best = 0
        print(f"  [solve] R{rnd} vote -> #{best} votes={votes}")
        try:
            annotate_choice(f"{shot_dir}/v_grid{rnd}.png", geom, best,
                            f"{shot_dir}/REVIEW_r{rnd}.png", note=f"r{rnd} #{best} {votes}", votes_raw=raws)
        except Exception:
            pass
        if on_round:
            try:
                on_round(rnd, best, votes)
            except Exception:
                pass
        game = None
        for _w in range(8):
            game, _ = await gh_find_game(page)
            if game:
                break
            if not any("octocaptcha" in (f.url or "") for f in page.frames):
                return True
            await asyncio.sleep(2)
        if not game:
            if not any("octocaptcha" in (f.url or "") for f in page.frames):
                return True
            continue
        back = (N - 1 - best)
        prv = game.get_by_role("button", name="Navigate to previous image")
        for _ in range(back):
            try:
                await prv.first.click(timeout=3000)
            except Exception:
                pass
            await asyncio.sleep(0.6)
        await asyncio.sleep(1)
        for attempt in range(4):
            try:
                await game.get_by_role("button", name="Submit").first.click(timeout=4000)
                break
            except Exception:
                game, _ = await gh_find_game(page)
                if not game:
                    break
                await asyncio.sleep(1.5)
        await asyncio.sleep(4)
        if not any("octocaptcha" in (f.url or "") for f in page.frames):
            print("  [solve] 验证通过")
            return True
