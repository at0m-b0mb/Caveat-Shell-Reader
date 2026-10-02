#!/usr/bin/env python3
"""
Repository art — the social card, the README banner, and the contact sheet.

Three surfaces, three sets of rules, all drawn from the same palette as the
application so the repo and the app read as one thing:

* **social-preview.png** — 1280x640, with GitHub's 40pt (80px) safe border.
  Every piece of information is registered with a :class:`SafeBox` as it is
  drawn, and ``check()`` refuses to write a file that crosses the border. The
  signature pipeline is redrawn here from a real sample's reading, so the card
  carries the product's own output rather than an illustration of it.
* **banner.png / banner-dark.png** — 2560x800, a light/dark pair for a README
  ``<picture>``. A banner is never cropped, so its gold band may bleed.
* **screens.png / screens-dark.png** — a contact sheet of real, off-screen
  captures, one sheet per theme so neither README background gets a glaring
  slab.

Run ``python tools/capture_screenshots.py`` first; the contact sheet needs
those PNGs.
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMG = os.path.join(ROOT, "images")

SERIF = "/System/Library/Fonts/Supplemental/Iowan Old Style.ttc"
SANS = "/System/Library/Fonts/SFNS.ttf"
MONO = "/System/Library/Fonts/Menlo.ttc"

# palette, straight from caveat.ui.theme
PAPER = "#F3F1EC"
SURFACE = "#FFFFFF"
INK = "#1B1813"
INK_MUTED = "#575144"
INK_FAINT = "#847D6E"
RULE = "#DCD6C9"
RULE_STRONG = "#C4BCAA"
BRASS = "#7A5D18"
SHINE = "#C39B24"
GREEN = "#2C6249"
RED = "#8C1F16"
RED_WASH = "#FBE9E7"

BLACK = "#000000"
D_SURFACE = "#131312"
D_INK = "#F3F0E9"
D_MUTED = "#A29C91"
D_FAINT = "#6B675F"
D_RULE = "#2B2B28"
D_RULE_STRONG = "#3D3C38"
D_BRASS = "#D9B75C"
D_SHINE = "#F1C84B"
D_GREEN = "#67BE94"
D_RED = "#EE8B82"
D_RED_WASH = "#2A100E"


def font(path: str, size: int, index: int = 0) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size, index=index)


class SafeBox:
    """Registers every meaningful rectangle and reports the tightest margin.

    Background art is simply never registered, so it is free to bleed; only the
    things a crop must not eat — wordmark, tagline, pitch, URL, the pipeline
    panel — are handed to :meth:`add`.
    """

    def __init__(self, w: int, h: int, safe: int):
        self.w, self.h, self.safe = w, h, safe
        self.rects: list[tuple[str, tuple[int, int, int, int]]] = []

    def add(self, name: str, box: tuple[float, float, float, float]) -> None:
        self.rects.append((name, tuple(int(round(v)) for v in box)))

    def check(self) -> None:
        worst = None
        for name, (left, top, right, bottom) in self.rects:
            margin = min(left, top, self.w - right, self.h - bottom)
            if worst is None or margin < worst[0]:
                worst = (margin, name, (left, top, right, bottom))
        if worst is None:
            return
        margin, name, box = worst
        assert margin >= self.safe, (
            f"{name} at {box} leaves a {margin}px margin on a {self.w}x{self.h} "
            f"canvas; the safe border needs {self.safe}px.")
        print(f"  safe border ok — tightest: {name} at {margin}px "
              f"(need {self.safe})")


def _text(draw, xy, s, fnt, fill, ls=0, anchor="la"):
    """Draw text, optionally letter-spaced, and return its pixel width."""
    if ls == 0:
        draw.text(xy, s, font=fnt, fill=fill, anchor=anchor)
        left, _, right, _ = draw.textbbox(xy, s, font=fnt, anchor=anchor)
        return right - left
    x, y = xy
    for ch in s:
        draw.text((x, y), ch, font=fnt, fill=fill, anchor="la")
        x += draw.textbbox((0, 0), ch, font=fnt)[2] + ls
    return x - xy[0] - ls


def _round_rect(draw, box, radius, fill=None, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline,
                           width=width)


# --- the pipeline motif, redrawn from a real reading --------------------------
# These are the exact values Caveat produces for samples/install-script.sh.
_STAGES = [
    ("curl", "download a URL, or send", "a request to one", "", False),
    ("bash", "run shell commands", "", "ROOT · UNREAD", True),
]
_FLOW = "STDOUT"
_SOURCE = "curl -fsSL https://example.com/i.sh | sudo bash"
_VERDICT = "RISKY"
_HEADLINE = "downloaded code is piped straight into a shell"


def _draw_pipeline(draw, box, pal, ss):
    """Draw the motif: the line as it was pasted, the stages, the verdict."""
    x0, y0, x1, y1 = box
    _round_rect(draw, box, 10 * ss, fill=pal["surface"], outline=pal["rule"],
                width=max(1, ss))

    pad = 20 * ss
    f_source = font(MONO, 13 * ss)
    f_cmd = font(MONO, 21 * ss, index=1)
    f_role = font(SANS, 13 * ss)
    f_mark = font(SANS, 10 * ss)
    f_flow = font(SANS, 11 * ss)
    f_verdict = font(SANS, 14 * ss, index=0)

    _text(draw, (x0 + pad, y0 + 18 * ss), _SOURCE, f_source, pal["muted"])

    arrow_w = 74 * ss
    inner = (x1 - x0) - pad * 2
    box_w = (inner - arrow_w) / 2
    box_h = 104 * ss
    top = y0 + 56 * ss

    rule_y = top + box_h + 36 * ss
    draw.line([(x0 + pad, rule_y), (x1 - pad, rule_y)], fill=pal["rule"],
              width=max(1, ss))
    v_w = _text(draw, (x0 + pad, rule_y + 18 * ss), _VERDICT, f_verdict,
                pal["red"], ls=2 * ss)
    _text(draw, (x0 + pad + v_w + 14 * ss, rule_y + 19 * ss), _HEADLINE,
          f_role, pal["muted"])

    for index, (cmd, role_a, role_b, mark, alert) in enumerate(_STAGES):
        bx = x0 + pad + index * (box_w + arrow_w)
        accent = pal["red"] if alert else pal["green"]
        fill = pal["red_wash"] if alert else pal["surface"]
        rect = (bx, top, bx + box_w, top + box_h)
        _round_rect(draw, rect, 7 * ss, fill=fill, outline=accent,
                    width=2 * ss if alert else max(1, ss))
        draw.rounded_rectangle((bx + 2 * ss, top + 2 * ss, bx + 5 * ss,
                                top + box_h - 2 * ss), radius=2 * ss,
                               fill=accent)

        tx = bx + 15 * ss
        _text(draw, (tx, top + 11 * ss), f"STAGE {index + 1}", f_mark,
              pal["faint"], ls=ss)
        if mark:
            pill_w = 92 * ss
            pill = (bx + box_w - 11 * ss - pill_w, top + 8 * ss,
                    bx + box_w - 11 * ss, top + 24 * ss)
            _round_rect(draw, pill, 3 * ss, fill=pal["brass"])
            draw.text(((pill[0] + pill[2]) / 2, (pill[1] + pill[3]) / 2), mark,
                      font=f_mark, fill=pal["bg"], anchor="mm")
        _text(draw, (tx, top + 33 * ss), cmd, f_cmd, pal["ink"])
        _text(draw, (tx, top + 64 * ss), role_a, f_role, pal["muted"])
        if role_b:
            _text(draw, (tx, top + 82 * ss), role_b, f_role, pal["muted"])

        if index == 0:
            ay = top + box_h / 2
            ax0 = bx + box_w + 9 * ss
            ax1 = bx + box_w + arrow_w - 9 * ss
            draw.line([(ax0, ay), (ax1 - 5 * ss, ay)], fill=pal["rule_strong"],
                      width=2 * ss)
            draw.polygon([(ax1, ay), (ax1 - 7 * ss, ay - 5 * ss),
                          (ax1 - 7 * ss, ay + 5 * ss)], fill=pal["rule_strong"])
            draw.text(((ax0 + ax1) / 2, ay - 15 * ss), _FLOW, font=f_flow,
                      fill=pal["brass"], anchor="mm")


def _pal(dark: bool) -> dict:
    if dark:
        return dict(bg=BLACK, surface=D_SURFACE, ink=D_INK, muted=D_MUTED,
                    faint=D_FAINT, rule=D_RULE, rule_strong=D_RULE_STRONG,
                    brass=D_BRASS, shine=D_SHINE, green=D_GREEN, red=D_RED,
                    red_wash=D_RED_WASH)
    return dict(bg=PAPER, surface=SURFACE, ink=INK, muted=INK_MUTED,
                faint=INK_FAINT, rule=RULE, rule_strong=RULE_STRONG,
                brass=BRASS, shine=SHINE, green=GREEN, red=RED,
                red_wash=RED_WASH)


# --- social card --------------------------------------------------------------

def render_card(path: str, dark: bool = False) -> None:
    W, H, SS, SAFE = 1280, 640, 2, 80
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)
    box = SafeBox(W * SS, H * SS, SAFE * SS)
    margin = 96 * SS  # author at 96, assert at 80

    lx = margin
    f_mark = font(SERIF, 84 * SS)
    wordmark_w = _text(d, (lx, 148 * SS), "CAVEAT", f_mark, pal["ink"])
    box.add("wordmark", (lx, 148 * SS, lx + wordmark_w, 148 * SS + 84 * SS))
    d.line([(lx, 254 * SS), (lx + wordmark_w, 254 * SS)], fill=pal["brass"],
           width=3 * SS)

    f_tag = font(SANS, 19 * SS)
    tag_w = _text(d, (lx, 274 * SS), "READ BEFORE YOU RUN", f_tag, pal["faint"],
                  ls=4 * SS)
    box.add("tagline", (lx, 274 * SS, lx + tag_w, 274 * SS + 24 * SS))

    f_pitch = font(SERIF, 35 * SS)
    d.text((lx, 326 * SS), "Know what a line does", font=f_pitch, fill=pal["ink"])
    d.text((lx, 370 * SS), "before you paste it.", font=f_pitch, fill=pal["ink"])
    box.add("pitch", (lx, 326 * SS, lx + 420 * SS, 370 * SS + 40 * SS))

    f_sub = font(SANS, 17 * SS)
    subs = ["Splits a command into stages, explains each one,",
            "names the risks — and never runs a thing."]
    for i, line in enumerate(subs):
        d.text((lx, (436 + i * 25) * SS), line, font=f_sub, fill=pal["muted"])
    box.add("sub", (lx, 436 * SS, lx + 430 * SS, (436 + 2 * 25) * SS))

    f_url = font(MONO, 16 * SS)
    url_w = _text(d, (lx, 508 * SS), "github.com/at0m-b0mb/Caveat", f_url,
                  pal["brass"])
    box.add("url", (lx, 508 * SS, lx + url_w, 508 * SS + 20 * SS))

    panel = (648 * SS, 180 * SS, (W - 96) * SS, 452 * SS)
    _draw_pipeline(d, panel, pal, SS)
    box.add("pipeline", panel)

    box.check()
    im = im.resize((W, H), Image.LANCZOS)
    im.save(path)
    _assert_safe_border(path, SAFE, pal["bg"])
    print(f"wrote {os.path.relpath(path, ROOT)}")


def _assert_safe_border(path: str, margin: int, bg_hex: str) -> None:
    """Measure the rendered PNG: no non-background ink inside the border."""
    im = Image.open(path).convert("RGB")
    W, H = im.size
    px = im.load()
    bg = tuple(int(bg_hex.lstrip("#")[i:i + 2], 16) for i in (0, 2, 4))

    def near(colour):
        return all(abs(colour[i] - bg[i]) <= 6 for i in range(3))

    points = [(x, y) for y in range(0, H, 2) for x in range(0, W, 2)
              if not near(px[x, y])]
    if not points:
        return
    left = min(p[0] for p in points)
    right = max(p[0] for p in points)
    top = min(p[1] for p in points)
    bottom = max(p[1] for p in points)
    tightest = min(left, W - 1 - right, top, H - 1 - bottom)
    assert tightest >= margin, (
        f"content reaches {tightest}px from the edge (need {margin})")
    print(f"  measured card margins: L{left} R{W - 1 - right} T{top} "
          f"B{H - 1 - bottom} — ok")


# --- banner -------------------------------------------------------------------

def render_banner(path: str, dark: bool = False) -> None:
    W, H, SS = 1280, 400, 2
    pal = _pal(dark)
    im = Image.new("RGB", (W * SS, H * SS), pal["bg"])
    d = ImageDraw.Draw(im)

    # a gold band that may bleed to the right edge
    d.rectangle([(W - 150) * SS, 0, W * SS, H * SS], fill=pal["brass"])
    d.rectangle([(W - 156) * SS, 0, (W - 150) * SS, H * SS], fill=pal["shine"])

    lx = 80 * SS
    f_mark = font(SERIF, 96 * SS)
    _text(d, (lx, 116 * SS), "CAVEAT", f_mark, pal["ink"])
    d.line([(lx, 240 * SS), (lx + 372 * SS, 240 * SS)], fill=pal["brass"],
           width=3 * SS)
    f_tag = font(SANS, 21 * SS)
    _text(d, (lx, 260 * SS), "READ BEFORE YOU RUN", f_tag, pal["faint"],
          ls=5 * SS)
    f_sub = font(SANS, 20 * SS)
    d.text((lx, 300 * SS), "An offline reader for shell commands.",
           font=f_sub, fill=pal["muted"])
    d.text((lx, 331 * SS), "Every stage explained, every risk named.",
           font=f_sub, fill=pal["muted"])

    panel = (548 * SS, 62 * SS, (W - 174) * SS, 334 * SS)
    _draw_pipeline(d, panel, pal, SS)

    im.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({im.size[0]}x{im.size[1]})")


# --- contact sheet ------------------------------------------------------------

def render_contact_sheet(path: str, shots: list[str], dark: bool = False) -> None:
    pal = _pal(dark)
    loaded = []
    for name in shots:
        full = os.path.join(IMG, name)
        if os.path.exists(full):
            loaded.append(Image.open(full).convert("RGB"))
    if not loaded:
        print(f"  (no screenshots for {os.path.basename(path)} — "
              f"run capture first)")
        return

    gap, pad, scale_w = 28, 40, 560
    thumbs = []
    for im in loaded:
        height = int(im.height * scale_w / im.width)
        thumbs.append(im.resize((scale_w, height), Image.LANCZOS))
    sheet_w = pad * 2 + scale_w * len(thumbs) + gap * (len(thumbs) - 1)
    sheet_h = pad * 2 + max(t.height for t in thumbs)
    sheet = Image.new("RGB", (sheet_w, sheet_h), pal["bg"])
    d = ImageDraw.Draw(sheet)
    x = pad
    for thumb in thumbs:
        sheet.paste(thumb, (x, pad))
        d.rectangle([x, pad, x + thumb.width - 1, pad + thumb.height - 1],
                    outline=pal["rule"], width=1)
        x += thumb.width + gap
    sheet.save(path)
    print(f"wrote {os.path.relpath(path, ROOT)}  ({sheet_w}x{sheet_h})")


def main() -> int:
    os.makedirs(IMG, exist_ok=True)
    print("social card:")
    render_card(os.path.join(IMG, "social-preview.png"), dark=False)
    print("banner (light + dark):")
    render_banner(os.path.join(IMG, "banner.png"), dark=False)
    render_banner(os.path.join(IMG, "banner-dark.png"), dark=True)
    print("contact sheet (light + dark):")
    render_contact_sheet(os.path.join(IMG, "screens.png"),
                         ["shot-install-script-light.png",
                          "shot-log-triage-light.png"], dark=False)
    render_contact_sheet(os.path.join(IMG, "screens-dark.png"),
                         ["shot-install-script-dark.png",
                          "shot-log-triage-dark.png"], dark=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
