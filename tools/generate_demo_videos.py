from __future__ import annotations

import math
import sys
from pathlib import Path

import imageio.v2 as imageio
import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "web" / "assets" / "demo"
WALLPAPER_DIR = ROOT / "assets" / "wallpaper"
MARK_PATH = ROOT / "web" / "assets" / "wins-vpn-mark.webp"
CALC_ICON = ROOT / "assets" / "icon" / "ic_calculator.png"
WIDTH, HEIGHT = 1280, 720
FPS = 24
DURATION = 23.0


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    for path in [
        Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf"),
        Path("/System/Library/Fonts/SFNS.ttf"),
        Path("C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"),
        Path("C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf"),
    ]:
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


F = {
    "hero": font(40, True),
    "title": font(27, True),
    "subtitle": font(20),
    "body": font(17),
    "small": font(13),
    "tiny": font(11),
    "button": font(17, True),
    "calc": font(30),
}


def fit_cover(path: Path, size: tuple[int, int]) -> Image.Image:
    img = Image.open(path).convert("RGB")
    scale = max(size[0] / img.width, size[1] / img.height)
    img = img.resize((int(img.width * scale), int(img.height * scale)), Image.Resampling.LANCZOS)
    x = (img.width - size[0]) // 2
    y = (img.height - size[1]) // 2
    return img.crop((x, y, x + size[0], y + size[1]))


def bg(scene: str = "singapore") -> Image.Image:
    path = WALLPAPER_DIR / f"{scene}.webp"
    if not path.exists():
        path = WALLPAPER_DIR / "default.webp"
    image = fit_cover(path, (WIDTH, HEIGHT)).filter(ImageFilter.GaussianBlur(1.1))
    tint = Image.new("RGB", (WIDTH, HEIGHT), "#07111f")
    return Image.blend(image, tint, 0.45)


def rr(draw: ImageDraw.ImageDraw, box, r: int, fill, outline=None, width: int = 1):
    draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)


def text(draw: ImageDraw.ImageDraw, xy, s: str, style="body", fill="#ffffff", anchor=None):
    draw.text(xy, s, font=F[style], fill=fill, anchor=anchor)


def multiline_text(draw: ImageDraw.ImageDraw, xy, s: str, max_chars: int, style="body", fill="#ffffff", line_gap=8):
    x, y = xy
    line_height = F[style].size + line_gap
    for idx, line in enumerate(wrap(s, max_chars)):
        text(draw, (x, y + idx * line_height), line, style, fill)


def centered_multiline_text(draw: ImageDraw.ImageDraw, xy, s: str, max_chars: int, style="body", fill="#ffffff", line_gap=8):
    x, y = xy
    line_height = F[style].size + line_gap
    lines = wrap(s, max_chars)
    for idx, line in enumerate(lines):
        text(draw, (x, y + idx * line_height), line, style, fill, "ma")


def paste_rgba(base: Image.Image, overlay: Image.Image, xy: tuple[int, int]):
    base.paste(overlay, xy, overlay if overlay.mode == "RGBA" else None)


def ease(t: float, start: float, end: float) -> float:
    if t <= start:
        return 0.0
    if t >= end:
        return 1.0
    x = (t - start) / (end - start)
    return x * x * (3 - 2 * x)


def type_text(value: str, t: float, start: float, end: float) -> str:
    return value[: max(0, min(len(value), int(len(value) * ease(t, start, end))))]


def phone_frame(base: Image.Image, box=(426, 28, 854, 698)) -> tuple[int, int, int, int]:
    d = ImageDraw.Draw(base)
    rr(d, box, 44, "#07090d", "#3b4354", 2)
    inner = (box[0] + 18, box[1] + 24, box[2] - 18, box[3] - 24)
    rr(d, inner, 32, "#101827")
    d.rounded_rectangle((box[0] + 148, box[1] + 10, box[2] - 148, box[1] + 20), 5, fill="#232b37")
    return inner


def desktop_frame(base: Image.Image, os_name: str) -> tuple[int, int, int, int]:
    d = ImageDraw.Draw(base)
    box = (80, 108, 1200, 660)
    rr(d, box, 14, "#101624", "#475569", 2)
    top = (box[0], box[1], box[2], box[1] + 42)
    d.rounded_rectangle(top, 14, fill="#172033")
    d.rectangle((box[0], box[1] + 22, box[2], box[1] + 42), fill="#172033")
    if os_name == "Windows":
        text(d, (box[0] + 18, box[1] + 10), "Win's VPN", "small", "#cbd5e1")
        text(d, (box[2] - 56, box[1] + 10), "_  □  ×", "small", "#cbd5e1")
    else:
        for i, c in enumerate(["#ef4444", "#f59e0b", "#22c55e"]):
            d.ellipse((box[0] + 18 + i * 22, box[1] + 15, box[0] + 30 + i * 22, box[1] + 27), fill=c)
        text(d, (box[0] + 96, box[1] + 10), f"Win's VPN for {os_name}", "small", "#cbd5e1")
    return (box[0] + 24, box[1] + 58, box[2] - 24, box[3] - 24)


def header(draw: ImageDraw.ImageDraw, box, label="Win's VPN®"):
    x1, y1, _, _ = box
    mark = Image.open(MARK_PATH).convert("RGBA").resize((38, 38), Image.Resampling.LANCZOS)
    return mark, (x1 + 20, y1 + 18), (x1 + 68, y1 + 20), label


def draw_app_activation(base: Image.Image, box, t: float, mobile=True):
    d = ImageDraw.Draw(base)
    x1, y1, x2, y2 = box
    scene = fit_cover(WALLPAPER_DIR / "singapore.webp", (x2 - x1, y2 - y1)).convert("RGBA")
    scene.alpha_composite(Image.new("RGBA", scene.size, (7, 12, 26, 142)))
    paste_rgba(base, scene, (x1, y1))
    mark, mark_xy, label_xy, label = header(d, box)
    paste_rgba(base, mark, mark_xy)
    text(d, label_xy, label, "title")
    text(d, (x1 + 22, y1 + 78), "Free Plan: 100 Mbps upload and download", "small", "#bbf7d0")

    text(d, (x1 + 24, y1 + 122), "Activate Device", "title")
    text(d, (x1 + 24, y1 + 158), "Account number", "small", "#dbeafe")
    rr(d, (x1 + 22, y1 + 178, x2 - 22, y1 + 220), 12, "#f8fafc")
    text(d, (x1 + 38, y1 + 190), type_text("9999-9999-9999", t, 0.7, 2.0), "body", "#111827")
    text(d, (x1 + 24, y1 + 236), "Set 4-digit PIN", "small", "#dbeafe")
    rr(d, (x1 + 22, y1 + 256, x2 - 22, y1 + 298), 12, "#f8fafc", "#fbbf24" if t < 2.4 else None, 3)
    pin = type_text("0000", t, 2.1, 3.0)
    text(d, (x1 + 38, y1 + 268), "•" * len(pin), "body", "#111827")
    if t < 2.5:
        rr(d, (x1 + 22, y1 + 312, x2 - 22, y1 + 354), 12, "#fef3c7")
        text(d, (x1 + 34, y1 + 324), "Please set the PIN here, then try free server.", "small", "#713f12")
    rr(d, (x1 + 22, y2 - 70, x2 - 22, y2 - 26), 16, "#18b76b")
    text(d, ((x1 + x2) // 2, y2 - 57), "Try Free Server", "button", anchor="ma")


def draw_legal_dialog(base: Image.Image, box, t: float):
    d = ImageDraw.Draw(base)
    x1, y1, x2, y2 = box
    draw_app_activation(base, box, 3.2)
    overlay = Image.new("RGBA", (x2 - x1, y2 - y1), (3, 7, 18, 150))
    paste_rgba(base, overlay, (x1, y1))
    dlg = (x1 + 22, y1 + 92, x2 - 22, y2 - 54)
    rr(d, dlg, 20, "#f8fafc")
    text(d, (dlg[0] + 18, dlg[1] + 18), "Legal Acceptance Required", "subtitle", "#0f172a")
    text(d, (dlg[0] + 18, dlg[1] + 52), "Version 2026-06-30.v6", "tiny", "#64748b")
    labels = [
        "Terms of Service",
        "Hold Harmless Agreement",
        "Limitation of Liability",
        "Electronic Records Consent",
    ]
    for i, label in enumerate(labels):
        yy = dlg[1] + 88 + i * 45
        checked = t > 4.1 + i * 0.32
        rr(d, (dlg[0] + 20, yy, dlg[0] + 42, yy + 22), 5, "#16a34a" if checked else "#ffffff", "#94a3b8")
        if checked:
            d.line((dlg[0] + 25, yy + 11, dlg[0] + 31, yy + 17, dlg[0] + 39, yy + 5), fill="#ffffff", width=3)
        text(d, (dlg[0] + 54, yy + 2), f"I agree to the {label}.", "small", "#111827")
    rr(d, (dlg[2] - 116, dlg[3] - 52, dlg[2] - 20, dlg[3] - 14), 14, "#2563eb")
    text(d, (dlg[2] - 68, dlg[3] - 40), "Agree", "button", anchor="ma")


def draw_android_permission(base: Image.Image, box, t: float):
    d = ImageDraw.Draw(base)
    draw_app_activation(base, box, 3.2)
    x1, y1, x2, y2 = box
    overlay = Image.new("RGBA", (x2 - x1, y2 - y1), (0, 0, 0, 140))
    paste_rgba(base, overlay, (x1, y1))
    dlg = (x1 + 28, y1 + 178, x2 - 28, y1 + 424)
    rr(d, dlg, 24, "#ffffff")
    title = "Connection request" if t < 7.0 else "Allow notifications?"
    body = (
        "Win's VPN wants to set up a VPN connection that allows it to monitor network traffic."
        if t < 7.0
        else "Allow Win's VPN to send VPN status and security alerts?"
    )
    text(d, (dlg[0] + 22, dlg[1] + 22), title, "subtitle", "#0f172a")
    for idx, line in enumerate(wrap(body, 40)):
        text(d, (dlg[0] + 22, dlg[1] + 62 + idx * 24), line, "small", "#334155")
    rr(d, (dlg[2] - 116, dlg[3] - 54, dlg[2] - 22, dlg[3] - 16), 14, "#2563eb")
    text(d, (dlg[2] - 69, dlg[3] - 42), "Allow" if t >= 7.0 else "OK", "button", anchor="ma")


def draw_ios_permission(base: Image.Image, box, t: float):
    d = ImageDraw.Draw(base)
    draw_app_activation(base, box, 3.2)
    x1, y1, x2, y2 = box
    overlay = Image.new("RGBA", (x2 - x1, y2 - y1), (0, 0, 0, 140))
    paste_rgba(base, overlay, (x1, y1))
    dlg = (x1 + 28, y1 + 178, x2 - 28, y1 + 424)
    rr(d, dlg, 24, "#ffffff")
    title = "Add VPN Configurations?" if t < 7.0 else "Allow Notifications?"
    body = (
        "Win's VPN needs permission to add VPN configurations before it can protect this iPhone."
        if t < 7.0
        else "Allow Win's VPN to send connection status and security alerts?"
    )
    text(d, (dlg[0] + 22, dlg[1] + 22), title, "subtitle", "#0f172a")
    for idx, line in enumerate(wrap(body, 38)):
        text(d, (dlg[0] + 22, dlg[1] + 62 + idx * 24), line, "small", "#334155")
    text(d, (dlg[0] + 42, dlg[3] - 42), "Don't Allow", "button", "#2563eb")
    text(d, (dlg[2] - 68, dlg[3] - 42), "Allow", "button", "#2563eb", anchor="ma")


def draw_connected_app(base: Image.Image, box, t: float, mobile=True):
    d = ImageDraw.Draw(base)
    x1, y1, x2, y2 = box
    scene = fit_cover(WALLPAPER_DIR / "singapore.webp", (x2 - x1, y2 - y1)).convert("RGBA")
    scene.alpha_composite(Image.new("RGBA", scene.size, (4, 11, 22, 116)))
    paste_rgba(base, scene, (x1, y1))
    mark, mark_xy, label_xy, label = header(d, box)
    paste_rgba(base, mark, mark_xy)
    text(d, label_xy, label, "title")
    text(d, (x1 + 22, y1 + 80), "Selected Protocol: Winn Protocol®", "small", "#bbf7d0")
    p = ease(t, 8.8, 9.6)
    cx, cy = (x1 + x2) // 2, y1 + (248 if mobile else 236)
    d.ellipse((cx - 82, cy - 82, cx + 82, cy + 82), fill="#052e1e", outline="#34d399", width=7)
    d.arc((cx - 82, cy - 82, cx + 82, cy + 82), -90, -90 + int(360 * p), fill="#22c55e", width=12)
    text(d, (cx, cy - 12), "CONNECTED" if p >= 1 else "CONNECTING", "subtitle", anchor="ma")
    text(d, (cx, cy + 26), "Singapore", "small", "#d1fae5", anchor="ma")
    status_box = (x1 + 24, y1 + 368, x2 - 24, y1 + 424) if mobile else (x1 + 24, y2 - 162, x2 - 24, y2 - 110)
    button_box = (x1 + 24, y2 - 72, x2 - 24, y2 - 28) if mobile else (x1 + 24, y2 - 70, x2 - 24, y2 - 24)
    rr(d, status_box, 14, "#0f172a")
    text(d, (status_box[0] + 18, status_box[1] + 18), "Threat filtering: On", "body", "#dbeafe")
    rr(d, button_box, 16, "#ef4444")
    text(d, ((x1 + x2) // 2, button_box[1] + 14), "Disconnect", "button", anchor="ma")


def draw_android_launcher(base: Image.Image, box, t: float):
    d = ImageDraw.Draw(base)
    x1, y1, x2, y2 = box
    launcher = fit_cover(WALLPAPER_DIR / "default.webp", (x2 - x1, y2 - y1)).convert("RGBA")
    launcher.alpha_composite(Image.new("RGBA", launcher.size, (0, 0, 0, 84)))
    paste_rgba(base, launcher, (x1, y1))
    text(d, (x1 + 24, y1 + 28), "12:41", "title")
    text(d, (x1 + 24, y1 + 64), "VPN connected", "small", "#bbf7d0")
    icon = Image.open(CALC_ICON).convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)
    paste_rgba(base, icon, (x1 + 42, y1 + 148))
    text(d, (x1 + 74, y1 + 220), "Calculator", "small", anchor="ma")
    if t > 11.0:
        rr(d, (x1 + 36, y1 + 274, x2 - 36, y2 - 48), 24, "#111827")
        text(d, (x1 + 62, y1 + 304), "Calculator", "subtitle")
        text(d, (x2 - 58, y1 + 366), type_text("0000", t, 11.2, 12.0), "calc", anchor="ra")
        buttons = ["7", "8", "9", "÷", "4", "5", "6", "×", "1", "2", "3", "-", "0", ".", "=", "+"]
        for i, b in enumerate(buttons):
            col, row = i % 4, i // 4
            bx = x1 + 60 + col * 70
            by = y1 + 414 + row * 46
            rr(d, (bx, by, bx + 52, by + 34), 17, "#1f2937")
            text(d, (bx + 26, by + 8), b, "body", anchor="ma")


def draw_messages_and_block(base: Image.Image, box, t: float, mobile=True):
    d = ImageDraw.Draw(base)
    x1, y1, x2, y2 = box
    rr(d, (x1, y1, x2, y2), 28 if mobile else 12, "#f8fafc", "#cbd5e1")
    if t < 16.4:
        text(d, (x1 + 28, y1 + 26), "Messages", "title", "#0f172a")
        rr(d, (x1 + 28, y1 + 90, x2 - 30, y1 + 220), 22, "#e2e8f0")
        msg = "USPS: Your package cannot be delivered. Confirm address: http://malicious-demo.test/usps"
        for idx, line in enumerate(wrap(msg, 44 if mobile else 62)):
            text(d, (x1 + 48, y1 + 112 + idx * 24), line, "body", "#0f172a")
        rr(d, (x1 + 48, y1 + 250, x2 - 48, y1 + 294), 18, "#2563eb")
        text(d, ((x1 + x2) // 2, y1 + 264), "Open link", "button", anchor="ma")
    else:
        d.rounded_rectangle((x1, y1, x2, y1 + 48), 24 if mobile else 12, fill="#e2e8f0")
        d.rectangle((x1, y1 + 24, x2, y1 + 48), fill="#e2e8f0")
        rr(d, (x1 + 28, y1 + 12, x2 - 28, y1 + 38), 13, "#ffffff")
        text(d, (x1 + 44, y1 + 17), type_text("http://malicious-demo.test/usps", t, 16.5, 17.4), "small", "#475569")
        if t < 17.5:
            text(d, ((x1 + x2) // 2, (y1 + y2) // 2), "Loading...", "title", "#334155", "mm")
        else:
            sx, sy = (x1 + x2) // 2, y1 + 168
            d.polygon([(sx, sy - 58), (sx + 58, sy - 26), (sx + 42, sy + 50), (sx, sy + 86), (sx - 42, sy + 50), (sx - 58, sy - 26)], fill="#16a34a")
            d.line((sx - 24, sy + 6, sx - 4, sy + 28, sx + 30, sy - 24), fill="#ffffff", width=8)
            text(d, ((x1 + x2) // 2, y1 + 286), "Threat Blocked", "hero", "#0f172a", "ma")
            centered_multiline_text(
                d,
                ((x1 + x2) // 2, y1 + 338),
                "Win's VPN blocked the scam before it loaded.",
                31 if mobile else 48,
                "subtitle",
                "#334155",
            )
            rr(d, (x1 + 66, y2 - 70, x2 - 66, y2 - 28), 18, "#0f766e")
            text(d, ((x1 + x2) // 2, y2 - 56), "Back to safety", "button", anchor="ma")


def wrap(s: str, max_chars: int) -> list[str]:
    words = s.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > max_chars:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def android(t: float) -> Image.Image:
    frame = bg("singapore")
    d = ImageDraw.Draw(frame)
    text(d, (54, 36), "Android demo", "hero")
    multiline_text(
        d,
        (56, 88),
        "Activation, PIN, permissions, calculator camouflage, instant VPN, and scam-link blocking.",
        32,
        "subtitle",
        "#dbeafe",
    )
    box = phone_frame(frame)
    if t < 3.7:
        draw_app_activation(frame, box, t)
    elif t < 6.2:
        draw_legal_dialog(frame, box, t)
    elif t < 8.4:
        draw_android_permission(frame, box, t)
    elif t < 10.4:
        draw_connected_app(frame, box, t)
    elif t < 13.2:
        draw_android_launcher(frame, box, t)
    elif t < 15.0:
        draw_connected_app(frame, box, 10.0)
    else:
        draw_messages_and_block(frame, box, t, True)
    draw_timeline(frame, t, "Android")
    return frame


def ios(t: float) -> Image.Image:
    frame = bg("new_york")
    d = ImageDraw.Draw(frame)
    text(d, (54, 36), "iOS demo", "hero")
    multiline_text(
        d,
        (56, 88),
        "Activation, legal acceptance, VPN permission, instant VPN, and scam-link blocking.",
        30,
        "subtitle",
        "#dbeafe",
    )
    box = phone_frame(frame)
    if t < 3.7:
        draw_app_activation(frame, box, t)
    elif t < 6.2:
        draw_legal_dialog(frame, box, t)
    elif t < 8.4:
        draw_ios_permission(frame, box, t)
    elif t < 13.8:
        draw_connected_app(frame, box, t)
    else:
        draw_messages_and_block(frame, box, t, True)
    draw_timeline(frame, t, "iOS")
    return frame


def desktop(t: float, os_name: str) -> Image.Image:
    frame = bg("uk" if os_name == "Linux" else "new_york")
    d = ImageDraw.Draw(frame)
    text(d, (56, 28), f"{os_name} demo", "hero")
    text(d, (58, 80), "Desktop activation, legal acceptance, instant VPN, and malicious-link blocking.", "subtitle", "#dbeafe")
    app_box = desktop_frame(frame, os_name)
    x1, y1, x2, y2 = app_box
    left = (x1, y1, x1 + 480, y2)
    right = (x1 + 520, y1 + 18, x2, y2 - 12)
    if t < 4.2:
        draw_app_activation(frame, left, t, False)
    elif t < 6.7:
        draw_legal_dialog(frame, left, t)
    elif t < 9.2:
        draw_connected_app(frame, left, t, False)
    else:
        draw_connected_app(frame, left, 10.0, False)
    if t < 12.3:
        rr(d, right, 14, "#0f172a", "#334155")
        text(d, (right[0] + 26, right[1] + 26), "Desktop stays visible", "title")
        text(d, (right[0] + 26, right[1] + 68), "No calculator camouflage on computers.", "subtitle", "#dbeafe")
        rr(d, (right[0] + 26, right[1] + 122, right[2] - 26, right[1] + 180), 14, "#1e293b")
        text(d, (right[0] + 46, right[1] + 140), "Selected Protocol: Winn Protocol®", "body", "#bbf7d0")
    else:
        draw_messages_and_block(frame, right, t, False)
    draw_timeline(frame, t, os_name)
    return frame


def draw_timeline(frame: Image.Image, t: float, label: str):
    d = ImageDraw.Draw(frame)
    bar = (56, HEIGHT - 44, WIDTH - 56, HEIGHT - 30)
    rr(d, bar, 7, "#1e293b")
    fill = (bar[0], bar[1], bar[0] + int((bar[2] - bar[0]) * min(1, t / DURATION)), bar[3])
    rr(d, fill, 7, "#22c55e")
    setup = "PIN + legal + permissions" if label in {"Android", "iOS"} else "Activation + legal"
    caption = setup if t < 8.4 else "Connected" if t < 15 else "Scam link blocked"
    text(d, (56, HEIGHT - 70), f"{label}: {caption}", "small", "#dbeafe")


def write_video(name: str, renderer):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"winsvpn-{name}-demo.mp4"
    poster = OUT_DIR / f"winsvpn-{name}-demo.webp"
    total = int(DURATION * FPS)
    poster_frame = int(18.4 * FPS)
    with imageio.get_writer(
        path,
        fps=FPS,
        codec="libx264",
        quality=8,
        macro_block_size=16,
        ffmpeg_log_level="error",
        output_params=["-pix_fmt", "yuv420p", "-movflags", "+faststart", "-map_metadata", "-1"],
    ) as writer:
        for i in range(total):
            img = renderer(i / FPS)
            writer.append_data(np.asarray(img))
            if i == poster_frame:
                img.save(poster, "WEBP", quality=82, method=6)
    print(f"wrote {path}")
    print(f"wrote {poster}")


RENDERERS = {
    "android": android,
    "ios": ios,
    "windows": lambda t: desktop(t, "Windows"),
    "macos": lambda t: desktop(t, "macOS"),
    "linux": lambda t: desktop(t, "Linux"),
}


def main(argv=None):
    selected = list(argv if argv is not None else sys.argv[1:])
    names = selected or list(RENDERERS)
    unknown = sorted(set(names) - set(RENDERERS))
    if unknown:
        raise SystemExit(f"unknown demo target(s): {', '.join(unknown)}")
    for name in names:
        write_video(name, RENDERERS[name])


if __name__ == "__main__":
    main()
