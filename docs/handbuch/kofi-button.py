#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Draw the Ko-fi button of the handbook as a PNG, in the style of the Ko-fi widget (Widget_2.js): Outline and the
README pages show no JavaScript, so the button is a picture with the text and the color of choice (default: the orange of the Spille IT Solutions logo).

  kofi-button.py <out.png> [<text>] [<color>] [<question>]
                  default: "Unterstütze die Entwicklung" #E67224, no question; with a question it stands centered
                  above the button in the color of the button (readable on light and dark pages)

Needs Pillow, the font Quicksand (OFL, github.com/google/fonts, ofl/quicksand/Quicksand[wght].ttf) and the cup of
Ko-fi (https://storage.ko-fi.com/cdn/cup-border.png) next to this file or in $KOFI_ASSETS.
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFont

S = 4   # drawn at four times the size, then scaled down: smooth edges
assets = os.environ.get("KOFI_ASSETS", os.path.dirname(os.path.abspath(__file__)))
out = sys.argv[1] if len(sys.argv) > 1 else sys.exit(__doc__)
text = sys.argv[2] if len(sys.argv) > 2 else "Unterstütze die Entwicklung"
color = sys.argv[3] if len(sys.argv) > 3 else "#E67224"
question = sys.argv[4] if len(sys.argv) > 4 else ""

font = ImageFont.truetype(os.path.join(assets, "Quicksand[wght].ttf"), 14 * S)
font.set_variation_by_axes([700])
cup = Image.open(os.path.join(assets, "cup-border.png")).convert("RGBA").resize((22 * S, 15 * S), Image.LANCZOS)

# like the widget: padding 2px 12px, line height 36px, radius 7px, cup 22x15 and a space before the text
left, top, bottom, radius = 12 * S, 2 * S, 38 * S, 7 * S
text_w = font.getlength(text)
width = int(left + cup.width + 4 * S + text_w + left)
height = 40 * S
img = Image.new("RGBA", (width + S, height + S), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)
draw.rounded_rectangle((S, S, width, height), radius, fill=(0, 0, 0, 51))          # shadow 1px 1px, 20 %
draw.rounded_rectangle((0, 0, width - S, height - S), radius, fill=color)
mid = (top + bottom) // 2
img.alpha_composite(cup, (left, mid - cup.height // 2))
draw.text((left + cup.width + 4 * S, mid), text, font=font, fill="white", anchor="lm")
if question:
    qfont = ImageFont.truetype(os.path.join(assets, "Quicksand[wght].ttf"), 16 * S)
    qfont.set_variation_by_axes([700])
    q_w, q_h, gap = int(qfont.getlength(question)), 22 * S, 10 * S
    full = Image.new("RGBA", (max(q_w, img.width), q_h + gap + img.height), (0, 0, 0, 0))
    ImageDraw.Draw(full).text((full.width // 2, q_h // 2), question, font=qfont, fill=color, anchor="mm")
    full.alpha_composite(img, ((full.width - img.width) // 2, q_h + gap))
    img = full
img.resize((img.width // S, img.height // S), Image.LANCZOS).save(out, optimize=True)
