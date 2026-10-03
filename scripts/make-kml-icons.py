#!/usr/bin/env python3
"""Draw the two placemark icons the KMZ export carries.

    python scripts/make-kml-icons.py

Why this exists, rather than the two hrefs that were here before.

The KML export pointed its `IconStyle` hrefs at Google's map-shape images, which
made the document depend on a third party at the moment a client opened it. The
fix is to carry the artwork inside the KMZ -- and the artwork then has to be
something this project is entitled to put inside a file it hands to a client.
Google's map files are not that. These are drawn here instead, so the licence
question has no answer to look up.

Both are drawn white, because KML's `<IconStyle><color>` multiplies: a white
source takes the severity colour exactly, and anything tinted would shift it.

Deterministic on purpose. Re-running this must produce the same bytes, or every
rebuild shows two binary files as changed; so there is no antialiasing seeded
from anything, and the supersampling factor is fixed.
"""
import os
from PIL import Image, ImageDraw

OUT = os.path.join('src', 'assets', 'kml')
SIZE = 64
# Drawn at 8x and reduced, which is how the edges get smooth without a
# library-dependent antialiasing mode.
SCALE = 8
BIG = SIZE * SCALE

os.makedirs(OUT, exist_ok=True)


def save(img, name):
    img = img.resize((SIZE, SIZE), Image.LANCZOS)
    path = os.path.join(OUT, name)
    # optimize=True and a fixed compress_level keep the output byte-stable.
    img.save(path, 'PNG', optimize=True, compress_level=9)
    print(f"  {path}  {os.path.getsize(path)} bytes")


# ── A filled circle: the ordinary placemark ────────────────────────────────
# Inset by one scaled pixel so the stroke is not clipped by the canvas edge.
circle = Image.new('RGBA', (BIG, BIG), (0, 0, 0, 0))
d = ImageDraw.Draw(circle)
pad = SCALE * 6
d.ellipse([pad, pad, BIG - pad, BIG - pad], fill=(255, 255, 255, 255))
# A darker rim, so a light pin stays visible against a pale satellite basemap.
d.ellipse([pad, pad, BIG - pad, BIG - pad], outline=(0, 0, 0, 160), width=SCALE * 2)
save(circle, 'placemark-circle.png')


# ── An open diamond: the mirror candidate ──────────────────────────────────
# Hollow and a different shape, because this one means "this position is one of
# two that fit the measurements equally well". It has to be distinguishable from
# a fix at a glance, not merely a different colour.
diamond = Image.new('RGBA', (BIG, BIG), (0, 0, 0, 0))
d = ImageDraw.Draw(diamond)
m = SCALE * 5
points = [(BIG // 2, m), (BIG - m, BIG // 2), (BIG // 2, BIG - m), (m, BIG // 2)]
d.polygon(points, fill=(0, 0, 0, 0), outline=(255, 255, 255, 255))
# `outline` on a polygon is one pixel wide whatever the scale, so the edge is
# drawn again as lines to get a stroke that survives the reduction.
d.line(points + [points[0]], fill=(255, 255, 255, 255), width=SCALE * 5, joint='curve')
d.line(points + [points[0]], fill=(0, 0, 0, 160), width=SCALE)
save(diamond, 'mirror-diamond.png')

print('[kml-icons] done - commit these, and `npm run check:kmz` resolves them')
