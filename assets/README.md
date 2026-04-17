# Logo assets

- `**torbunny.png**` — Source artwork for the CLI banner. Replace it with your logo (PNG recommended; transparency is composited on white). At startup, **Pillow** rasterizes the image into ASCII and paints each glyph with the **truecolor** sampled from the corresponding pixel (24-bit `rgb(r,g,b)` in the terminal). Very dark pixels are lifted slightly so the art stays readable on dark backgrounds.
- `**banner_logo.txt`** — Optional **monochrome** cache from `tools/png_to_ascii.py --write`. If this file exists, it is used only for the plain `LOGO_ASCII` string; **the live CLI banner prefers the PNG** so colors still work. Delete the cache or omit it to rely on the PNG alone.

```bash
python tools/png_to_ascii.py --write   # refresh text cache only (no color stored)
```

Use a terminal that supports **truecolor** (Windows Terminal, iTerm2, modern GNOME Terminal, WezTerm, etc.) for full effect. Older 16-color terminals may approximate colors.