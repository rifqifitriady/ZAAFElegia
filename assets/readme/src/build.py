#!/usr/bin/env python3
"""Build the animated README artwork ("Luminol") for ZAAFElegia.

Writes assets/readme/{hero,how-it-works,roadmap}.svg and their *-static.svg
twins (final frame, no motion; used for prefers-reduced-motion).

Fonts are embedded as WOFF2 subsets because GitHub renders SVG through <img>,
which never loads external fonts. Both typefaces are under the SIL Open Font
License (see assets/readme/fonts/). Download the sources once:

    mkdir -p /tmp/ze-fonts && cd /tmp/ze-fonts
    base=https://raw.githubusercontent.com/google/fonts/main/ofl
    curl -sSfLo BigShouldersDisplay.ttf "$base/bigshouldersdisplay/BigShouldersDisplay%5Bwght%5D.ttf"
    curl -sSfLo IBMPlexMono-Regular.ttf "$base/ibmplexmono/IBMPlexMono-Regular.ttf"
    curl -sSfLo IBMPlexMono-Medium.ttf "$base/ibmplexmono/IBMPlexMono-Medium.ttf"

Then, with `pip install fonttools brotli`:

    python3 assets/readme/src/build.py --fonts /tmp/ze-fonts
"""
import argparse
import base64
import io
import pathlib

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

# ---- locked tokens (docs/superpowers/specs/2026-11-08-readme-luminol-design.md) ----
VOID, DIM, INK, LUM = "#0A0D12", "#18202A", "#C3D6E0", "#9BF6FF"
UV, UVL = "#7A5CFF", "#A08CFF"
MAN, TAGINK, TAGSUB = "#E6D3A3", "#2A2116", "#5B4A2C"
MUTED, FAINT = "#7F93A3", "#55687A"
DISP, MONO = "ZE Display", "ZE Mono"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Doc:
    """Collects the text drawn with each font so it can be subset afterwards."""

    def __init__(self, static):
        self.static = static
        self.disp_text = set()
        self.mono_text = set()

    def a(self, element):
        """An <animate*> element, or nothing in the static variant."""
        return "" if self.static else element

    def disp(self, s):
        self.disp_text.update(s)
        return esc(s)

    def mono(self, s):
        self.mono_text.update(s)
        return esc(s)


# ------------------------------------------------------------------ hero
LOG = [
    ("2026-11-08T03:14:02Z  4624  logon type=3   user=svc_backup  src=10.4.2.17", False),
    ("2026-11-08T03:14:05Z  4688  cmd.exe /c whoami /all", False),
    ("2026-11-08T03:14:06Z  4688  powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA", True),
    ("2026-11-08T03:14:09Z  22    dns query update.msedge.net", False),
    ("2026-11-08T03:14:11Z  10    lsass.exe GrantedAccess=0x1010 src=rundll32.exe", True),
    ("2026-11-08T03:14:15Z  4688  explorer.exe", False),
    ("2026-11-08T03:14:18Z  mcp   tool_call search_docs agent=a-17", False),
    ("2026-11-08T03:14:21Z  4663  object=\\Users\\finance\\NTUSER.DAT", False),
]


def hero(d):
    y0, dy, dur = 128, 20, "8s"
    beam_move = d.a('<animateTransform attributeName="transform" type="translate" '
                    'values="-280 0;1010 0;1010 0" keyTimes="0;.72;1" dur="8s" repeatCount="indefinite"/>')
    rest = ' transform="translate(560 0)"' if d.static else ""
    dim = "".join(f'<text x="40" y="{y0 + i * dy}">{d.mono(t)}</text>' for i, (t, _) in enumerate(LOG))
    lit = "".join(f'<text x="40" y="{y0 + i * dy}" fill="{LUM if bad else INK}">{d.mono(t)}</text>'
                  for i, (t, bad) in enumerate(LOG))

    def glow(i, kt):
        t, _ = LOG[i]
        op = ' opacity=".55"' if d.static else ""
        anim = d.a(f'<animate attributeName="opacity" values="0;0;1;.55;.55;0" '
                   f'keyTimes="0;{kt};{kt + .02:.3f};.62;.94;1" dur="{dur}" repeatCount="indefinite"/>')
        return (f'<text x="40" y="{y0 + i * dy}" font-family="{MONO}" font-size="12.5" fill="{LUM}" '
                f'filter="url(#hGlow)"{op}>{d.mono(t)}{anim}</text>')

    def tag(i, kt, code, label):
        y = y0 + i * dy
        show = "" if d.static else ' opacity="0"'
        return (f'<g{show}>'
                + d.a(f'<animate attributeName="opacity" values="0;0;1;1;0" keyTimes="0;{kt};{kt + .015:.3f};.94;1" '
                      f'dur="{dur}" repeatCount="indefinite"/>')
                + '<g>'
                + d.a(f'<animateTransform attributeName="transform" type="translate" '
                      f'values="0 -46;0 -46;0 4;0 -2;0 0;0 0" '
                      f'keyTimes="0;{kt};{kt + .03:.3f};{kt + .05:.3f};{kt + .07:.3f};1" dur="{dur}" repeatCount="indefinite"/>')
                + f'<line x1="700" y1="{y - 4}" x2="742" y2="{y - 4}" stroke="{MAN}" stroke-width="1" stroke-dasharray="2 3"/>'
                f'<path d="M742 {y - 17} h178 v26 h-178 l-10 -13 z" fill="{MAN}"/>'
                f'<circle cx="750" cy="{y - 4}" r="2.6" fill="{VOID}"/>'
                f'<text x="760" y="{y}" font-family="{MONO}" font-size="11" font-weight="500" fill="{TAGINK}">{d.mono(code)}</text>'
                f'<text x="828" y="{y}" font-family="{MONO}" font-size="10" fill="{TAGSUB}">{d.mono(label)}</text></g></g>')

    lit_layer = (f'<g font-family="{MONO}" font-size="12.5">{lit}</g>' if d.static
                 else f'<g font-family="{MONO}" font-size="12.5" mask="url(#hMask)">{lit}</g>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 300" width="960" height="300" role="img">
<title>ZAAFElegia: a UV beam reveals a hidden log; two malicious events fluoresce and are tagged T1059.001 and T1003.001</title>
<defs>{{FONTS}}
 <filter id="hGlow" x="-5%" y="-80%" width="110%" height="260%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
 <filter id="hSoft" x="-50%" y="-10%" width="200%" height="120%"><feGaussianBlur stdDeviation="14"/></filter>
 <linearGradient id="hMaskG" x1="0" x2="1"><stop offset="0" stop-color="#000"/><stop offset=".3" stop-color="#fff"/><stop offset=".7" stop-color="#fff"/><stop offset="1" stop-color="#000"/></linearGradient>
 <linearGradient id="hBeamG" x1="0" x2="1"><stop offset="0" stop-color="#5B3CFF" stop-opacity="0"/><stop offset=".5" stop-color="{UV}" stop-opacity=".5"/><stop offset="1" stop-color="#5B3CFF" stop-opacity="0"/></linearGradient>
 <mask id="hMask"><rect width="960" height="300" fill="#000"/><g{rest}><polygon points="0,96 150,96 230,300 70,300" fill="url(#hMaskG)"/>{beam_move}</g></mask>
</defs>
<rect width="960" height="300" rx="12" fill="{VOID}"/>
<text x="40" y="66" font-family="{DISP}" font-weight="800" font-size="54" letter-spacing="1" fill="#E8F0F5">{d.disp("ZAAFElegia")}</text>
<text x="292" y="64" font-family="{MONO}" font-size="12.5" fill="{MUTED}">{d.mono("Sigma rules that bring an intrusion to light.")}</text>
<text x="920" y="64" text-anchor="end" font-family="{MONO}" font-size="11" fill="{FAINT}">{d.mono("3,807 of 3,807 SigmaHQ rules compile")}</text>
<g font-family="{MONO}" font-size="12.5" fill="{DIM}">{dim}</g>
{lit_layer}
{glow(4, .31)}{glow(2, .365)}
<g style="mix-blend-mode:screen"{rest}><g filter="url(#hSoft)"><polygon points="0,96 150,96 230,300 70,300" fill="url(#hBeamG)"/></g><polygon points="62,96 88,96 168,300 142,300" fill="{UVL}" opacity=".12"/>{beam_move}</g>
{tag(4, .31, "T1003.001", "lsass memory")}{tag(2, .365, "T1059.001", "encoded shell")}
</svg>'''


# ------------------------------------------------------------------ how it works
SLIDES = [
    ("1 · Rule", "Sigma YAML", ["selection:", "  CommandLine|contains:", "    - '-enc'", "condition: selection"]),
    ("2 · Compile", "IR", ["Pred CommandLine", "  Str *-enc*  ci", "weight 1"]),
    ("3 · Match", "Event", ["4688 powershell.exe", "  -nop -w hidden", "  -enc SQBFAFgA..."]),
    ("4 · Emit", "Finding", ["OCSF class 2004", "severity high", "T1059.001"]),
]


def how(d):
    dur, W, H, SK = "9s", 170, 120, -26
    parts = []
    for i, (step, kind, body) in enumerate(SLIDES):
        x, y, s = 70 + i * 215, 150 - i * 26, 1 - i * .045
        kt = .10 + i * .13
        poly = f"0,0 {W},{SK} {W},{H + SK} 0,{H}"
        lit_attrs = 'opacity=".55" fill-opacity=".05"' if d.static else 'opacity="0" fill-opacity="0"'
        g = (f'<g transform="translate({x} {y}) scale({s:.3f})">'
             f'<ellipse cx="{W / 2 + 10}" cy="{H + 28}" rx="{W * .55}" ry="9" fill="#000" opacity=".55" filter="url(#wBlur)"/>'
             f'<polygon points="{poly}" fill="{LUM}" fill-opacity=".035" stroke="{FAINT}" stroke-width="1.2"/>'
             f'<polygon points="{poly}" fill="{LUM}" stroke="{LUM}" stroke-width="1.6" filter="url(#wGlow)" {lit_attrs}>'
             + d.a(f'<animate attributeName="opacity" values="0;0;1;.55;.55;0" keyTimes="0;{kt:.3f};{kt + .02:.3f};{kt + .12:.3f};.93;1" dur="{dur}" repeatCount="indefinite"/>'
                   f'<animate attributeName="fill-opacity" values="0;0;.10;.05;.05;0" keyTimes="0;{kt:.3f};{kt + .02:.3f};{kt + .12:.3f};.93;1" dur="{dur}" repeatCount="indefinite"/>')
             + f'</polygon><line x1="4" y1="6" x2="{W - 4}" y2="{SK + 6}" stroke="#fff" stroke-opacity=".08" stroke-width="2"/>'
             f'<g transform="matrix(1 {SK / W:.4f} 0 1 0 0)">'
             f'<text x="12" y="22" font-family="{MONO}" font-size="10" fill="{MUTED}">{d.mono(kind)}</text>')
        for j, line in enumerate(body):
            fill = INK if d.static else DIM
            g += (f'<text x="12" y="{44 + j * 16}" font-family="{MONO}" font-size="11" fill="{fill}">{d.mono(line)}'
                  + d.a(f'<animate attributeName="fill" values="{DIM};{DIM};{LUM};{INK};{INK};{DIM}" keyTimes="0;{kt:.3f};{kt + .02:.3f};{kt + .1:.3f};.93;1" dur="{dur}" repeatCount="indefinite"/>')
                  + '</text>')
        g += '</g></g>'
        g += f'<text x="{x + 4}" y="{y + H * s + 48:.0f}" font-family="{MONO}" font-size="11.5" fill="{MUTED}">{d.mono(step)}</text>'
        parts.append(g)
    clip_w = "960" if d.static else "0"
    clip = (f'<clipPath id="wBeamClip"><rect x="0" y="0" height="340" width="{clip_w}">'
            + d.a(f'<animate attributeName="width" values="0;0;960;960;0" keyTimes="0;.06;.62;.93;1" dur="{dur}" repeatCount="indefinite"/>')
            + '</rect></clipPath>')
    beam = (f'<g style="mix-blend-mode:screen" clip-path="url(#wBeamClip)">'
            f'<polygon points="0,212 960,62 960,98 0,248" fill="url(#wBeamG)" filter="url(#wSoft)"/>'
            f'<line x1="0" y1="230" x2="960" y2="80" stroke="{UVL}" stroke-opacity=".45" stroke-width="1.2"/></g>')
    show = "" if d.static else ' opacity="0"'
    tag = (f'<g{show}>'
           + d.a(f'<animate attributeName="opacity" values="0;0;1;1;0" keyTimes="0;.64;.66;.93;1" dur="{dur}" repeatCount="indefinite"/>')
           + '<g>'
           + d.a(f'<animateTransform attributeName="transform" type="translate" values="0 -40;0 -40;0 6;0 -2;0 0;0 0" keyTimes="0;.64;.68;.7;.72;1" dur="{dur}" repeatCount="indefinite"/>')
           + f'<line x1="912" y1="70" x2="912" y2="226" stroke="{MAN}" stroke-dasharray="2 3"/>'
           f'<path d="M842 226 h104 v28 h-104 l-10 -14 z" fill="{MAN}"/><circle cx="850" cy="240" r="2.6" fill="{VOID}"/>'
           f'<text x="860" y="244" font-family="{MONO}" font-size="11" font-weight="500" fill="{TAGINK}">{d.mono("evidence")}</text></g></g>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 340" width="960" height="340" role="img">
<title>How ZAAFElegia works: a Sigma rule is compiled to an IR, matched against an event, and emitted as an OCSF Detection Finding</title>
<defs>{{FONTS}}
 <filter id="wGlow" x="-10%" y="-10%" width="120%" height="120%"><feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
 <filter id="wBlur"><feGaussianBlur stdDeviation="6"/></filter><filter id="wSoft"><feGaussianBlur stdDeviation="9"/></filter>
 <linearGradient id="wBeamG" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{UV}" stop-opacity=".05"/><stop offset=".7" stop-color="{UV}" stop-opacity=".55"/><stop offset="1" stop-color="{UVL}" stop-opacity=".8"/></linearGradient>
 {clip}
</defs>
<rect width="960" height="340" rx="12" fill="{VOID}"/>
<text x="40" y="44" font-family="{MONO}" font-size="12" fill="{FAINT}">{d.mono("how it works")}</text>
{beam}{"".join(parts)}{tag}
</svg>'''


# ------------------------------------------------------------------ roadmap
MILESTONES = [
    ("M1", "Engine core", "shipped · v0.0.1"),
    ("M2", "Correlation", "next"),
    ("M3", "Real log sources", "planned"),
    ("M4", "Fast history", "planned"),
    ("M5", "AI-era detection", "planned"),
    ("v0.1", "Public release", "planned"),
]


def roadmap(d):
    dur = "12s"
    xs = [90 + i * 156 for i in range(len(MILESTONES))]
    tag_shape = "h66 v52 h-66 l-10 -26 z"
    rp = []
    beam_x = xs[1] - 60
    beam = (f'<g style="mix-blend-mode:screen"' + (f' transform="translate({beam_x} 0)"' if d.static else "") + '>'
            f'<g filter="url(#rSoft)"><polygon points="0,30 70,30 110,190 40,190" fill="{UV}" opacity=".45"/></g>'
            + d.a(f'<animateTransform attributeName="transform" type="translate" values="40 0;{beam_x} 0;{xs[1] - 40} 0;{beam_x} 0;40 0" '
                  f'keyTimes="0;.45;.7;.9;1" dur="{dur}" repeatCount="indefinite" calcMode="spline" '
                  f'keySplines=".4 0 .2 1;.4 0 .6 1;.4 0 .6 1;.4 0 .2 1"/>')
            + '</g>')
    rp.append(beam)
    rp.append(f'<line x1="60" y1="96" x2="900" y2="96" stroke="{FAINT}" stroke-width="1" stroke-dasharray="3 5"/>')
    for i, (m, name, state) in enumerate(MILESTONES):
        x = xs[i]
        if i == 0:
            rp.append(f'<path d="M{x - 6} 70 {tag_shape}" fill="{MAN}"/><circle cx="{x + 2}" cy="96" r="3" fill="{VOID}"/>'
                      f'<text x="{x + 12}" y="92" font-family="{DISP}" font-weight="800" font-size="22" fill="{TAGINK}">{d.disp(m)}</text>'
                      f'<text x="{x + 12}" y="110" font-family="{MONO}" font-size="9.5" fill="{TAGSUB}">{d.mono("shipped")}</text>')
        else:
            stroke, fill, op = (LUM, INK, ".9") if i == 1 else (FAINT, FAINT, ".55")
            rp.append(f'<g opacity="{op}"><path d="M{x - 6} 70 {tag_shape}" fill="none" stroke="{stroke}" stroke-width="1.2"/>'
                      f'<text x="{x + 12}" y="96" font-family="{DISP}" font-weight="800" font-size="22" fill="{fill}">{d.disp(m)}</text></g>')
        rp.append(f'<text x="{x - 14}" y="148" font-family="{MONO}" font-size="11.5" fill="{INK if i < 2 else MUTED}">{d.mono(name)}</text>'
                  f'<text x="{x - 14}" y="166" font-family="{MONO}" font-size="10" fill="{LUM if i == 1 else FAINT}">{d.mono(state)}</text>')
    pulse_op = ' opacity=".9"' if d.static else ' opacity="0"'
    rp.append(f'<path d="M{xs[1] - 6} 70 {tag_shape}" fill="none" stroke="{LUM}" stroke-width="2" filter="url(#rGlow)"{pulse_op}>'
              + d.a(f'<animate attributeName="opacity" values="0;0;.9;.25;.9;.25;0" keyTimes="0;.45;.55;.67;.79;.9;1" dur="{dur}" repeatCount="indefinite"/>')
              + '</path>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 200" width="960" height="200" role="img">
<title>Roadmap: M1 engine core shipped as v0.0.1; next M2 correlation, then M3 real log sources, M4 fast history, M5 AI-era detection and the v0.1 public release</title>
<defs>{{FONTS}}
 <filter id="rGlow"><feGaussianBlur stdDeviation="2.5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
 <filter id="rSoft" x="-50%" y="-10%" width="200%" height="120%"><feGaussianBlur stdDeviation="12"/></filter>
</defs>
<rect width="960" height="200" rx="12" fill="{VOID}"/>
<text x="40" y="34" font-family="{MONO}" font-size="12" fill="{FAINT}">{d.mono("roadmap")}</text>
{"".join(rp)}
</svg>'''


# ------------------------------------------------------------------ fonts
def woff2_b64(font, text):
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = ["kern", "liga"]
    opts.name_IDs = []
    opts.notdef_outline = True
    opts.drop_tables += ["meta"]
    sub = subset.Subsetter(opts)
    sub.populate(text="".join(sorted(text)) + " ")
    sub.subset(font)
    buf = io.BytesIO()
    font.flavor = "woff2"
    font.save(buf)
    return base64.b64encode(buf.getvalue()).decode()


def font_css(fonts_dir, d):
    bsd = TTFont(fonts_dir / "BigShouldersDisplay.ttf")
    bsd = instancer.instantiateVariableFont(bsd, {"wght": 800})
    css = []
    if d.disp_text:
        css.append(f"@font-face{{font-family:'{DISP}';font-weight:800;src:url(data:font/woff2;base64,{woff2_b64(bsd, d.disp_text)}) format('woff2')}}")
    for weight, name in ((400, "IBMPlexMono-Regular.ttf"), (500, "IBMPlexMono-Medium.ttf")):
        css.append(f"@font-face{{font-family:'{MONO}';font-weight:{weight};src:url(data:font/woff2;base64,"
                   f"{woff2_b64(TTFont(fonts_dir / name), d.mono_text)}) format('woff2')}}")
    return "<style>" + "".join(css) + "</style>"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fonts", required=True, type=pathlib.Path, help="directory with the three .ttf files")
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    for name, build in (("hero", hero), ("how-it-works", how), ("roadmap", roadmap)):
        for static in (False, True):
            d = Doc(static)
            svg = build(d)
            svg = svg.replace("{FONTS}", font_css(args.fonts, d))
            path = args.out / f"{name}{'-static' if static else ''}.svg"
            path.write_text(svg, encoding="utf-8")
            print(f"{path.name:28s} {len(svg.encode()) / 1024:6.1f} KB")


if __name__ == "__main__":
    main()
