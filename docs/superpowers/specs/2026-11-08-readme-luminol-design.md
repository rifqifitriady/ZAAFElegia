# README redesign: "Luminol"

- **Status:** approved by Rifqi on 2026-11-08 in visual brainstorming. Direction A ("Luminol") was chosen over "Loom" and "Recording drum".
- **Goal:** a professional, elegant README in a security and threat-investigation style, with 2D and pseudo-3D animation, and with every factual statement still true.

## Concept

The visual language is forensic UV inspection. A dark field hides the evidence. A violet UV beam sweeps across it, and malicious traces fluoresce. Each finding is then bagged and tagged with a manila evidence label that carries an ATT&CK technique ID. Every animation tells how the engine works (a rule meets an event, and a finding comes out) rather than decorating.

## Tokens (locked)

| Token | Value | Use |
|---|---|---|
| `void` | `#0A0D12` | background |
| `dim` | `#18202A` | hidden log text |
| `ink` | `#C3D6E0` | revealed text |
| `lum` | `#9BF6FF` | fluorescing traces, active outlines |
| `uv` / `uv-light` | `#7A5CFF` / `#A08CFF` | the beam |
| `manila` / `tag-ink` | `#E6D3A3` / `#2A2116` | evidence tags |
| `muted` / `faint` | `#7F93A3` / `#55687A` | captions, inactive items |

Typefaces, both under the SIL Open Font License, embedded as subsets:
- **Big Shoulders Display 800** for display text;
- **IBM Plex Mono 400 and 500** for everything else.

## Assets (`assets/readme/`)

| File | What it shows | Cycle |
|---|---|---|
| `hero.svg` | The UV beam reveals a hidden log. Two malicious events (`powershell -enc`, `lsass` access) fluoresce and get evidence tags (T1059.001, T1003.001). The title, a one-line tagline and the fact "3,807 of 3,807 SigmaHQ rules compile" are also on the banner. | 8 s |
| `how-it-works.svg` | Four glass slides in perspective (pseudo-3D): Sigma YAML → IR → matched event → OCSF finding. The beam passes through them in order, each slide lights up, and an "evidence" tag drops at the end. | 9 s |
| `roadmap.svg` | An evidence timeline: M1 is tagged "shipped · v0.0.1", the beam drifts to M2 and pulses ("next"), and M3, M4, M5 and v0.1 stay dim. | 12 s |
| `*-static.svg` | The final frame of each animation, with no motion. | none |

## Rules

- **Fonts:** GitHub renders SVG through `<img>`, so external fonts never load. Each SVG therefore embeds base64 WOFF2 subsets containing only the glyphs it uses. The OFL licence texts ship in `assets/readme/fonts/`, and NOTICE credits the fonts.
- **Reduced motion:** the animations are SMIL, which CSS cannot pause. The README therefore uses `<picture><source media="(prefers-reduced-motion: reduce)" srcset="…-static.svg">`.
- **Size:** each SVG is under 150 KB.
- **Alt text:** every image has alt text that states its content in words.
- **Honest copy:** no metric appears unless the repository proves it (3,807/3,807 corpus compile, 30 conformance cases, fuzzing in CI). Log lines in the hero are illustrative events, not claims.
- **Reproducible:** `assets/readme/src/build.py` regenerates every SVG from the tokens. The font source files are downloaded by the script's documented command and are not committed.

## README structure

1. Hero
2. Badges: CI, release, licence, MSRV
3. Two-sentence pitch and quick links
4. **How it works**, with its animation and a short caption
5. Quick start
6. What a finding looks like: a real OCSF snippet
7. Proof, not promises: three checkable facts with links
8. **Roadmap**, with its animation and milestone text
9. Reference: output, exit codes, input and limits, in `<details>`
10. Contributing, Security, License

Every statement in the current README stays as it is: commands, exit codes, limits, caps and caveats.

## Verification

- Render each SVG in headless Chrome at several animation times, and as a static frame.
- Check every file size.
- After pushing the branch, screenshot the rendered GitHub page in both light and dark mode.
- Check that every link in the README resolves.
