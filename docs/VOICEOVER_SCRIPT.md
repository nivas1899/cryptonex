# CRYPTONEX — voiceover script

Timed to `cryptonex-demo.mp4` / `cryptonex-demo.gif` (82.2s, 30 fps, 12 UI scenes plus a
title card and a closing card). Captions matching this narration are burned into the
video itself and also shipped as real closed captions in `cryptonex-demo.srt` — load the
`.srt` alongside the `.mp4` in any player that supports external subtitles.

This is the second recording, redone after the console's visual redesign: interactive
donut charts you click to drill into a stat, a color/rating glossary, and a
professional full-width layout replaced the old bar charts and plain radio nav.

---

**[0:00–0:03.2] — Title card**
*(no narration — let the title land)*

**[0:03.2–0:08.2] — Scan page, idle**
> "You cannot migrate what you cannot see. CRYPTONEX scans a codebase locally — nothing
> is ever uploaded."

**[0:08.2–0:14.2] — Estate posture: 46 assets, grade B**
> "Forty-six cryptographic assets found. Estate posture: grade B out of a hundred."

**[0:14.2–0:21.2] — Overview donuts: quantum status + criticality**
> "Quantum status and criticality, at a glance — color-coded, and every color explained.
> Click any slice to drill straight in."

**[0:21.2–0:27.2] — Click "Vulnerable" → Inventory, filtered**
> "One click on 'Vulnerable' — and we're in the inventory, already filtered to the
> fifteen assets that need attention."

**[0:27.2–0:35.2] — Inventory detail: RSA root CA**
> "Let's inspect one: the RSA root of trust. Observed evidence, inferred criticality, the
> Mosca exposure window, and the exact post-quantum recommendation."

**[0:35.2–0:40.2] — Weaknesses, severity donut**
> "Twenty-five real-world misuse findings — hardcoded keys, weak modes, disabled TLS
> checks. Click a severity to filter."

**[0:40.2–0:46.2] — Weaknesses filtered to Critical**
> "Five critical findings, isolated instantly — each with the exact line, the fix, and
> the CWE."

**[0:46.2–0:53.2] — PQC Readiness: timeline + migration waves**
> "Post-quantum readiness: a crypto-agility score, a quantum-risk timeline, and migration
> waves sequenced by effort."

**[0:53.2–0:58.2] — Mosca Lab, NIST baseline**
> "The Mosca Lab lets you model your own assumptions — how long data must stay secret,
> how long migration takes."

**[0:58.2–1:05.2] — Regulator preset, live recompute**
> "Switch to the EU-2030 regulator preset — assumptions tighten, and twenty-four of
> forty-six assets fall at risk. Everything recomputes live."

**[1:05.2–1:12.2] — Coverage: the color/rating glossary**
> "And nothing here is a black box — every color, every score, every rating is
> explained, right in the console."

**[1:12.2–1:18.2] — Scan page: deliverables**
> "Export the CBOM, SARIF, and report — fully offline, ready for a GRC platform, a SIEM,
> or your CI pipeline."

**[1:18.2–1:22.2] — Closing card**
*(no narration — let the tagline land)*

---

## Full script (no timestamps, for a clean read-through)

> You cannot migrate what you cannot see. CRYPTONEX scans a codebase locally — nothing is
> ever uploaded. Forty-six cryptographic assets found. Estate posture: grade B out of a
> hundred.
>
> Quantum status and criticality, at a glance — color-coded, and every color explained.
> Click any slice to drill straight in. One click on "Vulnerable" — and we're in the
> inventory, already filtered to the fifteen assets that need attention.
>
> Let's inspect one: the RSA root of trust. Observed evidence, inferred criticality, the
> Mosca exposure window, and the exact post-quantum recommendation.
>
> Twenty-five real-world misuse findings — hardcoded keys, weak modes, disabled TLS
> checks. Click a severity to filter. Five critical findings, isolated instantly — each
> with the exact line, the fix, and the CWE.
>
> Post-quantum readiness: a crypto-agility score, a quantum-risk timeline, and migration
> waves sequenced by effort.
>
> The Mosca Lab lets you model your own assumptions — how long data must stay secret, how
> long migration takes. Switch to the EU-2030 regulator preset — assumptions tighten, and
> twenty-four of forty-six assets fall at risk. Everything recomputes live.
>
> And nothing here is a black box — every color, every score, every rating is explained,
> right in the console.
>
> Export the CBOM, SARIF, and report — fully offline, ready for a GRC platform, a SIEM,
> or your CI pipeline.

~185 words total, ≈1:22 at a natural ~135 wpm pace — matches the recording length.

## Regenerating this recording

The whole thing is scripted, not manually screen-recorded — see
`docs/demo/workflow-2026/*.png` for the source screenshots (captured against the
`tests/fixtures/vulnerable-repo` scan already loaded in `cryptonex-out/result.json`) and
the assembly step that turns them into `cryptonex-demo.mp4` / `.gif` / `.srt` with
burned-in captions (title card → 12 scenes → closing card, each faded in/out, a caption
banner drawn on with ffmpeg's `drawtext`, concatenated, then re-encoded to a paletted
GIF). Re-run the capture after any further UI change and rebuild rather than hand-editing
the video.
