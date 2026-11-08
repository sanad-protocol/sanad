# sanadprotocol.org

Source of the website of **Sanad**, an open protocol for recomputable recognition of skills (v0.1). Live site: <https://sanadprotocol.org>.

Sanad is not accreditation and has no token. The specification, the governance charter and the plan for the Open Sanad Foundation (United Arab Emirates, in preparation) are published on the site. Until the foundation exists, Dr. Arash Kermani Kolankeh acts as interim steward.

## Contents

| Path | What it is |
|---|---|
| `content/<lang>/*.md` | Page texts with a small front matter (`en`, `de`, `ar`, `fa`) |
| `spec/SPEC-v0.1.md` | Source text of the specification (and its tagged PDF) |
| `reference/` | Reference implementation (TypeScript, no dependencies), 20 conformance vectors and the command-line verifier `node reference/verify.mjs` |
| `lib/` | Templates and interface strings |
| `assets/style.css` | The only stylesheet (system fonts; no external requests) |
| `build.mjs` | Static site generator (Node 22); output in `dist/` |
| `pdf.mjs`, `social.mjs`, `shots.mjs` | PDF of the specification, social image, review screenshots (use Google Chrome) |
| `test.mjs` | Checks: links, structure, accessibility basics, privacy, feeds, contrast, wording rules |

## Build and test

```
npm ci
node build.mjs        # writes dist/
node pdf.mjs          # writes dist/spec/SANAD-SPEC-0.1.pdf (needs Google Chrome)
node test.mjs
node reference/verify.mjs   # runs the conformance vectors
```

`marked` (MIT) and `playwright-core` (Apache-2.0) are development dependencies only; the built site contains no scripts.

## Principles of the site

No cookies, no analytics, no third-party requests (a strict content security policy enforces this), WCAG 2.2 AA as the target, English first with a German translation, and no claim that is not yet true.

## Licences

Text: CC BY 4.0 (see `LICENSE-CONTENT`). Code: Apache-2.0 (see `LICENSE`). The name and logo are not yet registered; see `NOTICE`.
