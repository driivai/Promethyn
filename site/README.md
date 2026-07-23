# site/ — the validation landing page

A single-page validation instrument for the action-verification layer, served
at [promethynai.com](https://promethynai.com). One job: convert a qualified
visitor — someone who ships AI agents — into a captured email requesting early
access. It is deliberately **not** a product site: no pricing, no feature
matrix, no navigation, one call to action.

Plain HTML + CSS, **zero JavaScript**, no analytics, no cookies, no external
requests (fonts are the system stack; the mark is inlined SVG derived from
`docs/brand/`). The core content works with JS disabled; so does the form.

- `index.html` — the page. The form posts to the platform's built-in form
  handling (`data-netlify`), with a honeypot field and `action="/thanks.html"`.
- `thanks.html` — post-submit confirmation (`noindex`).
- `styles.css` — brand palette taken from the SVGs in `docs/brand/`
  (ink `#1C1B19`, light `#F5F4F2`, flame `#E2622E` / `#B23E12`).
- `og.png` — link-preview card referenced from `index.html`.
- Deploy config lives at the repo root in `netlify.toml` (publish dir: `site/`).

Local preview: `python3 -m http.server --directory site 8000`.

Every claim on the page is true of the project today; the proof section links
only things that exist (the three published articles, the two repositories,
and the skip-sweep).
