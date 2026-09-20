# UI language catalog

The header on every console page groups **Theme** and **Language** together.
Language initially offers only **English (flag + EN)**. It does not reload the
page, discard unsaved fields, change a campaign, or contact any provider. The
page declares English for browsers and assistive technology. Personal review
and independent human-review pages use the same header.
The flag is an inline SVG, so it requires neither an emoji font nor a download.
Authored interface copy uses ASCII punctuation: hyphens, straight quotes and
three dots. Decorative arrows and typographic symbols are removed or replaced
with clear words. The flag and other graphical icons remain SVG. This rule does
not rewrite saved model answers, research artifacts, names or identifiers.

## Where interface text belongs

`experiments/rig_web_app/locales/en.json` is the English catalog. It contains
application-authored labels, instructions, tooltips, accessible names, validation
messages and client-side feedback. Keys are grouped by the rendering module.
HTML, CSS, JavaScript, routes and executable commands stay in source files.

Use `i18n.text(message_id)` for ordinary text. Escape it at the HTML boundary,
as for any other displayed string. Use `i18n.template(static_source)` for a
static HTML or JavaScript fragment:

- `[[text:message_id]]` inserts escaped HTML text.
- `[[attr:message_id]]` inserts an escaped HTML attribute.
- `[[js:message_id]]` inserts a complete quoted JavaScript string.
- `[[jshtml:message_id]]` inserts a quoted JavaScript string whose content is
  escaped for an HTML fragment constructed by that script.

Expand static fragments **before** concatenating dynamic data. Never pass model
answers, prompts, user input, saved artifacts or interpolated HTML to the
template helper. Missing message IDs are errors, not silently displayed keys.
The catalog is loaded once and static fragments are cached. There is no
translation SDK, external translation service or additional browser request.

Dynamic messages should be complete sentences with named placeholders, for
example `"Showing {shown} of {total} results"`. Call
`i18n.text(message_id, shown=shown, total=total)`, then escape the resulting text
or attribute once at its HTML boundary. In client scripts, pass a catalog
message to `window.uraFormat(message, {shown, total})` and assign the result to
`textContent`. Substituted values are not interpreted recursively. Missing
values are errors. Do not assemble new messages from English word fragments.

`display_labels.py` maps known application choices to catalog labels, shared
with scripts through `window.uraLabel`. The option's value, request parameter
and saved rating are still the original identifier. Unknown identifiers and
research content pass through unchanged. Never decide pagination, numeric
validity, cost completeness or execution behavior by comparing display text.
Imported cohort tags are data, not shared UI vocabulary. Their display may
separate underscore-delimited words, but must not introduce campaign-specific
policy into the application or alter the stored tag.

Command flags, model/corpus identifiers, enum values, stored scientific labels,
provider errors and original prompts, answers, judgments and logs remain in
their recorded language. The detached process and log supervisors remain
independent of the UI catalog and can still execute directly.

## Adding or changing copy

1. Add or edit the complete English message in the JSON file, with named
   placeholders for dynamic values. Do not put markup or executable code
   into the catalog.
2. Reference the key from the renderer or embedded script. Keep saved values
   and machine identifiers separate from their presentation.
3. Run `tests/ura/test_rig_web_language.py`,
   `tests/ura/test_rig_web_language_coverage.py` and affected UI/browser tests on the
   rig. Reference coverage rejects missing and unused messages and dynamic
   template arguments. Test escaping, mobile layout, unsaved controls and
   JavaScript-created messages, not only the server-rendered heading.
   Include labels split around dynamic values and summaries rebuilt by scripts;
   an unchanged English screenshot alone cannot establish catalog coverage.
   The separate source audit checks authored HTML/SVG text, accessibility
   attributes, HTTP error bodies, review vocabulary and named substitutions.
   Check both branches of conditional labels, including unavailable-data
   fallbacks. Plain text stays plain in the catalog; HTML entities are not a
   substitute for escaping at the rendering boundary. Punctuation checks also
   inspect decoded Python literals and explicit HTML entities.
   Negative controls keep HTTP headers, CSS classes, SQL, keyboard keys,
   capture-method identifiers and retained log markers out of translations.
4. Exercise the relevant real page and its errors, loading states and recovery
   controls. Language work must not change execution semantics or research data.

Only English is supported by this release. Adding another catalog does not
automatically enable another language: request-level language selection,
locale-specific number formatting, plural rules and translated
workflow acceptance must be implemented and tested before exposing that choice.

This catalog covers the web application, not CLI documentation or historical
research artifacts. The small local/API campaign workflow is unchanged.
