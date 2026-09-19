# UI language catalog

The header on every console page groups **Theme** and **Language** together.
Language initially offers only **English (flag + EN)**. It does not reload the
page, discard unsaved fields, change a campaign, or contact any provider. The
page declares English for browsers and assistive technology. Personal review
and independent human-review pages use the same header.

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

Command flags, model/corpus identifiers, enum values, stored scientific labels,
provider errors and original prompts, answers, judgments and logs remain in
their recorded language. The detached process and log supervisors remain
independent of the UI catalog and can still execute directly.

## Adding or changing copy

1. Add or edit the English message in the JSON file, preserving meaningful
   whitespace in concatenated messages. Do not put markup or executable code
   into the catalog.
2. Reference the key from the renderer or embedded script. Keep saved values
   and machine identifiers separate from their presentation.
3. Run `tests/ura/test_rig_web_language.py` and affected UI/browser tests on the
   rig. Reference coverage rejects missing and unused messages and dynamic
   template arguments. Test escaping, mobile layout, unsaved controls and
   JavaScript-created messages, not only the server-rendered heading.
4. Exercise the relevant real page and its errors, loading states and recovery
   controls. Language work must not change execution semantics or research data.

Only English is supported by this release. Adding another catalog does not
automatically enable another language: request-level language selection,
formatted values, plural forms, script-generated enum labels and translated
workflow acceptance must be implemented and tested before exposing that choice.

This catalog covers the web application, not CLI documentation or historical
research artifacts. The small local/API campaign workflow is unchanged.
