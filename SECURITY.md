# Security and data-handling policy

URA-Bench processes adversarial prompts, model responses, third-party datasets,
and optional local media. Treat run artifacts as sensitive research data.

## Trust boundaries

- Only ingest corpora from a verified revision and record its license and digest.
- Do not run a third-party adapter with credentials it does not require. The
  built-in subprocess helper filters credential-like environment variables and
  bounds returned diagnostics, but it is not a filesystem, account, network, or
  process sandbox. A child still inherits the invoking user's filesystem
  privileges and HOME-accessible credential files; descendants may survive a
  direct-process timeout; temporary stdout/stderr can consume disk until the
  child stops.
- Treat untrusted engines as hostile code: run them in a disposable container,
  VM, or low-privilege account with an isolated HOME, read-only/minimal mounts,
  explicit network policy, process-tree termination, CPU/memory/time limits, and
  output/filesystem quotas. Forward only individually approved credentials and
  never give an engine a live offensive target.
- A hosted judge receives the evaluated prompt and response. Use a local judge,
  a same-provider approved endpoint, or an explicit data-processing approval for
  private, personal, gated, or export-controlled material.
- Claude Fable is a Covered Model with mandatory 30-day provider retention and
  is not available under Zero Data Retention. Obtain explicit institutional or
  operator approval for that retention before sending any corpus row; do not
  upload data whose license or handling rules prohibit it. See Anthropic's
  [Fable/Mythos documentation](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5).
- OpenAI Responses `store=false` disables response application-state storage;
  it does not by itself disable provider abuse-monitoring logs or prompt-cache
  retention. Record the organization's effective data controls and approvals
  under OpenAI's [data controls](https://developers.openai.com/api/docs/guides/your-data).
- Stateless Sol `all_turns` artifacts contain encrypted reasoning items needed
  for continuation. Treat those opaque items as sensitive response data: retain
  them only in access-controlled, hash-verified run artifacts and never paste
  them into reports or issue trackers.
- A typed Fable mid-generation refusal is not permission to retain the preceding
  partial generation. The adapter discards partial visible, thinking and
  redacted-thinking blocks and persists only the refusal plus bounded hashes and
  counts for audit.
- A real hosted run is rejected unless `--provider-data-policy-approval` and
  `--provider-data-policy-sha256` identify one bounded regular JSON file. It must
  name every exact hosted target/judge specification once, with its provider,
  role(s), accepted retention terms, accepted data-use terms, and HTTPS policy
  references. Its schema is `ura-provider-data-policy-approval/1.0`; the exact
  template is in [RUN_AND_RETURN.md](experiments/RUN_AND_RETURN.md). This is an
  auditable operator approval, not a claim that a provider offers zero retention.
- Local media must resolve beneath an operator-approved dataset root and match
  its recorded SHA-256 digest before it may be uploaded to a provider. Prepared
  artifacts store `@media-root/<index>/<relative-path>` rather than the local
  absolute path. Preserve the approved-root order when rebinding a resumed or
  relocated run; changing an alias index changes what the artifact names and is
  rejected by the digest/lineage gates.
- Human-audit exports may contain harmful or personal content. Encrypt or
  access-control them, disclose the exposure to raters, and delete them under the
  study's retention schedule.

## Paid-call containment

For every live grid, set finite `--max-total-target-calls`,
`--max-total-judge-calls`, `--max-total-http-attempts`, and
`--deadline-seconds`. Reservations are durably recorded before external calls;
systemic provider/judge failures open a durable circuit. Fix the cause before
using `--reset-open-circuits`. Do not delete or hand-edit budget, circuit,
checkpoint, completion, or error artifacts to force a run onward. Existing
locks fail closed and are never reclaimed automatically. If an abandoned lock
must be cleared, first verify that its PID/host/process identity has no active
owner, then remove only that exact lock and record the intervention. Recovery
validates the budget ledger against same-grid completion, checkpoint, error, and
circuit high-water evidence before any new call or circuit reset. These controls
bound declared call exposure, not dollars, tokens, provider-side retries outside
the declared transport, or billing reconciliation.

## Reporting vulnerabilities

Do not include provider keys, private corpus rows, or harmful payloads in a
public report. Report a vulnerability privately to the thesis author with the
smallest non-sensitive reproduction that demonstrates it.

## Scope

The current package is a research prototype. Passing the offline suite does not
certify third-party adapters, hosted endpoints, model safety, regulatory
compliance, or suitability for production deployment.
