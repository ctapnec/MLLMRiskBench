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
- Local media must resolve beneath an operator-approved dataset root and match
  its recorded SHA-256 digest before it may be uploaded to a provider.
- Human-audit exports may contain harmful or personal content. Encrypt or
  access-control them, disclose the exposure to raters, and delete them under the
  study's retention schedule.

## Reporting vulnerabilities

Do not include provider keys, private corpus rows, or harmful payloads in a
public report. Report a vulnerability privately to the thesis author with the
smallest non-sensitive reproduction that demonstrates it.

## Scope

The current package is a research prototype. Passing the offline suite does not
certify third-party adapters, hosted endpoints, model safety, regulatory
compliance, or suitability for production deployment.
