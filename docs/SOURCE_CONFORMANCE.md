# Compact source receipt

`ura-source-conformance/1` is the fail-closed bridge between an operator's
acquired benchmark files and a measured Runner grid. It is one compact JSON
receipt, not a download manager, general provenance database, or workflow
engine.

The checked-in source-instance example says how logical arms map to converters
and environment locators. It does **not** show what the operator actually
acquired. After acquisition, copy it to the ignored local registry and configure
the selected paths:

```bash
cp experiments/rig/source-instances.example.json experiments/source-instances.json
```

The receipt is written only after that exact registry and `URA_MEDIA_ROOTS` are
final. It may contain only the real arms selected for one command, but every
selected real arm must appear and be admitted. Optional `blocked` and
`not_selected` entries can preserve operator decisions; the complete 39-arm
account is built by joining the maintained registry/requested universe to the
receipt, runtime eligibility, and result artifacts. An admitted real arm records:

- the operator-observed upstream URI and revision;
- declared source files located through environment variables, with byte counts
  and SHA-256 digests (absolute workstation paths are not persisted);
- the operator's license/access decision and review attribution;
- declared and observed split;
- distinct raw-source counts for discovered, accepted, excluded-by-design, and
  rejected-invalid records, with reconciled reasons;
- a bounded, reviewer-attributed semantic mapping check with a documented item
  selection rule and unique `reviewed_cluster_ids`; its
  `reviewed_converted_corpus_sha256` binds that review to the complete converted
  corpus later re-derived by `run_matrix`.

The normal matrix preflight already converts the selected release and records
the emitted-row digest and counts, cluster rule and assignments, source policies,
required metrics, and media-byte conformance. Those machine-derived runtime
inventories remain in the grid/cell artifacts and are bound to the selected
receipt; the operator does not duplicate them in the compact JSON. Raw-source
counts remain separate from emitted `DataPoint` counts because a converter may
expand one released item into several policy, threshold, or media variants.

## Evidence boundary

Machine validation can establish the receipt schema and byte digest, selected
registry correspondence, declared-file hashes, count arithmetic, and current
runtime conversion/media evidence. Revision identity, source completeness,
license/access acceptability, and semantic fidelity include operator judgement.
The receipt therefore does not establish upstream authenticity, provide legal
advice, establish benchmark representativeness or evaluator validity, attest a
provider/model route, or contain a model result.

Use `CANNOT-VERIFY` in operator notes and mark an included arm `blocked` when a
required fact cannot be established. Use `not_selected` for an optionally
included known arm outside the current program. In the final fixed-universe
join, neither disposition is removed from coverage accounting or converted to
zero.

## Receipt shape and validation

Before authoring the receipt, run the bounded, no-provider, one-real-arm
`run_matrix --dry-run` observation in
[`RUN_AND_RETURN.md`, section 4.1](../experiments/RUN_AND_RETURN.md#41-validate-the-compact-source-receipt).
Its exact `<arm>__mock__replay__<run_id>.manifest.json` exposes
`config.run.sampling_audit.full_converted_corpus_sha256`, `total_cluster_ids`, and
`selected_cluster_ids`; its sibling attempts JSONL exposes the converted rows
selected for manual comparison with the raw source. Copy the full digest and
only the unique cluster IDs actually reviewed into the semantic-review fields.
This observation is conversion diagnostics, not admitted experiment evidence.

Write one manually reviewed receipt for the exact
`experiments/source-instances.json` used by the run. Do not insert guessed
revisions, hashes, counts, licenses, or review outcomes.

This non-empirical shape example uses syntactically valid sentinel digests and
example.invalid identifiers, not observations. Replace every value with reviewed
evidence and include every selected real arm. The schema also permits optional
blocked/not-selected entries containing only configuration fields, disposition,
and reason; it does not require the receipt itself to enumerate all 39 arms.

```json
{
  "schema": "ura-source-conformance/1",
  "claim_scope": "acquisition_and_conversion_traceability_only",
  "arms": [{
    "arm_id": "strongreject_official",
    "converter": "strongreject",
    "path_env": "URA_STRONGREJECT_OFFICIAL_PATH",
    "source_label": "StrongREJECT pinned harmful prompts",
    "split": "official-complete",
    "disposition": "admitted",
    "reason": "non-empirical schema example",
    "upstream_uri": "https://example.invalid/upstream",
    "requested_revision": "0000000000000000000000000000000000000000",
    "observed_revision": "0000000000000000000000000000000000000000",
    "consumed_input": {
      "kind": "file",
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "bytes": 1
    },
    "components": [],
    "operator_decision": {
      "decision": "approved",
      "access_status": "not_required",
      "license_identifier_or_notice": "non-empirical notice example",
      "reviewer": "example reviewer",
      "reviewed_at": "2026-08-12T12:00:00+03:00",
      "evidence_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "notes": "non-empirical license/access decision example"
    },
    "raw_records": {
      "discovered": 1,
      "accepted": 1,
      "excluded_by_design": 0,
      "rejected_invalid": 0,
      "reasons": {}
    },
    "semantic_review": {
      "status": "passed",
      "reviewer": "example reviewer",
      "reviewed_at": "2026-08-12T12:00:00+03:00",
      "selection_rule": "non-empirical bounded-rule example",
      "reviewed_cluster_ids": ["example-cluster-id"],
      "reviewed_converted_corpus_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "notes": "mapping review example only; not benchmark validation"
    }
  }]
}
```

For a directory-backed `consumed_input`, use only `{"kind":"directory"}` and
add at least one exact retained source/release file to `components`, each with
`role`, `path_env`, `sha256`, and `bytes`. The receipt omits the selected source
configuration digest: the validator and matrix compute and retain that digest
from the exact selected registry entries.

Calculate the exact byte digest and run the single validator. The validator
makes no provider call and does not download data:

```bash
export SOURCE_CONFORMANCE='runs/thesis/source-conformance.json'
export SOURCE_CONFORMANCE_SHA256="$(sha256sum "$SOURCE_CONFORMANCE" | awk '{print $1}')"
python -m experiments.source_conformance \
  --manifest "$SOURCE_CONFORMANCE" \
  --sha256 "$SOURCE_CONFORMANCE_SHA256" \
  --source-config experiments/source-instances.json
```

Then expose the same exact receipt to `rig_check` and `run_matrix`:

```bash
export URA_SOURCE_CONFORMANCE_MANIFEST="$SOURCE_CONFORMANCE"
export URA_SOURCE_CONFORMANCE_SHA256="$SOURCE_CONFORMANCE_SHA256"
```

A single receipt may cover the union of real arms used by later lanes; a matrix
binds only its selected subset. If receipts are lane-specific, switch both
environment variables together to the exact validated receipt and digest before
that lane's `rig_check` and measured run.

The driver rehashes the selected arms' declared files, reuses the runtime
converted/cluster/policy/metric/media checks, retains the exact receipt in the
return tree, and binds only selected receipt evidence into grid/run identity.
Changing an unrelated local-registry entry must not be represented as changing
the selected arm's evidence.
