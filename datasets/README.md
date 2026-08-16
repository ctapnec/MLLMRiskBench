# Dataset boundary

Released benchmark corpora are not redistributed in this repository. Configure
each real source through its documented `URA_<CORPUS>_PATH` environment variable
and, for local media, an approved `URA_MEDIA_ROOTS` value. The matrix driver
records the resolved logical source identity, full converted-source and
selected-sample hashes, selection indices/identifiers, and converter accounting
in its artifacts. The source-instance registry does not establish acquisition.
Before a non-synthetic measured run, a compact content-addressed
`ura-source-conformance/1` receipt must bind the operator-observed upstream
revision, declared source-file hashes, license/access review, raw-source counts,
split, and reviewer-attributed semantic spot-check. The runtime
artifacts remain authoritative for emitted-row, policy, metric, and media
inventories, including the converter-derived cluster rule; see
[`docs/SOURCE_CONFORMANCE.md`](../docs/SOURCE_CONFORMANCE.md).
For an exporter-prepared manifest, raw-source counts come from the retained
export summary at the upstream-input boundary; the consumed JSONL and summary
are hashed separately.

The `synth` corpus is generated in code solely for offline smoke and regression
tests. It is not a substitute for a released corpus and its outputs are never
publishable model measurements.

Legacy zero-byte files formerly stored under `datasets/samples/` were not data
or valid fixtures and have been removed. Missing, empty, malformed, or
schema-drifted requested corpora now fail closed instead of shrinking a run.
