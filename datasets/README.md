# Dataset boundary

Released benchmark corpora are not redistributed in this repository. Configure
each real source through its documented `URA_<CORPUS>_PATH` environment variable
and, for local media, an approved `URA_MEDIA_ROOTS` value. The matrix driver
records the resolved source identity, full-source and selected-sample hashes,
selection indices/identifiers, and converter accounting in its artifacts.

The `synth` corpus is generated in code solely for offline smoke and regression
tests. It is not a substitute for a released corpus and its outputs are never
publishable model measurements.

Legacy zero-byte files formerly stored under `datasets/samples/` were not data
or valid fixtures and have been removed. Missing, empty, malformed, or
schema-drifted requested corpora now fail closed instead of shrinking a run.
