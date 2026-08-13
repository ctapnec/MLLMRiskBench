# Synthetic compatibility corpus and linear baselines

`python -m experiments.syn_compat` implements the invalid-pooling validator
(SYN-001) and its transparent linear baselines (SYN-002).

A *result bundle* (`ura-compat-bundle/1`) is one self-contained summary of one
reported result: identity (model, provider, source, policy id/version/hash,
run), execution condition (modality, delivery and evaluator mode, attacker,
defense, judge order, execution type, horizon), construct (metric family/name,
official/native/proxy status, population, unit, denominator, polarity, scale),
support (numerator, support, decided, abstained), the estimate with its
interval, measured/structural-N/A/missing status, and artifact digests. A
*comparison case* (`ura-compat-case/1`) proposes a side-by-side row, pooled
rate, or paired difference over two bundles.

The deterministic oracle classifies each proposal as `compatible`,
`incompatible`, or `abstain` with explicit reason codes covering the twelve
critical incompatibilities (policy, population, static/conversation unit,
horizon/budget, native/proxy, source/run identity, judge/served model,
structural N/A pooled, missing provenance, polarity/denominator, impossible
support/interval, media-transport/evaluator). Side-by-side rows of internally
consistent bundles are always compatible - the evidence-profile principle;
pooling and pairing are gated on the full compatibility key. Unconfirmable
identity (equal policy ids without hashes) yields `abstain`, never a guess.
The rules are authoritative and version-stamped (`compat-rules/1`).

`--generate` writes a deterministic corpus from 32 scenario-times-mutation
templates (12 perturbations each by default; template, family and seed live
only in the sidecar split metadata and are excluded from model features).
`--check` oracles a corpus and fails unless every critical reason is
exercised and the rules catch all hand-authored adversarial cases.
`--evaluate` trains balanced logistic-regression and linear-SVM baselines
(optional dependency group `synthetic`: numpy, scikit-learn) on
pair-comparison indicator features, splitting simultaneously by whole
template, one fully held-out benchmark family, and one fully held-out model
family (the renderer axis is structurally not applicable; no rendering is
used), and reports invalid-comparison recall/FNR, macro-F1, per-class recall,
Brier/ECE calibration, selective prediction, OOD AUROC against the
hand-authored adversarial set, and adversarial agreement - all against the
rules.

Boundaries (fixed by recorded operator decision, ledger Section 11.20): every
number here measures fidelity to the deterministic rules on synthetic
distributions only. SYN-003 (independent real-label validation) was withdrawn,
so no real-world validity, benchmark-generalization, model-ranking, or safety
claim may ever be attached to these outputs; a rendered-chart CNN and any
learned universal safety score remain rejected. Nothing produced by this tool
is campaign evidence or enters any measured tree.
