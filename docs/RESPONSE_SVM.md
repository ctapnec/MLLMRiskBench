# Response classifiers from retained campaign data

This optional analysis complements, and never replaces, recorded campaign
judgments. It is separate from the synthetic compatibility-rule experiment.
The user approved the three-classifier study on 13 September 2026. Human
validation remains a separate, unfinished assessment.

## Fixed protocol

- Harmful compliance: on inputs expected to be refused, predict whether the
  output-specific Haiku label is `violation`.
- Over-refusal: on benign inputs (`safe_answer` or `comply_safely`), predict
  whether that label is `over_refusal`.
- Disagreement: on harmful inputs with valid local and Haiku labels, predict
  disagreement on the violation endpoint. This does not identify the correct
  judge. Inapplicable local decisions are not negative examples.

The initial experiment uses static, text-only retained outputs and one exact
Haiku condition. Local outputs are restricted to inputs assigned in the hosted
campaign. Missing/invalid records, unsupported modalities, unresolved source
metadata and ambiguous local judging conditions are counted explicitly. Usable
truncated text is retained and reported separately. No generated reasoning or
judge rationale becomes a feature. No new target or judge call is made.

All outputs for an input, exact duplicate prompts across sources, and related
source-cluster variants share one connected split group. Freeze a seeded
60/20/20 group split before fitting. Vocabulary and inverse document frequencies
are learned on training data only. Choose C from 0.1, 1 and 10 by validation
macro-F1, never by test performance. Keep the original split for model/corpus
holdouts; remove that domain from training and validation and evaluate its
previously unseen test inputs. Unsupported class support is reported, not repaired
by searching seeds. This is not a random row split.

Compare prompt-only, response-only, and separately encoded prompt-plus-response
linear SVMs; add majority and logistic-regression baselines. Use word unigrams/
bigrams and character 3-5 grams. Feature extraction keeps at most 20,000
characters per field (equal beginning/end portions), and reports clipping;
this is an analysis-resource limit, not a generation-token setting. Run with two
CPU threads on the rig. The existing `synthetic` optional dependency supplies
scikit-learn; do not reinstall an already working environment.

Report response counts, input groups, class support, precision/recall, macro-F1,
average precision, confusion matrices, and group-bootstrap intervals. For
disagreement, also report captured disputes when reviewing the top 10%, 20%
and 40% of scored outputs, compared with random selection. Report model/corpus
facets and truncation separately, without a universal safety score or a claim
of independent response observations. Human accuracy is not established by
fidelity to Haiku. Source policy identifiers remain metadata, not features:
this study does not test generalization to unseen policy definitions.

As an exploratory reuse baseline, combine the harmful-compliance SVM's saved
test prediction with the already known local verdict. Disagreement is their
binary difference; reverse the SVM's score when the local judge predicts a
violation. This needs no new model fit and tests whether the third SVM adds
value over the first classifier and existing local evaluation. Haiku labels
score this baseline but do not determine its predictions or ranking.

## CLI and UI flow

Open **Campaigns -> your campaign -> SVM analysis**. Choose the saved local
input source, matched input campaign and recorded Haiku condition. Optionally
include local counterparts. **Start classifier study** automatically extracts
input metadata, exports labeled static-text answers, evaluates the fixed
three-task protocol and packages reusable classifiers. Its job is grouped
under the campaign. Output locations and intermediate files are system-managed.

**Saved analyses** links previous work. **Resume unfinished analysis** reuses
completed stages and retains failed attempts. It also handles an interruption
between stage completion and controller publication. Changed scientific
settings require a new study. The interface does not silently fill missing
labels, refit completed work or treat insufficient class support as success.
If Runner finalized a response checkpoint after indexing it, dataset export
resolves the same saved output in its final file by response identity, not by
the old line number. Both indexed and resolved source locations are retained;
missing or duplicate identities remain errors. This reads only the selected
response files and makes no generation or judging calls.
Stats keeps unfinished studies selectable but offers report/figure downloads
only when their saved report is available.

The CLI equivalent is `python -m experiments.response_svm --study`, with
`--database`, one or more `--campaign`, `--matched-campaign`,
`--judge-condition` and `--out`. Use `--source-campaign` for already-indexed
local attempts, including retained partial outputs. This reads selected saved
files and checks record ownership without repeating corpus reconstruction or
historical grid validation. Missing source metadata is reported explicitly.
Advanced callers can supply explicit `--source-root` and `--run-id` selections,
or an existing `--candidates` file. The same output directory and arguments
resume that study; a different selection is rejected.

Raw export/evaluate/package/predict modes remain available under **Tools ->
Advanced CLI tools and troubleshooting -> Analysis and native imports**.
They support exceptional imports and trusted-package prediction, not required
operator handoffs. Source files are read for selected data; no model-store
scan or provider calls occur. UI-launched analysis caps numerical-library
threads at two and records the analysis code checkout separately from Runner.

See [Small campaigns, section 10](SMALL_CAMPAIGNS.md#10-optional-response-svm-analysis)
for exact clicks. A few demonstration answers do not establish held-out
accuracy, even when every preparation stage completes.

The earlier rig study evaluated 7,541 static-text records on 13 September 2026.
Its numerical results, predictions and split membership remain retained. An
isolated browser-launched export also produced 4,682 hosted records without
provider calls. The automatic workflow changes operator handoffs, not those
historical results or their scientific limitations.

## Reusable fitted classifiers

The study runner fits real scikit-learn LinearSVC classifiers, not heuristic
rules or synthetic label stand-ins. Each of the three tasks has prompt-only,
response-only and combined feature representations. The combined representation
keeps prompt and response vocabularies separate. Scores are signed,
uncalibrated decision margins, never confidence probabilities.

Use **package** with the exported dataset, completed study report and saved
predictions. It reconstructs only the nine validation-selected primary fits
on their original training partition. It does not repeat the C search,
held-out-model trials, bootstrap or generation. Every reconstructed held-out
decision and score must reproduce the original study before the fitted
classifiers and TF-IDF transformations are saved. Packaging also verifies
predictions after serialization and reload.

Use **predict** to apply that saved artifact to new retained static-text rows.
This performs no fitting and needs no Haiku label. Minimum fields are `id`,
`response`, `expected_behavior`, `modality: text`, and `framework: replay`;
prompt-based representations also need `prompt`. Disagreement prediction needs
a valid `local_label` because an absent local decision is not agreement.
Missing responses, unsupported modalities and inapplicable tasks receive
explicit dispositions rather than invented predictions. The optional derived
disagreement score uses the harmful classifier and the known local verdict.

```bash
python -m experiments.response_svm --package --dataset /path/svm-dataset/dataset.jsonl \
  --study-result /path/svm-analysis/result.json \
  --study-predictions /path/svm-analysis/predictions.json --out /path/svm-fitted
python -m experiments.response_svm --predict --models /path/svm-fitted/models.joblib \
  --dataset /path/new-retained-rows.jsonl --features response --out /path/svm-predictions
```

All four modes are available through the same Tools form. Load only fitted
artifacts created by this trusted workflow: joblib uses Python object
serialization and must not load untrusted files. Reuse the recorded scikit-learn
version. These exploratory classifications remain separate from campaign
judgments and are never installed as automatic safety gates or replacements
for local, hosted or independent human evaluation.

## Results in the console

**Stats -> SVM results** displays retained studies, including registered CLI
studies and new UI analysis jobs. Select the study, task and evaluation split.
The chart displays held-out SVM macro-F1 and recorded input-group bootstrap
intervals. The accompanying table includes baselines, average precision,
test-class counts and test-group support. Different studies and splits are not
pooled. Missing estimates remain explicit. CSV and SVG exports preserve the
selection; CSV also records teacher, split seed and population counts.

Opening Stats reads the selected result report only. It does not read training
datasets, load fitted pickle files, recalculate hashes or fit classifiers.
Study registration stores a relative artifact reference and associated
campaigns; it does not fabricate an old console job. UI studies are discovered
from their recorded execution arguments and appear without an import step.
