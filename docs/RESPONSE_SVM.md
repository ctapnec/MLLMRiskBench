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

In **Tools -> Analysis and native imports -> Retained response classifiers**,
choose **export** first. Supply the campaign SQLite path, retained source
candidate JSON/JSON.GZ, one or more campaign IDs, the hosted campaign defining
the matched input population, and one exact Haiku condition. The fresh output
directory receives `dataset.jsonl` and an extraction report. Original responses
are read once per selected file; the command makes no recursive model-store
scan and never reads provider credentials.

Then choose **evaluate**, select that dataset and a different fresh output
directory. Seed, feature-character allowance, bootstrap draws, held-out model
prefixes and held-out corpus IDs are configurable. Jobs retains the log and
analysis artifacts. Export and evaluation are separate reproducible operations,
not generation jobs. The same CLI is:

```bash
python -m experiments.response_svm --export --database /path/console.db \
  --candidates /path/source-candidates.json.gz --campaign LOCAL_ID \
  --campaign API_ID --matched-campaign API_ID --judge-condition EXACT_JUDGE \
  --exclude-model ollama:mollysama/rwkv --out /path/svm-dataset
python -m experiments.response_svm --evaluate \
  --dataset /path/svm-dataset/dataset.jsonl --out /path/svm-analysis \
  --seed 0 --bootstrap 1000
```

The three classifiers completed a rig evaluation on 7,541 static-text records
on 13 September 2026. Focused regressions and leakage mutation checks passed.
An actual browser-launched export produced 4,682 hosted records in four seconds
on an isolated console; its job completed, with no JavaScript errors or stuck
busy state. This covers export, not a paid campaign's full Build flow. The
general Build acceptance and Google collection are separate from this SVM
export check; their current state is recorded in the campaign plans. Exact
numerical results and split membership accompany each run;
the thesis reports observed limitations instead of selecting a universal winner.

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
