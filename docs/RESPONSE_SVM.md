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

This interface is implemented; focused rig tests, actual retained-data results
and browser acceptance are pending. The general Build preparation acceptance
and the waiting Google campaign remain separate obligations.
