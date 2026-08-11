# Run and return: Fable versus GPT-5.6 Sol

This is the complete operator path from a clean machine to a returnable
experiment artifact. The two direct grids have not been executed yet. A dry
run proves only that the local plumbing works; it is not measured evidence.

The two target conditions are:

```text
anthropic-fable:claude-fable-5;effort=high;max_tokens=25000
openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns
```

This is a cross-provider endpoint comparison, not a same-base causal ablation.
Do not substitute a different endpoint silently. If either exact endpoint is
not visible to the account, stop and record that fact.

The run uses every supported input combination available in the selected
official corpora: StrongREJECT supplies text, while MM-SafetyBench and
MOSSBench supply text+image. Replay exercises text and text+image on both
targets. The bounded Crescendo run is restricted to StrongREJECT text; it does
not claim multimodal adaptivity. The maintained target adapters do not support
audio or video, and these three corpora provide neither, so this study must not
claim audio or video coverage.

## 1. Machine requirements

Install before starting:

- Git;
- Python 3.12 or 3.13 (the project requires `>=3.12,<3.14`);
- an archive extractor for the MM-SafetyBench image ZIP; and
- enough disk space for the repositories, 5,040 MM-SafetyBench images, run
  artifacts and backups.

Check the tools:

```bash
git --version
python3.12 --version
```

PowerShell:

```powershell
git --version
py -3.12 --version
```

The corpora contain harmful prompts and images. Use access-controlled storage,
review the upstream licences, and ensure this academic use is permitted. In
particular, MM-SafetyBench is published for non-commercial research use, and
MOSSBench prohibits using the test set for training.

## 2. Download and install URA-Bench

POSIX shell:

```bash
mkdir -p "$HOME/ura-work"
cd "$HOME/ura-work"
git clone https://github.com/ctapnec/MLLMRiskBench.git
cd MLLMRiskBench
git switch main
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,analysis,api,guardrail]"
```

Windows PowerShell:

```powershell
$Work = Join-Path $HOME 'ura-work'
New-Item -ItemType Directory -Force -Path $Work | Out-Null
Set-Location $Work
git clone https://github.com/ctapnec/MLLMRiskBench.git
Set-Location (Join-Path $Work 'MLLMRiskBench')
git switch main
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,analysis,api,guardrail]"
```

If PowerShell blocks the activation script, set an appropriate execution
policy for the current process or invoke `.venv\Scripts\python.exe` explicitly.
Do not disable machine security controls globally.

## 3. Download the three official corpora

Create a sibling `corpora` directory and check out the exact revisions accepted
by the maintained converters. These revisions are compatibility requirements:
the converters reject altered, incomplete or differently structured releases
before a paid call begins.

POSIX shell:

```bash
cd "$HOME/ura-work"
mkdir -p corpora

git clone https://github.com/alexandrasouly/strongreject.git corpora/strongreject
git -C corpora/strongreject checkout f7cad6c17e624e21d8df2278e918ae1dddb4cb56

git clone https://github.com/isXinLiu/MM-SafetyBench.git corpora/MM-SafetyBench
git -C corpora/MM-SafetyBench checkout b80eedea3db312c09ded2082813390f68e750ef3

git clone https://github.com/xirui-li/MOSSBench.git corpora/MOSSBench
git -C corpora/MOSSBench checkout 8d68b0614b39d8990a508e03d99975832f399db2
```

Windows PowerShell:

```powershell
$Work = Join-Path $HOME 'ura-work'
$Corpora = Join-Path $Work 'corpora'
New-Item -ItemType Directory -Force -Path $Corpora | Out-Null

git clone https://github.com/alexandrasouly/strongreject.git (Join-Path $Corpora 'strongreject')
git -C (Join-Path $Corpora 'strongreject') checkout f7cad6c17e624e21d8df2278e918ae1dddb4cb56

git clone https://github.com/isXinLiu/MM-SafetyBench.git (Join-Path $Corpora 'MM-SafetyBench')
git -C (Join-Path $Corpora 'MM-SafetyBench') checkout b80eedea3db312c09ded2082813390f68e750ef3

git clone https://github.com/xirui-li/MOSSBench.git (Join-Path $Corpora 'MOSSBench')
git -C (Join-Path $Corpora 'MOSSBench') checkout 8d68b0614b39d8990a508e03d99975832f399db2
```

StrongREJECT and MOSSBench are complete after those checkouts. The
MM-SafetyBench repository contains the question manifests but not the image
archive. Download `MM-SafetyBench(imgs).zip` from the authors'
[official Google Drive file](https://drive.google.com/file/d/1xjW9k-aGkmwycqGCXbru70FaSKhSDcR_/view?usp=sharing),
then extract it so that the scenario directories are directly below
`MM-SafetyBench/data/imgs`.

POSIX extraction example:

```bash
mkdir -p "$HOME/ura-work/corpora/MM-SafetyBench/data/imgs"
unzip '/path/to/MM-SafetyBench(imgs).zip' \
  -d "$HOME/ura-work/corpora/MM-SafetyBench/data/imgs"
```

PowerShell extraction example:

```powershell
$Zip = 'C:\path\to\MM-SafetyBench(imgs).zip'
$ImageRoot = Join-Path $HOME 'ura-work\corpora\MM-SafetyBench\data\imgs'
New-Item -ItemType Directory -Force -Path $ImageRoot | Out-Null
Expand-Archive -LiteralPath $Zip -DestinationPath $ImageRoot -Force
```

If the ZIP utility creates one extra wrapper directory, move only its 13
scenario directories into `data/imgs`. The final required layout is:

```text
corpora/
  strongreject/
    strongreject_dataset/strongreject_dataset.csv
  MM-SafetyBench/
    data/processed_questions/01-Illegal_Activitiy.json
    data/processed_questions/...                         (13 JSON files total)
    data/imgs/01-Illegal_Activitiy/SD/0.jpg
    data/imgs/01-Illegal_Activitiy/SD_TYPO/0.jpg
    data/imgs/01-Illegal_Activitiy/TYPO/0.jpg
    data/imgs/...                                        (all 13 scenarios)
  MOSSBench/
    information.csv
    images/1.png
    images/...                                           (1.png through 300.png)
```

The converter gates expect:

| Corpus | Source population | Emitted inputs | Input combination |
| --- | ---: | ---: | --- |
| StrongREJECT | 313 prompts | 313 | text |
| MM-SafetyBench | 1,680 question clusters | 5,040 | text+image |
| MOSSBench | 300 benign pairs | 300 | text+image |

StrongREJECT is intentionally tied to the paper repository above even though
that repository now points new users to a successor implementation. URA-Bench
uses its dataset and a StrongREJECT-style judge; it does not claim to run the
official evaluator. MM-SafetyBench common ASR and MOSSBench common FRR are also
URA proxies, not executions of the upstream evaluators.

These are the only corpora required for the Chapter V case study. Do not
download every source or native engine registered by URA-Bench for this run.
R-Judge and GPTGeoChat are optional source-specific classification tracks;
AgentDojo and the other native integrations retain their upstream environments
and metrics in a separate results root. They do not enter the main common
ASR/FRR cohort, human-audit cohort, or figures. See the README's
"Source-specific tracks" section and `docs/NATIVE_ENGINE_IMPORTS.md` when one of
those separate evaluations is intentionally in scope.

## 4. Configure paths and credentials

POSIX shell:

```bash
export URA_STRONGREJECT_PATH="$HOME/ura-work/corpora/strongreject/strongreject_dataset/strongreject_dataset.csv"
export URA_MMSAFETY_PATH="$HOME/ura-work/corpora/MM-SafetyBench"
export URA_MOSSBENCH_PATH="$HOME/ura-work/corpora/MOSSBench"
export URA_MEDIA_ROOTS="$HOME/ura-work/corpora/MM-SafetyBench/data/imgs:$HOME/ura-work/corpora/MOSSBench"

FABLE='anthropic-fable:claude-fable-5;effort=high;max_tokens=25000'
SOL='openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns'
JUDGE='anthropic:<exact-account-visible-judge-id>'
GUARD='meta-llama/Llama-Guard-3-8B'
GUARD_REV='7327bd9f6efbbe6101dc6cc4736302b3cbb6e425'
GUARD_DEVICE='cuda:0'
TARGETS="$FABLE,$SOL"
```

Windows PowerShell:

```powershell
$Work = Join-Path $HOME 'ura-work'
$Corpora = Join-Path $Work 'corpora'
$env:URA_STRONGREJECT_PATH = Join-Path $Corpora 'strongreject\strongreject_dataset\strongreject_dataset.csv'
$env:URA_MMSAFETY_PATH = Join-Path $Corpora 'MM-SafetyBench'
$env:URA_MOSSBENCH_PATH = Join-Path $Corpora 'MOSSBench'
$env:URA_MEDIA_ROOTS = (Join-Path $Corpora 'MM-SafetyBench\data\imgs') + ';' + (Join-Path $Corpora 'MOSSBench')

$Fable = 'anthropic-fable:claude-fable-5;effort=high;max_tokens=25000'
$Sol = 'openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns'
$Judge = 'anthropic:<exact-account-visible-judge-id>'
$Guard = 'meta-llama/Llama-Guard-3-8B'
$GuardRevision = '7327bd9f6efbbe6101dc6cc4736302b3cbb6e425'
$GuardDevice = 'cuda:0'
$Targets = "$Fable,$Sol"
```

Replace the judge placeholder with one exact model ID visible to the account.
Inject `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` into the process environment
from an approved secret manager. Never put keys in this file, `RUNNOTE.md`, a
command-line argument, a JSON artifact, a filename or a return archive.

The middle judge stage uses the gated
[`meta-llama/Llama-Guard-3-8B`](https://huggingface.co/meta-llama/Llama-Guard-3-8B)
repository at the exact commit above. Accept the repository's access terms with
the operator's Hugging Face account, inject `HF_TOKEN` from the secret manager,
and download the exact revision before running the sanity checks. These commands
populate the normal Hugging Face cache without placing the token in an argument:

POSIX shell:

```bash
python -c "import os; from huggingface_hub import snapshot_download; snapshot_download(repo_id='$GUARD', revision='$GUARD_REV', token=os.environ['HF_TOKEN'])"
```

PowerShell:

```powershell
python -c "import os; from huggingface_hub import snapshot_download; snapshot_download(repo_id='$Guard', revision='$GuardRevision', token=os.environ['HF_TOKEN'])"
```

If access is denied, the token is absent, or the exact revision cannot be
downloaded, stop. Do not replace the guard model or revision silently.

The media-root order matters. Keep MM-SafetyBench first and MOSSBench second
when resuming or moving the artifact tree.

## 5. Run the offline sanity checks

From the `MLLMRiskBench` directory with the virtual environment active:

POSIX shell:

```bash
python -m pytest -p no:cacheprovider
python -m ruff check --no-cache .
python -m compileall src experiments
python -m experiments.run_matrix --dry-run \
  --attackers replay,crescendo --judges rules,guardrail,llm \
  --guardrail-model "$GUARD" --guardrail-revision "$GUARD_REV" --guardrail-device "$GUARD_DEVICE" \
  --corpora synth --limit 12 --seeds 0,1 \
  --max-queries 4 --max-turns 4 --out runs/dry
python -m experiments.figures --synth --out runs/figure-check
```

PowerShell:

```powershell
python -m pytest -p no:cacheprovider
python -m ruff check --no-cache .
python -m compileall src experiments
python -m experiments.run_matrix --dry-run `
  --attackers replay,crescendo --judges rules,guardrail,llm `
  --guardrail-model $Guard --guardrail-revision $GuardRevision --guardrail-device $GuardDevice `
  --corpora synth --limit 12 --seeds 0,1 `
  --max-queries 4 --max-turns 4 --out runs/dry
python -m experiments.figures --synth --out runs/figure-check
```

The dry run must exit zero, have no failed cells, exercise the local guardrail,
and produce only mock-target/mock-LLM-judge-marked artifacts. The synthetic
figures must retain the illustrative watermark. This check can be slow on its
first guardrail load, but it makes no hosted model or judge call.

## 6. Run the no-call rig check

The experiment uses two direct grids under one `runs/main` return tree. This
avoids an impractical all-corpus adaptive run:

| Direct grid | Inputs | Target calls | Local guardrail evaluations | Hosted LLM-judge calls | Declared HTTP attempts |
| --- | ---: | ---: | ---: | ---: | ---: |
| Replay: all three corpora | 5,653 | 22,612 | 22,612 | 22,612 | 90,448 |
| Crescendo: StrongREJECT only | 313 | 5,008 | 2,504 | 2,504 | 12,520 |
| Operator total | - | 27,620 | 25,116 | 25,116 | 102,968 |

The guardrail stage is local and runs on every policy-evaluable response, but
it does not consume the hosted LLM-judge or HTTP-attempt ceilings. These are
conservative call bounds, not token, latency, or currency estimates. Confirm
provider pricing, quotas, and the 90-day operational window before proceeding.

Run both checks below. Together they load and validate every selected corpus
and image, construct the selected SDK-backed components, print policy-stratum
counts and call totals, and make no target or judge generation request.

POSIX shell:

```bash
python -m experiments.rig_check \
  --api "$TARGETS" \
  --attackers replay \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$GUARD" --guardrail-revision "$GUARD_REV" --guardrail-device "$GUARD_DEVICE" \
  --corpora strongreject,mmsafety,mossbench \
  --limit 0 --sample-seed 0 --seeds 0,1 \
  --max-queries 4 --max-turns 4 \
  --group model,risk,modality,source_policy_id,source_policy_version \
  --max-total-target-calls 22612 \
  --max-total-judge-calls 22612 \
  --max-total-http-attempts 90448 \
  --deadline-seconds 7776000

python -m experiments.rig_check \
  --api "$TARGETS" \
  --attackers crescendo \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$GUARD" --guardrail-revision "$GUARD_REV" --guardrail-device "$GUARD_DEVICE" \
  --corpora strongreject \
  --limit 0 --sample-seed 0 --seeds 0,1 \
  --max-queries 4 --max-turns 4 \
  --group model,risk,modality,source_policy_id,source_policy_version \
  --max-total-target-calls 5008 \
  --max-total-judge-calls 2504 \
  --max-total-http-attempts 12520 \
  --deadline-seconds 7776000
```

PowerShell:

```powershell
python -m experiments.rig_check `
  --api $Targets `
  --attackers replay `
  --judges rules,guardrail,llm --judge-model $Judge `
  --guardrail-model $Guard --guardrail-revision $GuardRevision --guardrail-device $GuardDevice `
  --corpora strongreject,mmsafety,mossbench `
  --limit 0 --sample-seed 0 --seeds 0,1 `
  --max-queries 4 --max-turns 4 `
  --group model,risk,modality,source_policy_id,source_policy_version `
  --max-total-target-calls 22612 `
  --max-total-judge-calls 22612 `
  --max-total-http-attempts 90448 `
  --deadline-seconds 7776000

python -m experiments.rig_check `
  --api $Targets `
  --attackers crescendo `
  --judges rules,guardrail,llm --judge-model $Judge `
  --guardrail-model $Guard --guardrail-revision $GuardRevision --guardrail-device $GuardDevice `
  --corpora strongreject `
  --limit 0 --sample-seed 0 --seeds 0,1 `
  --max-queries 4 --max-turns 4 `
  --group model,risk,modality,source_policy_id,source_policy_version `
  --max-total-target-calls 5008 `
  --max-total-judge-calls 2504 `
  --max-total-http-attempts 12520 `
  --deadline-seconds 7776000
```

Do not start either paid grid unless both checks exit zero and their printed
bounds equal the table. These local checks confirm SDK imports and nonblank
credential variables, not endpoint entitlement, quota, remote reachability or
valid keys.

## 7. Run the experiment

Run Replay first and Crescendo second. Each direct grid has its own output
directory, durable ledger, deadline, and completion records under the common
`runs/main` parent. Resume a stopped grid only by rerunning its identical
command. Do not copy artifacts between the two directories or change arguments
while resuming.

POSIX shell:

```bash
python -m experiments.run_matrix \
  --api "$TARGETS" \
  --attackers replay \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$GUARD" --guardrail-revision "$GUARD_REV" --guardrail-device "$GUARD_DEVICE" \
  --corpora strongreject,mmsafety,mossbench \
  --limit 0 --sample-seed 0 --seeds 0,1 \
  --max-queries 4 --max-turns 4 \
  --group model,risk,modality,source_policy_id,source_policy_version \
  --max-total-target-calls 22612 \
  --max-total-judge-calls 22612 \
  --max-total-http-attempts 90448 \
  --deadline-seconds 7776000 \
  --out runs/main/replay

python -m experiments.run_matrix \
  --api "$TARGETS" \
  --attackers crescendo \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$GUARD" --guardrail-revision "$GUARD_REV" --guardrail-device "$GUARD_DEVICE" \
  --corpora strongreject \
  --limit 0 --sample-seed 0 --seeds 0,1 \
  --max-queries 4 --max-turns 4 \
  --group model,risk,modality,source_policy_id,source_policy_version \
  --max-total-target-calls 5008 \
  --max-total-judge-calls 2504 \
  --max-total-http-attempts 12520 \
  --deadline-seconds 7776000 \
  --out runs/main/crescendo-strongreject
```

PowerShell:

```powershell
python -m experiments.run_matrix `
  --api $Targets `
  --attackers replay `
  --judges rules,guardrail,llm --judge-model $Judge `
  --guardrail-model $Guard --guardrail-revision $GuardRevision --guardrail-device $GuardDevice `
  --corpora strongreject,mmsafety,mossbench `
  --limit 0 --sample-seed 0 --seeds 0,1 `
  --max-queries 4 --max-turns 4 `
  --group model,risk,modality,source_policy_id,source_policy_version `
  --max-total-target-calls 22612 `
  --max-total-judge-calls 22612 `
  --max-total-http-attempts 90448 `
  --deadline-seconds 7776000 `
  --out runs/main/replay

python -m experiments.run_matrix `
  --api $Targets `
  --attackers crescendo `
  --judges rules,guardrail,llm --judge-model $Judge `
  --guardrail-model $Guard --guardrail-revision $GuardRevision --guardrail-device $GuardDevice `
  --corpora strongreject `
  --limit 0 --sample-seed 0 --seeds 0,1 `
  --max-queries 4 --max-turns 4 `
  --group model,risk,modality,source_policy_id,source_policy_version `
  --max-total-target-calls 5008 `
  --max-total-judge-calls 2504 `
  --max-total-http-attempts 12520 `
  --deadline-seconds 7776000 `
  --out runs/main/crescendo-strongreject
```

A usable return requires both commands to exit zero, zero failed cells in both
grid descriptors, and a completion marker for every requested cell. The Replay
grid must report executed text and text+image coverage for both exact targets;
the Crescendo grid must report executed text coverage and is not multimodal
evidence. Provider refusal is a measured response state; transport, parsing,
missing-media and exhausted-budget errors are not measurements.

If a process stops, correct the external cause and rerun that grid's identical
command. Use `--reset-open-circuits` only after correcting the recorded provider
or judge failure that opened the circuit.

## 8. Run read-only diagnostics

These commands make no target or judge calls:

```bash
python -m experiments.judge_sensitivity --results runs/main
python -m experiments.kappa --results runs/main
python -m experiments.transfer_matrix --results runs/main --attacker replay

python -m experiments.paired_compare --results runs/main \
  --left-model "$FABLE" --right-model "$SOL" \
  --attacker replay --corpus strongreject \
  --output runs/main/paired-strongreject-replay.json

python -m experiments.paired_compare --results runs/main \
  --left-model "$FABLE" --right-model "$FABLE" \
  --attacker replay --right-attacker crescendo --corpus strongreject \
  --output runs/main/adaptivity-fable-strongreject.json

python -m experiments.paired_compare --results runs/main \
  --left-model "$SOL" --right-model "$SOL" \
  --attacker replay --right-attacker crescendo --corpus strongreject \
  --output runs/main/adaptivity-sol-strongreject.json
```

In PowerShell, use `$Fable` and `$Sol` in place of `$FABLE` and `$SOL`, and use
the backtick for line continuation. Keep corpus and source-policy estimates
separate. Do not report a universal safety score, and do not treat the
cross-provider contrast as causal.

## 9. Prepare and analyse the human audit

Choose a feasible number of unique prompt/intent clusters after inspecting the
completed population. The example below selects 200 clusters. It is not a claim
that 200 is automatically adequate; report uncertainty and the achieved
per-stratum counts.

```bash
python -m experiments.human_audit \
  --results runs/main --prepare 200 \
  --output runs/main/human-audit-sample.csv \
  --acknowledge-sensitive-content
```

The command writes an automated-label-blinded but model-visible CSV and rater
instructions. Model and run identity remain in the file for a lossless artifact
join, so this is not double-blind or model-identity-blinded. Every selected row
must be independently labelled by at least two qualified raters across all
required dimensions. Before rating an image row, resolve every
`@media-root/<index>/<relative-path>` in `media_references` against the ordered
`URA_MEDIA_ROOTS`, verify its MIME and SHA-256, and view it. The CSV also retains
the source-policy ID, version, intended metric, and short policy instruction.
Leave an unresolved media row unrated for remediation; analysis fails closed on
missing, altered, or unverifiable context. Preserve every metadata column,
duplicate rows for each rater, and use adjudication for unresolved disagreements. Do not expose the
automated judgments to raters, and report model-visibility as a possible source
of expectancy bias.

After the completed multi-rater CSV is returned:

```bash
python -m experiments.human_audit \
  --results runs/main \
  --labels runs/main/human-audit-labelled.csv
```

Until this step succeeds, judge validity is pending. Small or sparse strata
must be reported as limited-sample evidence with intervals, not as validated
rankings.

## 10. Render the measured figures

The human-audit command writes `runs/main/human_audit.json`. Bind that exact
file when rendering. The figures remain sample-conditional and do not claim
population-wide judge validity.

POSIX shell:

```bash
HUMAN_AUDIT_SHA256="$(sha256sum runs/main/human_audit.json | awk '{print $1}')"
python -m experiments.figures \
  --results runs/main \
  --left-model "$FABLE" --right-model "$SOL" \
  --human-audit runs/main/human_audit.json \
  --human-audit-sha256 "$HUMAN_AUDIT_SHA256" \
  --out runs/main/figures
```

PowerShell:

```powershell
$HumanAuditSha256 = (Get-FileHash runs\main\human_audit.json -Algorithm SHA256).Hash.ToLowerInvariant()
python -m experiments.figures `
  --results runs/main `
  --left-model $Fable --right-model $Sol `
  --human-audit runs/main/human_audit.json `
  --human-audit-sha256 $HumanAuditSha256 `
  --out runs/main/figures
```

Measured mode fails unless the real run cohort and completed human audit are
content-consistent and analysis-ready. It renders one StrongREJECT replay ASR
model comparison, six MM-SafetyBench policy-specific ASR proxy comparisons,
one MOSSBench benign-FRR proxy comparison, and two StrongREJECT
replay-versus-Crescendo comparisons. Those are conditioned estimates with
cluster intervals, not universal scores or causal provider effects.

## 11. Record and return the artifacts

Create `runs/main/RUNNOTE.md`. Record:

- UTC start/end time, hostname, OS, Python version and GPU/driver information;
- `git rev-parse HEAD` and `git status --short`;
- the exact commands and non-secret environment/path choices;
- exact account-visible target and judge IDs, account tier and region;
- the rig-check output, any interruptions/retries and their resolution;
- provider usage/cost reconciliation; and
- whether the human audit is pending or complete.

Also capture the installed package inventory without credentials:

```bash
python -m pip list --format=json > runs/main/environment-packages.json
git rev-parse HEAD > runs/main/harness-commit.txt
git status --short > runs/main/harness-status.txt
```

Before packaging, verify that the return tree contains the grid descriptor,
every manifest/attempt/response/judgment/trail file, completion markers,
aggregates, modality coverage output, durable call ledger, error records,
diagnostics, human-audit files if completed, and `RUNNOTE.md`. Do not return API
keys, shell history, secret-manager exports or unrelated corpora.

POSIX archive:

```bash
tar -czf ura-main-return.tgz runs/main
sha256sum ura-main-return.tgz > ura-main-return.tgz.sha256
```

PowerShell archive:

```powershell
Compress-Archive -Path runs\main -DestinationPath ura-main-return.zip -Force
Get-FileHash ura-main-return.zip -Algorithm SHA256 | Format-List | Out-File ura-main-return.zip.sha256.txt
```

The return is evidence only after integrity checks pass. Any failed, mock,
partial or manually edited artifact remains diagnostic and must not be promoted
to a thesis result.
