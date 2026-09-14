# A small local campaign through Build

This guide uses the installed Qwen3-VL model and Llama Guard on the rig. It does
not require a framework installation, a model download or a hosted API call.
The destination is a new demonstration campaign, not the thesis Local campaign.
Use a new name and output directory when reproducing the example.

Acceptance status, 14 September: the text probe, saved-answer recovery and
transport-receipt form have passed in production. The image probe and the final
measured text/image example are still undergoing acceptance. The remaining
steps below describe the intended sequence, not a claim that they have passed.

## 1. Create the draft and select the installed models

1. Open <http://localhost:8642/build?work_kind=campaign>.
2. Leave **Campaign** selected under **What are you building?**. In the campaign
   dropdown choose **New campaign**. Enter `My Qwen demonstration` as its name.
3. Open **Pipeline**. Choose **attestation probe**. Enable Text and Image and
   disable Audio, Video and Tool. Select only `xstest_full` initially.
4. Open the target-model picker, choose **Local rig**, select only
   `vllm:Qwen/Qwen3-VL-8B-Instruct`, then click **Done**.
5. Open **Evaluation**. Keep **rules**, uncheck **llm**, and select **guardrail**.
   Leave the defense **none**. Enter the scoring guardrail values below, not
   the similarly named defense guardrail fields.

| Scoring field | Value |
| --- | --- |
| Model | `meta-llama/Llama-Guard-3-8B` |
| Revision | `7327bd9f6efbbe6101dc6cc4736302b3cbb6e425` |
| Device | `cuda:0` |

Static local collection releases the target process before local scoring.
Do not manually start another GPU model beside this job. The selected Qwen
profile uses both GPUs. Its already assessed generation settings are applied
automatically; do not repeat the responsiveness survey or replace its context
allocation with an arbitrary value.

## 2. Set the text probe's bounds

In **Admission**, leave the current project and source receipts supplied by
the console unchanged. Set **--execution-scope-id** to `my-qwen-demonstration`.
Leave the live-attestation rows and maximum-age field empty for this probe.

In **Execution**, set:

| Field | Value |
| --- | --- |
| Per-arm limit | `1` |
| Sampling policy | `seeded_pseudorandom_whole_cluster_prefix_v1` |
| Sample seed / generation seeds | `0` / `0` |
| Maximum queries / turns | `1` / `1` |
| Target answer retries | `1` |
| Target / judge / HTTP ceilings | `16` / `16` / `1` |
| --deadline-seconds | `3600` |
| Local process wall-time cap | Leave empty during probes |
| Output directory | `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-text` |

Uncheck **Exclude tool-conditioned inputs** and leave full model SHA
verification unchecked. The exclusion applies to the standalone synthetic dry
run, not this real probe. HTTP's positive ceiling does not initiate network
calls; the actual local projection should report zero HTTP attempts.

Return to **General** and click **Save campaign**. This opens **Definition**.
Click **Configure in Build**, return to **General**, then **Compose & review**.
Saving and reviewing make no model calls.

## 3. Complete preparation, then run the text probe

Use the buttons on the newly opened job at each step; do not start a second copy.

1. Click **Plan & acquire models for no-call preflight**. Wait for the plan job
   to pass, then click **Acquire sealed models**. This reuses the installed store.
2. When acquisition passes, click **Start no-call preflight**. Wait for it to
   pass. The demonstrated text projection contains one trajectory, at most two
   target attempts, one local guardrail evaluation and zero HTTP attempts.
3. On that job click **Review this exact lane in the builder**. It opens the
   execution review directly. Check that the projection fits the entered caps.
4. Click **Plan & acquire models for this job**. Wait for its plan to pass,
   click **Acquire sealed models**, and wait for acquisition to pass.
5. Click **Start reviewed measured job**. This button currently has a generic
   label: the command must still show **--attestation-probe**, not a measured
   run. This is the first step that makes a real target call.
6. Wait for **passed**. A saved response alone is not completion; local scoring
   and the final result must also finish. The job and its outputs belong to the
   named demonstration campaign.

The initial text example retained a usable 319-token answer in 3.3 seconds;
model loading took longer. A corrected UI handoff recovered its local decision
from the saved answer without regenerating it. That earlier defect is fixed in
the deployed software and is not a step to reproduce.

## 4. Derive the text transport receipt

1. From the demonstration campaign, click **Run tools**.
2. Filter for `live_attestation` and open its form. Keep the demonstration
   campaign selected so this preparation job remains grouped with it.
3. Set **--probe-root** to the text probe output directory from step 2.
4. Set **--execution-scope-id** to `my-qwen-demonstration`.
5. Set **--out** to
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/attestation-text.json`.
   This is a new file name, not a directory. Leave **--validate** and **--sha256**
   empty when deriving it.
6. Click **Start job**. When it passes, keep the output path and the `sha256`
   value printed in its result for the measured lane's Admission tab.

Deriving this receipt makes no additional target or judge call. It establishes
the observed transport path, not benchmark performance or human validity.

## 5. Repeat for one image input

Reopen the same campaign through **Configure in Build**. In Pipeline, uncheck
`xstest_full` and select only `vlsbench_release`. Keep **attestation probe**,
the same model, scope, seed, bounds and evaluation settings. Change Output to
`/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/probe-image`.

Repeat steps 3 and 4, using the image probe root and the new output file
`/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/attestation-image.json`.
Do not start its real probe while another GPU job is active.

## 6. Configure the small measured run

Reopen the same saved campaign in Build:

1. In **Pipeline**, choose **measured** and select `xstest_full` and
   `vlsbench_release`. Keep only Qwen selected as a target.
2. In **Admission**, enter the text and image receipt paths and their printed
   digests in two separate rows. Keep the same scope and set maximum age to
   `24` hours. Refresh only receipts that have actually expired or changed.
3. In **Execution**, change the per-arm limit to `2`, set the local process
   wall-time cap to `1` hour and change Output to
   `/mnt/stor/data/ura-work/runs/demonstrations/my-qwen-demonstration/measured`.
   Keep the other bounds and the one-answer-retry policy unchanged.
4. Save, return through **Configure in Build**, and **Compose & review**.
   Follow step 3's preparation sequence for this new measured selection.
   Confirm the exact no-call projection before the real start.
5. Wait for collection and local evaluation to finish. Inspect the campaign's
   **Results**, **Judging**, **Costs** and **Campaign jobs**. Probes remain
   diagnostic records; do not pool them with the measured cases.

Use saved run selection for any subsequent hosted comparison, as explained in
[the Flash guide](SMALL_API_CAMPAIGN.md). Selecting the same seed independently
does not by itself prove identical prompts and images. Haiku must assess each
new selected answer separately; the verdict for another model's answer cannot
be copied onto it. Hosted execution and Haiku assessment require their own
forecast and spending controls.
