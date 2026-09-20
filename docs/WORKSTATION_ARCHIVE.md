# Workstation archive console

The campaign archive was copied from the rig on 20 September 2026 and passed
local browsing acceptance. This document describes the current installation,
startup, recovery and limitations. It is not a pending transfer or campaign
plan. The rig originals remain untouched.

The [historical plan and acceptance record](archive/WORKSTATION_ARCHIVE_PLAN_20260920.md)
preserves the earlier sequence, demonstration outcomes, transfer details and
historical limitations in full. For creating a new campaign on a suitable
execution host, use [Small campaigns](SMALL_CAMPAIGNS.md). The workstation
archive itself is non-executing.

## Start, browse and stop

1. In the workspace, open `CampaignArchive/rig-20260920`.
2. Double-click **Start console.cmd**. It starts the existing Ubuntu/WSL
   environment if needed, checks the retained data location, mounts the console
   source and starts the local service. Repeating Start does not launch a second
   copy when its tmux session already exists.
3. Open **http://127.0.0.1:8644/**. This service does not need SSH or the rig.
   Port 8642 remains separate; it is not this local copy.
4. Open **Campaigns -> Local campaign** or **Campaigns -> API campaign**.
   Browse Results, Judging, Compare, Costs, saved human review and analyses.
   Historical demonstrations and QA work remain separate campaigns.
5. To stop only this local service, double-click **Stop console.cmd**.
   Saved data and rig services are unaffected.

Useful saved views:

- [Local campaign](http://127.0.0.1:8644/campaigns/d74685e6af8e4e199d46db201c557858)
- [API campaign](http://127.0.0.1:8644/campaigns/e7887fc36e54413290cf0b5259796d0c)
- [Research SVM study](http://127.0.0.1:8644/stats?view=svm&study=engineering%2Fresponse-svm-20260913-r-checkpoints%2Fanalysis)

The default SVM selection may be a small demonstration with insufficient
independent inputs. Select the research study above for the retained
7,541-response, 397-input-group analysis. Opening it does not refit models or
buy judgments.

## What archive mode permits

The launcher keeps `--archive-view` enabled. Browsing, comparisons, charts,
retained-artifact access and exports are available. Editing, job launches,
model downloads, automatic process recovery and preparation/acquisition
continuation are disabled. Historical jobs and operations retain their saved
state; they are not treated as Windows processes to restart.

No provider secrets, model weights or framework runtimes were copied. The
existing lightweight console environment supports browsing, not local inference.
Do not remove archive mode to retry historical jobs. A future execution or
rating installation requires its own deliberate setup; this archive does not
start one implicitly.

The archive contains retained SVM datasets and the fitted package. Viewing
reports does not deserialize that package. Reusing fitted models requires a
trusted artifact and compatible analysis dependencies, not merely a working
web page.

## Storage and process locations

| Item | Current location or role |
| --- | --- |
| Launchers, compressed backup and notes | `CampaignArchive/rig-20260920` in the Windows workspace |
| Active data | `/mnt/stor/data/ura-work` inside the existing Ubuntu/WSL installation |
| Windows Explorer access to active data | `\\wsl.localhost\Ubuntu\mnt\stor\data\ura-work` |
| Console source snapshot | `CampaignArchive/rig-20260920/runtime`, mounted at `/home/ura/MLLMRiskBench` |
| Results and console state | `/mnt/stor/data/ura-work/runs` and its `rig-web` subdirectory |
| Console database | `/mnt/stor/data/ura-work/runs/rig-web/console.db` |
| Lightweight console Python | `/home/desync/.local/share/ura-archive-console/bin/python` |
| Local process | Ubuntu tmux server `ura-workstation`, session `console` |
| Service log | `CampaignArchive/rig-20260920/console.log` |

Only console source is mounted from the Windows directory. Active data uses
native WSL storage so small-file reads do not cross the Windows/WSL boundary.
Original Linux data paths remain valid without rewriting prompts, responses,
scientific identities or accounting. Moving only the Windows directory does
not move the active data out of Ubuntu.

The `transport` directory holds 14 compressed core parts, attribution and SVM
support packages, and the console source snapshot. Keep this recovery copy
unchanged while the working installation acquires derived caches. If the
initial `rootfs` extraction remains present, it is redundant and is not the
active data source. Do not confuse it with the native WSL copy.

## Retained contents and accepted scope

The selected copy contains 98,088 files, approximately 13.15 GiB, including the
consistent SQLite snapshot, research campaigns, demonstrations, historical
outcomes, recoveries, judgments, costs, SVM artifacts, human/AI review state,
source attribution and referenced media. It excludes unrelated regression
trees, model weights, framework environments, provider secrets and live rig
console process logs.

The database snapshot contains 66,437 assignments, 66,416 response records,
88,072 judgment records and 46,357 cost-attempt records across saved conditions.
These are archive inventory counts, including history and demonstrations,
not the thesis's deduplicated study denominators.

Transfer acceptance covered all selected files' presence and size, compressed
streams and the consistent SQLite database. Local checks covered data-backed
pages, actual matched comparisons, cost and SVM exports, retained artifacts,
desktop/mobile presentation and saved-review media. The detailed records are
beside the archive launchers and in the historical snapshot. They describe
this copied installation, not all future revisions.

An old unrated QA study has an empty media index on both rig and workstation.
Its two images are retained and resolve in a later QA study; this is a historical
index defect, not transfer loss. The study containing seven actual human
ratings resolves its media. Historical failures remain visible rather than
being removed to make the archive appear complete.

## Recovery and troubleshooting

- **Page unavailable:** run **Start console.cmd**, then inspect `console.log`.
  The launcher reports mounting or startup failure instead of silently starting
  against another directory. If it reports an existing session but the service
  is unresponsive, inspect the log, stop the local console and start it again.
- **Ubuntu unavailable:** check the existing distribution with
  `wsl.exe --list --verbose`. Do not unregister or reinstall Ubuntu as a
  troubleshooting shortcut; its filesystem contains the active data.
- **Mount conflict:** the launcher refuses to cover an unrelated existing
  directory or mount. Resolve the actual conflicting location before retrying;
  do not delete data to satisfy the check.
- **Missing response or media:** inspect the retained record and its source
  location. Some failures and unavailable historical outputs are intentional
  parts of the evidence. Do not regenerate answers or infer a replacement from
  a similar input merely to repair presentation.
- **Missing active data:** stop the local service and restore into a separate
  staging location from the compressed backup or preserved rig source.
  Confirm the restored inventory, consistent database and path mapping before
  substituting it for active storage. One-time copy helpers are not routine
  startup scripts and must not be rerun over the working database.
- **Backing up this installation:** preserve both the Windows archive directory
  and the Ubuntu working data. Use a consistent SQLite backup; a live database
  copy must account for its WAL. Stop the local console for a filesystem-level
  backup if no SQLite backup mechanism is used.

Human ratings and adjudications are primary database records, not reconstructed
generation indexes. Preserve the database or their explicit exports, as well
as the separate conversational-review database and presentation records.
Original response/judgment files alone cannot reproduce human ratings.

Removing Ubuntu removes the active working copy. The compressed parts can
reconstruct the selected archive, and the rig remains an independent source.
No rig deletion is authorized by this document. Restoring or browsing the data
does not establish completion of statistical synthesis, thesis revision or
independent human assessment.
