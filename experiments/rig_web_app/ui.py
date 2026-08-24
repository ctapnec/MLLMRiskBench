"""Shared HTML, CSS, JavaScript, and compact rendering helpers."""

from __future__ import annotations

import html
from urllib.parse import quote

from .catalog import _icon

_STYLE = """
:root { color-scheme: light dark;
  --bg:#eef1f5; --card:#ffffff; --ink:#182430; --muted:#5b6b7c;
  --line:#d9e0e8; --accent:#0a5fb4; --accent-ink:#ffffff;
  --soft:#f4f7fa; --shadow:0 1px 2px rgba(16,24,32,.06),
  0 4px 14px rgba(16,24,32,.05);
  --m-text:#0a66c2; --m-text-bg:#e4eefb; --m-image:#1d7a43;
  --m-image-bg:#e1f2e8; --m-audio:#a86400; --m-audio-bg:#f7ecd9;
  --m-video:#7a3fb8; --m-video-bg:#f0e7fa;
  --chevron:url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%20fill='none'%20stroke='%235b6b7c'%20stroke-width='2.2'%20stroke-linecap='round'%20stroke-linejoin='round'%3E%3Cpath%20d='M6%209l6%206%206-6'/%3E%3C/svg%3E"); }
@media (prefers-color-scheme: dark) {
  :root { --bg:#10161d; --card:#19212b; --ink:#e7edf3; --muted:#92a3b4;
    --line:#28323e; --accent:#59a3ea; --accent-ink:#0d1621;
    --soft:#141b23; --shadow:0 1px 2px rgba(0,0,0,.35);
    --m-text:#79b7f7; --m-text-bg:#16304a; --m-image:#63cb90;
    --m-image-bg:#12301f; --m-audio:#f0b25e; --m-audio-bg:#3a2a10;
    --m-video:#c89df3; --m-video-bg:#2d1b41;
    --chevron:url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%20fill='none'%20stroke='%2392a3b4'%20stroke-width='2.2'%20stroke-linecap='round'%20stroke-linejoin='round'%3E%3Cpath%20d='M6%209l6%206%206-6'/%3E%3C/svg%3E"); } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.55 system-ui, "Segoe UI", sans-serif;
  background:var(--bg); color:var(--ink); }
main { max-width:1160px; margin:0 auto; padding:1.4rem 1.2rem 2rem; }
nav { position:sticky; top:0; z-index:5; background:var(--card);
  border-bottom:1px solid var(--line); padding:.6rem 1.2rem;
  display:flex; gap:.4rem; align-items:center; flex-wrap:wrap; }
nav .brand { display:flex; gap:.55rem; align-items:center; font-weight:700;
  margin-right:1rem; letter-spacing:.01em; }
nav .brand .ic { color:var(--accent); }
nav a { display:flex; gap:.4rem; align-items:center; color:var(--muted);
  text-decoration:none; font-weight:600; font-size:.92rem;
  padding:.35rem .7rem; border-radius:8px; }
nav a:hover { background:var(--soft); color:var(--ink); }
nav a.active { background:var(--soft); color:var(--accent); }
h1 { font-size:1.3rem; margin:.4rem 0 1rem; display:flex; gap:.55rem;
  align-items:center; }
h1 .ic { color:var(--accent); }
h2 { font-size:1rem; margin:0 0 .6rem; display:flex; gap:.45rem;
  align-items:center; color:var(--ink); }
h2 .ic { color:var(--muted); }
.card { background:var(--card); border:1px solid var(--line);
  border-radius:12px; padding:1rem 1.2rem; margin:.9rem 0;
  box-shadow:var(--shadow); }
.cols { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:.9rem; }
.cols .card { margin:0; }
.stat { display:flex; flex-direction:column; gap:.15rem; }
.stat .value { font-size:1.35rem; font-weight:700; }
.stat .label { color:var(--muted); font-size:.82rem; }
table { border-collapse:collapse; width:100%; font-size:.87rem; }
th, td { border-bottom:1px solid var(--line); padding:.42rem .6rem;
  text-align:left; vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.78rem;
  text-transform:uppercase; letter-spacing:.05em;
  border-bottom:2px solid var(--line); }
tr:hover td { background:var(--soft); }
.scroll { overflow-x:auto; }
pre { background:var(--soft); border:1px solid var(--line);
  border-radius:10px; padding:.8rem .95rem; overflow-x:auto;
  font-size:.82rem; white-space:pre-wrap; word-break:break-word; }
code { background:var(--soft); border-radius:5px; padding:.05rem .35rem;
  font-size:.85em; }
.badge { display:inline-flex; align-items:center; border-radius:999px;
  padding:.08rem .62rem; font-size:.74rem; font-weight:600;
  margin:0 .25rem .25rem 0; }
.badge.amber { background:#7a5200; color:#ffe9c2; }
.badge.blue { background:#0b4c8c; color:#dcecfd; }
.badge.green { background:#1d6b35; color:#d9f4e1; }
.badge.red { background:#8c1d24; color:#fde0e2; }
.badge.gray { background:#4a5563; color:#e3e8ee; }
.dot { display:inline-block; width:.55rem; height:.55rem;
  border-radius:50%; margin-right:.4rem; vertical-align:baseline; }
.dot.blue { background:#3f8edb; box-shadow:0 0 0 3px
  color-mix(in srgb, #3f8edb 25%, transparent); }
.dot.green { background:#2e9e57; }
.dot.red { background:#d4525b; }
.dot.gray { background:#8a97a5; }
.crumbs { color:var(--muted); font-size:.86rem; margin:0 0 .8rem; }
.crumbs a { color:var(--accent); text-decoration:none; }
.crumbs span.sep { margin:0 .35rem; }
details.cmd { background:var(--card); border:1px solid var(--line);
  border-radius:12px; margin:.55rem 0; box-shadow:var(--shadow); }
details.cmd > summary { list-style:none; cursor:pointer; display:flex;
  gap:.6rem; align-items:baseline; padding:.75rem 1.1rem; }
details.cmd > summary::-webkit-details-marker { display:none; }
details.cmd > summary .ic { color:var(--accent); align-self:center; }
details.cmd > summary .name { font-weight:700; }
details.cmd > summary .desc { color:var(--muted); font-size:.86rem; }
details.cmd[open] > summary { border-bottom:1px solid var(--line); }
details.cmd .inner { padding:.9rem 1.1rem 1.1rem; }
.group-head { display:flex; gap:.55rem; align-items:center;
  margin:1.6rem 0 .4rem; }
.group-head .ic { color:var(--accent); }
.group-head h2 { margin:0; }
.group-head .ref { color:var(--muted); font-size:.8rem; }
form.cmd { display:grid; grid-template-columns:minmax(200px,260px) 1fr;
  gap:.4rem .8rem; align-items:center; }
form.cmd label { color:var(--muted); font-size:.84rem; }
.req { color:#c0392b; font-weight:700; }
form.cmd label .kind { color:var(--muted); opacity:.7; font-size:.75rem; }
form.cmd input[type=text], form.cmd input[type=number] {
  width:100%; padding:.38rem .55rem;
  border:1px solid var(--line); border-radius:8px; background:var(--bg);
  color:var(--ink); font-size:.86rem; }
form.cmd select { width:100%; }
form.cmd input:focus, form.cmd select:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
button { display:inline-flex; gap:.4rem; align-items:center;
  background:var(--accent); border:0; color:var(--accent-ink);
  font-weight:600; border-radius:9px; padding:.48rem 1rem; cursor:pointer;
  font-size:.9rem; }
button:hover { filter:brightness(1.08); }
button.danger { background:#a4262f; color:#fff; }
button.small { padding:.28rem .6rem; font-size:.8rem; border-radius:7px; }
form.inline { display:inline; margin:0; }
.chips { display:flex; flex-wrap:wrap; gap:.4rem; margin:.2rem 0 .6rem; }
.chip { background:var(--card); color:var(--muted); border:1px solid var(--line);
  border-radius:999px; padding:.3rem .8rem; font-size:.82rem; font-weight:600;
  cursor:pointer; }
.chip:hover { color:var(--ink); }
.chip.on { background:var(--accent); color:var(--accent-ink);
  border-color:var(--accent); }
.page-tablist { display:none; }
.page-tabs.tabs-ready .page-tablist { display:flex; align-items:center; gap:.25rem;
  overflow-x:auto; margin:.2rem 0 .9rem; padding:.28rem;
  background:var(--card); border:1px solid var(--line); border-radius:11px;
  box-shadow:var(--shadow); scrollbar-width:thin; }
.page-tab { flex:0 0 auto; border:1px solid transparent; border-radius:8px;
  padding:.46rem .85rem; background:transparent; color:var(--muted);
  font-size:.86rem; white-space:nowrap; }
.page-tab:hover { filter:none; color:var(--ink); background:var(--soft); }
.page-tab[aria-selected=true] { color:var(--accent); background:var(--soft);
  border-color:color-mix(in srgb, var(--accent) 22%, var(--line)); }
.page-tab:focus-visible { outline:2px solid
  color-mix(in srgb, var(--accent) 55%, transparent); outline-offset:1px; }
.page-tabpanel { min-width:0; }
.page-tabpanel:focus { outline:none; }
.page-tabpanel:focus-visible { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); outline-offset:4px; }
.page-tabpanel[hidden] { display:none; }
.tab-summary { margin:.2rem 0 .9rem; }
.tab-summary .card { min-height:100%; }
.tab-summary a { text-decoration:none; }
@media (max-width:640px) {
  .page-tabs.tabs-ready .page-tablist { margin-left:-.25rem; margin-right:-.25rem; }
  .page-tab { padding:.42rem .68rem; }
}
.notice { position:relative; }
.notice-close { position:absolute; top:.35rem; right:.45rem;
  background:transparent; color:var(--muted); border:0; font-size:1.15rem;
  line-height:1; padding:.1rem .35rem; cursor:pointer; border-radius:6px; }
.notice-close:hover { background:var(--card); color:var(--ink); }
#jobfilter { width:100%; max-width:420px; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:9px; background:var(--card);
  color:var(--ink); font-size:.9rem; }
#jobfilter:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
.job-date-filters { max-width:720px; grid-template-columns:repeat(2,
  minmax(220px,1fr)); }
.job-date-filters input[type=datetime-local] { width:100%; min-height:2.35rem;
  padding:.42rem .65rem; border:1px solid var(--line); border-radius:8px;
  background:var(--bg); color:var(--ink); font:inherit; font-size:.86rem;
  color-scheme:light dark; }
.job-date-filters input[type=datetime-local]:hover { border-color:
  color-mix(in srgb, var(--accent) 55%, var(--line)); }
.job-date-filters input[type=datetime-local]:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
a { color:var(--accent); }
p.note { color:var(--muted); font-size:.84rem; }
footer.note { color:var(--muted); font-size:.8rem; margin-top:2rem;
  border-top:1px solid var(--line); padding-top:.8rem; }
.pipeline { width:100%; min-width:900px; }
.pipeline .node rect { fill:var(--card); stroke:var(--line);
  stroke-width:1.4; }
.pipeline .node.present rect { stroke:var(--accent); stroke-width:2; }
.pipeline .node text { fill:var(--ink); font:600 12.5px system-ui,
  "Segoe UI", sans-serif; }
.pipeline .node text.count { fill:var(--muted); font-weight:500;
  font-size:11.5px; }
.pipeline .node text.count.sub { font-size:10px; opacity:.85; }
.pipeline .node.present text.count { fill:var(--accent); font-weight:700; }
.pipeline a { cursor:pointer; }
.pipeline a:hover .node rect { stroke:var(--accent); stroke-width:2.4;
  filter:brightness(1.04); }
.pipeline .arrow { stroke:var(--muted); stroke-width:1.4; fill:none;
  marker-end:url(#arrowhead); }
.pipeline #arrowhead path { fill:var(--muted); }
.meter { height:.55rem; border-radius:999px; background:var(--soft);
  border:1px solid var(--line); overflow:hidden; margin:.35rem 0 .15rem; }
.meter > div { height:100%; background:var(--accent); }
.argv { display:flex; flex-wrap:wrap; gap:.3rem; }
.argv code { border:1px solid var(--line); padding:.12rem .45rem; }
.filelist td .ic { color:var(--muted); vertical-align:-3px;
  margin-right:.45rem; }
.notice { border-left:4px solid var(--line); border-radius:8px;
  background:var(--soft); padding:.6rem .8rem; margin:.45rem 0;
  font-size:.9rem; }
.notice.amber { border-left-color:#c9922a; }
.notice.red { border-left-color:#c4515c; }
.notice.blue { border-left-color:#3f8edb; }
.notice p.note { margin:.25rem 0 0; }
details.stagefiles { margin:.35rem 0; font-size:.86rem; }
details.stagefiles > summary { cursor:pointer; color:var(--accent);
  font-weight:600; }
details.stagefiles ul { margin:.3rem 0 .5rem; padding-left:1.2rem; }
details.stagefiles li { margin:.12rem 0; overflow-wrap:anywhere; }
#cmdfilter { width:100%; max-width:420px; padding:.45rem .7rem;
  border:1px solid var(--line); border-radius:9px; background:var(--card);
  color:var(--ink); font-size:.9rem; }
#cmdfilter:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent);
  border-color:var(--accent); }
.fieldwrap { display:flex; flex-direction:column; gap:.15rem; }
.fieldcell { display:flex; flex-direction:column; min-width:0; }
.fieldcell .fieldlabel { flex:1 0 auto; }
.fieldcell select { align-self:flex-start; }
.fieldhint { color:var(--muted); font-size:.76rem; line-height:1.35; }
.fieldlabel { display:block; color:var(--muted); font-size:.82rem;
  margin:.6rem 0 .25rem; }
select { appearance:none; -webkit-appearance:none; font:inherit;
  font-size:.86rem; color:var(--ink); background-color:var(--bg);
  border:1px solid var(--line); border-radius:8px; cursor:pointer;
  padding:.4rem 2.1rem .4rem .6rem; min-width:8.5rem;
  background-image:var(--chevron); background-repeat:no-repeat;
  background-position:right .55rem center; background-size:15px; }
select:hover { border-color:color-mix(in srgb, var(--accent) 55%, var(--line)); }
select:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent);
  border-color:var(--accent); }
input[type=checkbox], input[type=radio] { appearance:none;
  -webkit-appearance:none; width:17px; height:17px; margin:0;
  flex:0 0 auto; cursor:pointer; border:1.5px solid
  color-mix(in srgb, var(--muted) 55%, var(--line));
  border-radius:5px; background:var(--card); display:inline-grid;
  place-content:center; vertical-align:middle;
  transition:border-color .12s ease, background-color .12s ease; }
input[type=radio] { border-radius:50%; }
input[type=checkbox]:hover:not(:disabled),
input[type=radio]:hover:not(:disabled) { border-color:var(--accent); }
input[type=checkbox]:focus-visible, input[type=radio]:focus-visible {
  outline:2px solid color-mix(in srgb, var(--accent) 45%, transparent);
  outline-offset:1px; }
input[type=checkbox]:checked { background:var(--accent);
  border-color:var(--accent); }
input[type=checkbox]:checked::before { content:''; width:9px; height:5px;
  border:2px solid var(--accent-ink); border-top:0; border-right:0;
  transform:rotate(-45deg) translateY(-1px); }
input[type=radio]:checked { border-color:var(--accent); }
input[type=radio]:checked::before { content:''; width:9px; height:9px;
  border-radius:50%; background:var(--accent); }
input[type=checkbox]:disabled, input[type=radio]:disabled {
  cursor:not-allowed; background:var(--soft); opacity:.55; }
textarea.editor { width:100%; min-height:60vh; font:.82rem/1.5
  ui-monospace, "Cascadia Code", Menlo, monospace; padding:.8rem;
  border:1px solid var(--line); border-radius:10px; background:var(--soft);
  color:var(--ink); resize:vertical; }
textarea.editor:focus { outline:2px solid
  color-mix(in srgb, var(--accent) 45%, transparent); border-color:var(--accent); }
.editor-actions { display:flex; gap:.6rem; margin:.7rem 0; }
button.ghost { background:transparent; color:var(--accent);
  border:1px solid var(--line); }
.playbook { margin:.4rem 0 0; padding-left:0; list-style:none; }
.playbook li { display:flex; gap:.5rem; align-items:baseline;
  padding:.35rem 0; border-bottom:1px solid var(--line); flex-wrap:wrap; }
.playbook li:last-child { border-bottom:0; }
.step-n { display:inline-flex; width:1.4rem; height:1.4rem;
  align-items:center; justify-content:center; border-radius:50%;
  background:var(--accent); color:var(--accent-ink); font-size:.75rem;
  font-weight:700; flex:none; }
.radios { display:flex; flex-direction:column; gap:.5rem; }
.radio { display:flex; gap:.5rem; align-items:flex-start; cursor:pointer; }
.radio input { margin-top:.15rem; }
.check { display:flex; gap:.45rem; align-items:flex-start; cursor:pointer;
  padding:.25rem 0; }
.check input { margin-top:.2rem; flex:0 0 auto; }
.check span { font-size:.88rem; min-width:0; overflow-wrap:anywhere; }
.check > span { flex:1 1 auto; }
.checkgrid { display:grid; grid-template-columns:repeat(auto-fill,
  minmax(240px,1fr)); gap:.15rem .8rem; align-items:start; }
.targetfilters { display:grid; grid-template-columns:repeat(auto-fit,
  minmax(min(14rem,100%),1fr)); gap:.65rem 1rem; align-items:stretch;
  min-width:0; max-width:100%; margin:.55rem 0 .8rem;
  padding:.65rem .75rem; background:var(--soft); border:1px solid var(--line);
  border-radius:10px; }
.targetfilters > * { min-width:0; max-width:100%; }
.targetfilters .fieldlabel { margin:0 0 .25rem; }
.targetfilters input[type=range] { width:100%; min-width:0; accent-color:var(--accent); }
.paramfilter { display:grid; grid-template-columns:minmax(0,1fr) minmax(5.5rem,7rem);
  gap:.55rem; align-items:center; min-width:0; max-width:100%; }
.paramfilter > * { min-width:0; max-width:100%; }
.compatfilter { display:grid; grid-template-columns:17px minmax(0,1fr);
  gap:.55rem; align-items:start; min-width:0; max-width:100%;
  padding:.5rem .6rem; cursor:pointer;
  background:var(--card); border:1px solid var(--line); border-radius:8px; }
.compatfilter input { margin-top:.15rem; }
.compatcopy { display:flex; flex-direction:column; gap:.12rem; line-height:1.3; }
.compatcopy .fieldhint { display:block; }
.modelrow { min-width:0; padding:.5rem .55rem; background:var(--card);
  border:1px solid var(--line); border-radius:9px; }
.modelrow:focus-within { border-color:var(--accent); }
.modelrow:has(.modelbox:checked) {
  background:color-mix(in srgb, var(--accent) 8%, var(--card));
  border-color:var(--accent); }
.modelchoice { width:100%; min-width:0; padding:0; }
.modelchoice > .modelchoice-copy { display:block; flex:1 1 auto; min-width:0;
  cursor:pointer; overflow-wrap:anywhere; }
.modelrow .fieldhint { display:block; margin-top:.18rem; line-height:1.35; }
.modelquant { display:flex; align-items:center; gap:.45rem;
  min-width:0; max-width:100%; margin:.4rem 0 0 calc(17px + .45rem);
  flex-wrap:wrap; }
.modelquant label { color:var(--muted); font-size:.76rem; }
.modelquant select { width:min(100%,24rem); min-width:0; max-width:100%; }
.precision-badge { margin-left:.35rem; white-space:nowrap; vertical-align:middle; }
.precision-badge.precision-16 { box-shadow:inset 0 0 0 1px #4fa66a; }
.precision-badge.precision-8 { box-shadow:inset 0 0 0 1px #529ee8; }
.precision-badge.precision-4 { box-shadow:inset 0 0 0 1px #d6a044; }
.precision-badge.precision-unknown { box-shadow:inset 0 0 0 1px var(--line); }
.filter-empty { display:none; color:var(--muted); font-size:.84rem;
  margin:.35rem 0; }
.model-picker-selection { display:flex; align-items:center; gap:.75rem;
  flex-wrap:wrap; padding:.65rem .75rem; background:var(--soft);
  border:1px solid var(--line); border-radius:10px; }
.selection-summary { color:var(--muted); font-size:.86rem; overflow-wrap:anywhere; }
.model-picker { position:fixed; inset:0; z-index:900; padding:clamp(.5rem,3vw,2rem);
  background:color-mix(in srgb, var(--bg) 62%, transparent);
  backdrop-filter:blur(3px); display:flex; align-items:center; justify-content:center; }
.model-picker[hidden] { display:none; }
.model-picker-shell { width:min(1080px,100%); min-width:0;
  max-height:calc(100vh - 2rem);
  overflow:auto; background:var(--card); border:1px solid var(--line);
  border-radius:14px; box-shadow:0 18px 60px rgba(0,0,0,.28);
  padding:1rem 1.15rem; }
.model-picker-head, .model-picker-foot {
  display:flex; justify-content:space-between; align-items:center; gap:.75rem;
  flex-wrap:wrap; }
.model-picker-head { position:sticky; top:-1rem; z-index:4; margin:-1rem -1.15rem 0;
  padding:1rem 1.15rem .75rem; background:var(--card);
  border-bottom:1px solid var(--line); }
.model-picker-head h2 { margin:0; font-size:1.1rem; }
.wizard-kicker { margin:0 0 .1rem; color:var(--accent); font-size:.72rem;
  font-weight:700; text-transform:uppercase; letter-spacing:.08em; }
.wizard-steps { display:flex; flex-wrap:wrap; gap:.45rem; margin:.85rem 0; }
button.wizard-step { padding:.25rem .65rem; border:1px solid var(--line);
  border-radius:999px; color:var(--muted); background:transparent;
  font-size:.78rem; font-weight:600; }
button.wizard-step:hover:not(:disabled), button.wizard-step:focus-visible {
  color:var(--accent); border-color:var(--accent); filter:none; }
button.wizard-step:disabled { cursor:default; opacity:.58; }
button.wizard-step.on { color:var(--accent); border-color:var(--accent);
  background:color-mix(in srgb, var(--accent) 9%, var(--card)); }
.picker-runtime-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr));
  gap:.8rem; margin:.75rem 0 1rem; }
button.picker-runtime-choice { display:flex; flex-direction:column; align-items:flex-start;
  min-height:9rem; padding:1rem; text-align:left; color:var(--ink);
  background:var(--soft); border:1px solid var(--line); }
button.picker-runtime-choice:hover, button.picker-runtime-choice:focus-visible {
  border-color:var(--accent); background:color-mix(in srgb,var(--accent) 8%,var(--card)); }
.picker-runtime-choice strong { color:var(--accent); font-size:1rem; }
.picker-runtime-choice span { color:var(--muted); font-weight:400; line-height:1.45; }
.picker-role-note { margin:.2rem 0 .65rem; }
.picker-model-panel { min-width:0; max-width:100%; }
.picker-model-panel .checkgrid { grid-template-columns:repeat(auto-fill,
  minmax(min(290px,100%),1fr)); max-height:48vh; overflow:auto; padding:.15rem; }
.model-picker-foot { position:sticky; bottom:-1rem; z-index:4;
  margin:.85rem -1.15rem -1rem; padding:.75rem 1.15rem 1rem;
  background:var(--card); border-top:1px solid var(--line); }
.model-picker[data-role=target] .judge-cost-warning { display:none; }
body.model-picker-open { overflow:hidden; }
@media (max-width:640px) {
  .picker-runtime-grid, .job-date-filters { grid-template-columns:1fr; }
  .model-picker { padding:.25rem; }
  .model-picker-shell { max-height:calc(100vh - .5rem); border-radius:10px; }
  .picker-model-panel .checkgrid { grid-template-columns:1fr; }
  .paramfilter { grid-template-columns:1fr; }
}
.hardware-grid { display:grid; grid-template-columns:minmax(220px,.8fr) 2fr;
  gap:1rem; align-items:start; }
.hardware-grid h3 { margin:.15rem 0 .45rem; }
.hardware-spec { display:grid; grid-template-columns:auto 1fr; gap:.25rem .65rem;
  margin:0; font-size:.86rem; }
.hardware-spec dt { color:var(--muted); }
.hardware-spec dd { margin:0; font-weight:600; overflow-wrap:anywhere; }
.hardware-list { list-style:none; margin:0; padding:0; display:grid; gap:.45rem; }
.hardware-list li { padding:.5rem .6rem; background:var(--soft);
  border:1px solid var(--line); border-radius:8px; }
.hardware-list .fieldhint { display:block; margin-top:.12rem; }
@media (max-width:760px) { .hardware-grid { grid-template-columns:1fr; } }
.modgroup { margin:.6rem 0; }
.modgroup h3 { font-size:.82rem; text-transform:uppercase;
  letter-spacing:.05em; color:var(--muted); margin:.5rem 0 .2rem; }
.modscope { display:flex; flex-wrap:wrap; gap:.5rem; margin:.3rem 0 .2rem; }
.modtoggle { display:inline-flex; align-items:center; gap:.45rem;
  cursor:pointer; user-select:none; padding:.5rem .95rem; border-radius:10px;
  border:1.5px solid var(--line); background:var(--card); font-weight:600;
  font-size:.9rem; text-transform:capitalize; transition:all .12s ease; }
.modtoggle input { position:absolute; opacity:0; width:0; height:0; }
.modtoggle span::before { content:''; display:inline-block; width:.7rem;
  height:.7rem; margin-right:.5rem; border-radius:4px; vertical-align:-1px;
  border:1.5px solid var(--muted); background:transparent; }
.modtoggle:has(input:checked) { background:color-mix(in srgb,
  var(--accent) 14%, var(--card)); border-color:var(--accent);
  color:var(--accent); }
.modtoggle:has(input:checked) span::before { background:var(--accent);
  border-color:var(--accent); box-shadow:inset 0 0 0 2px var(--card); }
.modtoggle:hover { border-color:var(--accent); }
.grouphead { display:flex; align-items:center; justify-content:space-between;
  gap:.5rem; margin:.7rem 0 .1rem; }
.grouphead h3 { margin:0; }
.groupsel { display:flex; gap:.5rem; }
.linkbtn { background:transparent; border:0; color:var(--accent);
  font-size:.8rem; font-weight:600; cursor:pointer; padding:.1rem .3rem; }
.linkbtn:hover { text-decoration:underline; }
.modtag { display:inline-block; font-size:.66rem; font-weight:600;
  text-transform:uppercase; letter-spacing:.04em; color:var(--muted);
  background:var(--soft); border:1px solid var(--line); border-radius:5px;
  padding:0 .3rem; margin-left:.2rem; vertical-align:middle; }
.modicon { display:inline-flex; align-items:center; justify-content:center;
  width:19px; height:19px; border-radius:6px; vertical-align:middle;
  flex:0 0 auto; }
.modicon .ic { width:12px; height:12px; }
.modicon.m-text { color:var(--m-text); background:var(--m-text-bg); }
.modicon.m-image { color:var(--m-image); background:var(--m-image-bg); }
.modicon.m-audio { color:var(--m-audio); background:var(--m-audio-bg); }
.modicon.m-video { color:var(--m-video); background:var(--m-video-bg); }
.armhead { display:flex; align-items:center; justify-content:space-between;
  gap:.45rem; }
.armhead .armname { min-width:0; overflow-wrap:anywhere; }
.modset { display:inline-flex; gap:.22rem; flex:0 0 auto; }
.check .badge { margin:.18rem 0 .05rem; }
.check .prepared-framework-badge { margin:.18rem 0 .05rem .55rem;
  padding:.12rem .65rem; gap:.3rem; }
.tip { position:relative; cursor:help; outline:none; }
.tip .tiptext { display:none; position:absolute; z-index:30; left:0; top:135%;
  width:min(320px,72vw); background:var(--card); color:var(--ink);
  border:1px solid var(--line); border-radius:7px; padding:.5rem .6rem;
  font-size:.75rem; font-weight:400; text-transform:none; letter-spacing:0;
  line-height:1.45; box-shadow:var(--shadow); white-space:normal; }
.tip:hover .tiptext, .tip:focus .tiptext, .tip:focus-within .tiptext {
  display:block; }
.fwrow.incompatible { opacity:.55; }
.fwrow.incompatible .fwflag { color:#c4515c; font-weight:600; }
.prepared-workflows { border-top:1px solid var(--line); margin-top:1rem;
  padding-top:1rem; }
.prepared-workflows > .note { margin:0 0 .85rem; }
.workflow-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
  gap:1rem; margin:0; }
.workflow-panel { border:1px solid var(--line); border-radius:10px;
  padding:1rem; background:var(--soft); min-width:0; display:grid;
  align-content:start; gap:.9rem; }
.workflow-panel[hidden] { display:none; }
.workflow-panel h3, .workflow-panel h4, .workflow-panel p.note,
.workflow-panel .cols, .workflow-panel details { margin:0; }
.workflow-panel h3 { display:flex; align-items:center; flex-wrap:wrap; gap:.45rem; }
.workflow-step { display:grid; gap:.7rem; padding:.8rem; background:var(--card);
  border:1px solid var(--line); border-radius:9px; }
.workflow-step h4 { font-size:.92rem; }
.workflow-panel .cols { grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
  gap:.75rem; }
.workflow-panel .fieldcell { margin:0; }
.workflow-panel details { border:1px solid var(--line); border-radius:8px;
  padding:.65rem; }
.workflow-panel details summary { cursor:pointer; font-weight:600; }
.workflow-panel details[open] summary { margin-bottom:.75rem; }
.workflow-actions { display:flex; align-items:center; flex-wrap:wrap; gap:.65rem;
  margin:0; }
.sample-size-control { display:grid; gap:.7rem; margin:0 0 1rem;
  padding:.85rem; background:var(--soft); border:1px solid var(--line);
  border-radius:10px; min-width:0; }
.sample-size-control[hidden] { display:none; }
.sample-size-head { display:flex; align-items:flex-start; justify-content:space-between;
  gap:.75rem; flex-wrap:wrap; }
.sample-size-head h3, .sample-size-head p { margin:0; }
.sample-size-head p { margin-top:.25rem; }
.sample-size-grid { display:grid; grid-template-columns:minmax(0,2fr)
  repeat(2,minmax(10rem,1fr)); gap:.75rem; align-items:end; min-width:0; }
.sample-size-grid input[type=range] { width:100%; min-width:0;
  accent-color:var(--accent); }
@media (max-width:400px) {
  .workflow-grid, .workflow-panel .cols { grid-template-columns:minmax(0,1fr); }
  .prepared-workflows, .workflow-panel, .workflow-step {
    min-width:0; max-width:100%; }
}
@media (max-width:760px) {
  .sample-size-grid { grid-template-columns:minmax(0,1fr); }
}
.fielderr { display:block; color:#c4515c; font-size:.8rem; font-weight:600;
  margin:.2rem 0 .1rem; }
.attrow { display:grid; grid-template-columns:1fr 1fr; gap:.5rem;
  margin:.35rem 0; }
@media (max-width:640px) { .attrow { grid-template-columns:1fr; } }
.notice ul { margin:.35rem 0 .1rem; padding-left:1.2rem; }
.notice li { font-size:.86rem; margin:.15rem 0; }
input.wide { width:100%; padding:.4rem .55rem; border:1px solid var(--line);
  border-radius:8px; background:var(--bg); color:var(--ink); font-size:.86rem; }
.buildbar { position:sticky; bottom:0; display:flex; gap:.8rem;
  align-items:center; padding:.65rem .9rem; flex-wrap:wrap;
  background:var(--card); border:1px solid var(--line);
  border-radius:12px 12px 0 0; border-bottom:0;
  box-shadow:0 -6px 18px -8px rgba(0,0,0,.28); }
.builder-summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
  gap:.65rem; margin:.8rem 0; }
.builder-summary > div { min-width:0; padding:.65rem .75rem; border:1px solid var(--line);
  border-radius:9px; background:var(--soft); }
.builder-summary dt { color:var(--muted); font-size:.75rem; font-weight:700;
  text-transform:uppercase; letter-spacing:.04em; }
.builder-summary dd { margin:.18rem 0 0; font-size:.84rem; overflow-wrap:anywhere; }
#buildpreview { font:.78rem ui-monospace, Menlo, monospace;
  overflow-wrap:anywhere; display:block; padding:.55rem .65rem; }
.barchart { width:100%; min-width:640px; }
.barchart .bl, .barchart .bn { fill:var(--ink); font:600 12px system-ui,
  sans-serif; }
.barchart .bn { font-weight:500; fill:var(--muted); }
.barchart .bt { fill:var(--soft); stroke:var(--line); stroke-width:1; }
.barchart .bv { fill:var(--accent); }
.stats-campaign-list { display:grid; grid-template-columns:repeat(auto-fit,
  minmax(min(360px,100%),1fr)); gap:.85rem; margin:.7rem 0 1.2rem; }
.stats-campaign-card { min-width:0; padding:.85rem .95rem; background:var(--card);
  border:1px solid var(--line); border-radius:12px; box-shadow:var(--shadow); }
.stats-campaign-card[data-authority=thesis-measured] {
  border-left:4px solid #4fa66a; }
.stats-campaign-card[data-authority=diagnostic],
.stats-campaign-card[data-authority=synthetic],
.stats-campaign-card[data-authority=measured-incomplete] {
  border-left:4px solid #c9922a; }
.stats-campaign-card.engineering { border-left:4px solid var(--muted); }
.stats-campaign-head { display:flex; align-items:flex-start;
  justify-content:space-between; gap:.65rem; flex-wrap:wrap; }
.stats-campaign-head h3 { margin:0; font-size:1rem; overflow-wrap:anywhere; }
.stats-campaign-head p { margin:.15rem 0 0; }
.stats-badges { display:flex; flex-wrap:wrap; gap:.3rem; align-items:center; }
.stats-campaign-meta { display:grid; grid-template-columns:minmax(5.2rem,auto)
  minmax(0,1fr); gap:.3rem .65rem; margin:.75rem 0; font-size:.84rem; }
.stats-campaign-meta dt { color:var(--muted); }
.stats-campaign-meta dd { margin:0; min-width:0; overflow-wrap:anywhere; }
.stats-campaign-actions { display:flex; flex-wrap:wrap; gap:.5rem; }
a.button { display:inline-flex; align-items:center; justify-content:center;
  padding:.42rem .8rem; border-radius:8px; text-decoration:none;
  font-size:.86rem; font-weight:600; }
a.button.ghost { color:var(--accent); border:1px solid var(--line);
  background:transparent; }
.stats-pagination { display:flex; align-items:center; justify-content:center;
  gap:.65rem; flex-wrap:wrap; margin:.7rem 0 1.2rem; }
.stats-modal { display:none; min-width:0; margin:1rem 0; }
.stats-modal-shell { min-width:0; padding:.9rem; background:var(--card);
  border:1px solid var(--line); border-radius:12px; }
.stats-modal-head { display:flex; align-items:flex-start;
  justify-content:space-between; gap:.75rem; border-bottom:1px solid var(--line);
  padding-bottom:.65rem; margin-bottom:.75rem; }
.stats-modal-head h2 { margin:0; overflow-wrap:anywhere; }
.stats-modal-close { display:none; }
.stats-modal-body { min-width:0; }
.stats-modal-body > *, .stats-modal-body .card { min-width:0; max-width:100%; }
.stats-modal-links { margin:.7rem 0 0; }
.stats-modal-ready .stats-modal { display:none; position:fixed; inset:0;
  z-index:920; margin:0; padding:clamp(.35rem,3vw,2rem);
  align-items:center; justify-content:center;
  background:color-mix(in srgb,var(--bg) 62%,transparent);
  backdrop-filter:blur(3px); }
.stats-modal-ready .stats-modal.is-open { display:flex; }
.stats-modal-ready .stats-modal-shell { width:min(1120px,100%);
  max-height:calc(100vh - 2rem); overflow:auto; padding:1rem 1.15rem;
  box-shadow:0 18px 60px rgba(0,0,0,.28); }
.stats-modal-ready .stats-modal-close { display:inline-flex; }
body.stats-modal-open { overflow:hidden; }
@media (max-width:640px) {
  .stats-campaign-list { grid-template-columns:minmax(0,1fr); }
  .stats-campaign-meta { grid-template-columns:1fr; gap:.1rem; }
  .stats-campaign-meta dd { margin:0 0 .35rem; }
  .stats-modal-ready .stats-modal { padding:.2rem; }
  .stats-modal-ready .stats-modal-shell { max-height:calc(100vh - .4rem);
    border-radius:9px; padding:.75rem; }
}
#busy-overlay { position:fixed; inset:0; z-index:1000; display:none;
  align-items:center; justify-content:center;
  background:color-mix(in srgb, var(--bg) 78%, transparent);
  backdrop-filter:blur(2px); }
#busy-overlay.on { display:flex; }
#busy-overlay .box { background:var(--card); border:1px solid var(--line);
  border-radius:14px; padding:26px 34px; box-shadow:0 12px 40px rgba(0,0,0,.18);
  display:flex; flex-direction:column; align-items:center; gap:14px;
  max-width:min(90vw,420px); text-align:center; }
#busy-overlay .spin { width:38px; height:38px; border-radius:50%;
  border:4px solid var(--line); border-top-color:var(--accent);
  animation:busy-rot .8s linear infinite; }
#busy-overlay .msg { font-weight:600; color:var(--ink); }
#busy-overlay .sub { font-size:.82rem; color:var(--muted); }
@keyframes busy-rot { to { transform:rotate(360deg); } }
button.is-busy { opacity:.6; pointer-events:none; }
@media (prefers-reduced-motion:reduce){ #busy-overlay .spin{ animation:none; } }
"""


_BUILDER_SCRIPT = """<script>(function(){
var form=document.getElementById('builder');
if(!form){return;}
var picker=document.getElementById('model-picker');
var pickerRole='target';var pickerKind='';var pickerLastFocus=null;
function pickerIsOpen(){return !!(picker&&!picker.hidden);}
function checked(sel,attr){var out=[];
form.querySelectorAll(sel).forEach(function(el){
if(el.checked){out.push(el.getAttribute(attr));}});return out;}
function checkedKind(kind,attr){var out=[];
form.querySelectorAll('.modelbox').forEach(function(el){
if(el.getAttribute('data-target-selected')==='true'&&
el.getAttribute('data-kind')===kind){
out.push(el.getAttribute(attr));}});return out;}
function scopeSet(){var s={};form.querySelectorAll('.modbox').forEach(
function(m){if(m.checked){s[m.getAttribute('data-mod')]=1;}});return s;}
function intersects(list,set){return list.some(function(x){return set[x];});}
function setFilterCount(kind,count){
var out=document.getElementById(kind+'-filter-count');
if(out){out.textContent=count+' shown';}
var empty=document.getElementById(kind+'-filter-empty');
if(empty){empty.style.display=count?'none':'block';}}
function applyTargetFilters(sc,role){
var provider=(document.getElementById('api-provider-filter')||{}).value||'all';
var query=((document.getElementById('local-name-filter')||{}).value||'')
.trim().toLowerCase();
var max=parseFloat((document.getElementById('local-param-number')||{}).value);
if(!Number.isFinite(max)){max=3000;}
var compatible=(document.getElementById('local-compatible-filter')||{}).checked;
var includeUnknown=(document.getElementById('local-unknown-filter')||{}).checked;
var counts={api:0,local:0};
form.querySelectorAll('.modelrow').forEach(function(row){
var mods=(row.getAttribute('data-mods')||'').split(',').filter(Boolean);
var scopeOk=intersects(mods,sc);var kind=row.getAttribute('data-kind')||'';
var backend=row.getAttribute('data-backend')||'';
var filterOk=true;
if(kind==='api'){
filterOk=provider==='all'||row.getAttribute('data-provider')===provider;
}else if(kind==='local'&&backend==='vllm'){
var name=(row.getAttribute('data-name')||'').toLowerCase();
var raw=row.getAttribute('data-params-b')||'';var params=parseFloat(raw);
var paramsOk=Number.isFinite(params)?params<=max:includeUnknown;
var fit=row.getAttribute('data-compatible')||'unknown';
var compatOk=fit==='true'||(fit==='false'&&!compatible)||
(fit==='unknown'&&includeUnknown);
filterOk=name.indexOf(query)!==-1&&paramsOk&&compatOk;}
var visible=scopeOk&&filterOk;row.style.display=visible?'':'none';
// A presentation filter never changes a selected target. Modality scope keeps
// its established behavior because an out-of-scope target cannot serve a lane.
if(role==='target'&&!scopeOk){var cb=row.querySelector('.modelbox');if(cb){
cb.checked=false;cb.setAttribute('data-target-selected','false');}}
if(visible&&kind==='api'){counts.api++;}
if(visible&&kind==='local'&&backend==='vllm'){counts.local++;}
});
setFilterCount('api',counts.api);setFilterCount('local',counts.local);}
function applyScope(){var sc=scopeSet();
// arms: keep an arm only if it shares a modality with the scope
form.querySelectorAll('.armbox').forEach(function(b){
var mods=(b.getAttribute('data-mods')||'').split(',').filter(Boolean);
var ok=intersects(mods,sc);var lab=b.closest('.check');
if(lab){lab.style.display=ok?'':'none';}if(!ok){b.checked=false;}});
form.querySelectorAll('.modgroup').forEach(function(g){
var any=Array.prototype.some.call(g.querySelectorAll('.check'),
function(l){return l.style.display!=='none';});g.style.display=any?'':'none';});
// Frameworks must share a selected modality. Target rows combine that scope
// with their independent filters. vLLM uses name/size/fit filters; Ollama
// rows represent already-pulled daemon artifacts and only follow modality.
form.querySelectorAll('.fwrow').forEach(function(row){
var mods=(row.getAttribute('data-mods')||'').split(',').filter(Boolean);
var ok=intersects(mods,sc);row.style.display=ok?'':'none';
if(!ok){var cb=row.querySelector('.fwbox');if(cb){cb.checked=false;}}});
if(pickerIsOpen()&&pickerRole==='judge'){
applyTargetFilters({text:1},'judge');
}else{applyTargetFilters(sc,'target');}}
function updateUnknownPrecisionBadges(){
var labels={none:'16-bit',fp8:'8-bit FP8',bitsandbytes:'4-bit BitsAndBytes',
awq:'4-bit AWQ',gptq:'4-bit GPTQ'};
form.querySelectorAll(".modelrow[data-compatible='unknown']").forEach(function(row){
var badge=row.querySelector('.precision-badge');var select=row.querySelector('.modelquant select');
var label=badge&&badge.querySelector('.precision-label');
var tip=badge&&badge.querySelector('.tiptext');
if(!badge||!select||!label){return;}var value=select.value;
label.textContent=value==='auto'?'fit unknown':
(labels[value]||value)+' selected · fit unknown';
if(tip){tip.textContent=value==='auto'?
'The operator must choose a per-model precision before a live run.':
'Operator-selected precision; hardware fit remains unknown.';}});
form.querySelectorAll(".modelrow[data-profile-overrides='true']").forEach(function(row){
var select=row.querySelector('.modelquant select');if(!select){return;}
var option=select.options[select.selectedIndex];var fit=option&&option.getAttribute('data-fit');
if(!fit){return;}row.setAttribute('data-compatible',fit);
var disabled=row.getAttribute('data-config-invalid')==='true'||fit==='false';
row.querySelectorAll('.modelbox').forEach(function(input){
input.disabled=disabled;});});}
function applyPreparedFields(){
var any=false;
form.querySelectorAll('.prepared-fields').forEach(function(panel){
var name=panel.getAttribute('data-prepared');
var box=form.querySelector(".fwbox[data-fw='"+name+"']");
var visible=!!(box&&box.checked);panel.hidden=!visible;
panel.setAttribute('aria-hidden',visible?'false':'true');
if(box){box.setAttribute('aria-expanded',visible?'true':'false');}
if(visible){any=true;}});
var group=document.getElementById('prepared-workflows');
if(group){group.hidden=!any;group.setAttribute('aria-hidden',any?'false':'true');}}
var samplePanel=document.getElementById('sample-size-control');
var sampleRange=document.getElementById('sample-limit-range');
var sampleNumber=document.getElementById('sample-limit-number');
var sampleSeed=document.getElementById('sample-seed-input');
function syncSampleSizeControl(){
var arms=checked('.armbox','data-arm');
var mode=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
var drySynthetic=mode==='diagnostic_canary'&&checkedName('canary_dry');
var effectiveCount=drySynthetic?1:arms.length;var enabled=effectiveCount>0;
if(samplePanel){samplePanel.hidden=!enabled;
samplePanel.setAttribute('aria-hidden',enabled?'false':'true');}
[sampleRange,sampleNumber,sampleSeed].forEach(function(input){
if(input){input.disabled=!enabled;}});
var count=document.getElementById('sample-arm-count');
if(count){count.textContent=drySynthetic?'Synthetic arm selected automatically':
arms.length+' arm'+(arms.length===1?'':'s')+' selected';}
if(!sampleRange||!sampleNumber){return;}
var raw=sampleNumber.value.trim();var valid=/^[0-9]+$/.test(raw);
if(mode==='diagnostic_canary'&&!raw){sampleNumber.value='1';raw='1';valid=true;}
var api=checkedKind('api','data-model');var judges=checked('.judgebox','data-judge');
var judgeModelValue=namedValue('judge_model','');
var hostedJudge=judges.indexOf('llm')>=0&&Array.prototype.some.call(
form.querySelectorAll(".modelbox[data-kind='api']"),
function(b){return (b.getAttribute('data-model')||'')===judgeModelValue;});
var localOnlyMeasured=mode==='measured'&&!api.length&&!hostedJudge;
var defaultValue=localOnlyMeasured?0:50;
var value=valid?parseInt(raw,10):defaultValue;
var base=parseInt(sampleRange.getAttribute('data-base-max')||'1000',10);
sampleRange.max=String(Math.max(base,value));sampleRange.value=String(value);
var status=document.getElementById('sample-limit-status');if(!status){return;}
if(!enabled){status.textContent='Select one or more arms to configure sampling';}
else if(!raw&&localOnlyMeasured){status.textContent='Blank composes 0: the full selected release for each arm';}
else if(!raw){status.textContent='Blank uses the CLI default of 50 clusters independently for each selected arm';}
else if(value===0){status.textContent='Full selected release for each of '+effectiveCount+' selected arm'+(effectiveCount===1?'':'s');}
else{status.textContent='Up to '+value+' source clusters in each of '+effectiveCount+' selected arm'+(effectiveCount===1?'':'s');}}
if(sampleRange&&sampleNumber){
sampleRange.addEventListener('input',function(){sampleNumber.value=this.value;});
sampleNumber.addEventListener('input',function(){var raw=this.value.trim();
if(!/^[0-9]+$/.test(raw)){return;}var value=parseInt(raw,10);
var base=parseInt(sampleRange.getAttribute('data-base-max')||'1000',10);
sampleRange.max=String(Math.max(base,value));sampleRange.value=String(value);});}
function rememberPickerSelection(){
if(!pickerIsOpen()){return;}
if(pickerRole==='target'){
form.querySelectorAll('.modelbox').forEach(function(input){
input.setAttribute('data-target-selected',input.checked?'true':'false');});
return;}
var selected=form.querySelector('.modelbox:checked');
var judgeInput=document.getElementById('judge-model-input');
if(selected&&judgeInput){judgeInput.value=selected.getAttribute('data-model')||'';}}
function configurePickerInputs(){
var judgeInput=document.getElementById('judge-model-input');
var judgeModel=judgeInput?judgeInput.value:'';
form.querySelectorAll('.modelbox').forEach(function(input){
var model=input.getAttribute('data-model')||'';
if(pickerRole==='judge'){
input.type='radio';input.name='_judge_model_ui';input.checked=model===judgeModel;
}else{
input.type=input.getAttribute('data-target-type')||'checkbox';
if(input.getAttribute('data-kind')==='local'){input.name='local_choice';}
else{input.removeAttribute('name');}
input.checked=input.getAttribute('data-target-selected')==='true';}});}
function updateSelectionSummaries(){
var targets=checkedKind('api','data-model').concat(
checkedKind('local','data-model'));
var targetOut=document.getElementById('target-model-summary');
if(targetOut){targetOut.textContent=targets.length?
targets.length+' selected: '+targets.join(', '):'No target models selected';}
var judgeInput=document.getElementById('judge-model-input');
var judgeOut=document.getElementById('judge-model-summary');
if(judgeOut){judgeOut.textContent=judgeInput&&judgeInput.value?
judgeInput.value:'No LLM judge model selected';}}
function setPickerRole(role){
pickerRole=role==='judge'?'judge':'target';
if(!picker){return;}picker.setAttribute('data-role',pickerRole);
var title=document.getElementById('model-picker-title');
if(title){title.textContent=pickerRole==='judge'?'Choose LLM judge model':'Choose target models';}
var note=document.getElementById('model-picker-role-note');
if(note){note.textContent=pickerRole==='judge'?
'Choose exactly one judge. It must differ from every target model.':
'Choose one or more hosted targets and at most one local target.';}
configurePickerInputs();}
function showPickerRuntime(){
var runtime=document.getElementById('model-picker-runtime');
var models=document.getElementById('model-picker-models');
if(runtime){runtime.hidden=false;}if(models){models.hidden=true;}
document.querySelectorAll('[data-picker-step]').forEach(function(step){
var active=step.getAttribute('data-picker-step')==='runtime';
step.classList.toggle('on',active);
if(active){step.setAttribute('aria-current','step');}
else{step.removeAttribute('aria-current');step.disabled=!pickerKind;}});
if(runtime){var first=runtime.querySelector('button');if(first){first.focus();}}}
function showPickerModels(kind){
pickerKind=kind==='local'?'local':'api';
var runtime=document.getElementById('model-picker-runtime');
var models=document.getElementById('model-picker-models');
if(runtime){runtime.hidden=true;}if(models){models.hidden=false;}
document.querySelectorAll('.picker-model-panel').forEach(function(panel){
panel.hidden=panel.getAttribute('data-picker-panel')!==pickerKind;});
document.querySelectorAll('[data-picker-step]').forEach(function(step){
var active=step.getAttribute('data-picker-step')==='models';
step.disabled=false;step.classList.toggle('on',active);
if(active){step.setAttribute('aria-current','step');}
else{step.removeAttribute('aria-current');}});
applyTargetFilters(pickerRole==='judge'?{text:1}:scopeSet(),pickerRole);
var panel=document.querySelector(".picker-model-panel[data-picker-panel='"+pickerKind+"']");
if(panel){var first=panel.querySelector('select,input:not([hidden]),button');
if(first){first.focus();}}}
function openPicker(role,opener){
if(!picker){return;}pickerLastFocus=opener||document.activeElement;
pickerKind='';setPickerRole(role);picker.hidden=false;picker.setAttribute('aria-hidden','false');
document.body.classList.add('model-picker-open');
document.querySelectorAll('[data-open-model-picker]').forEach(function(button){
button.setAttribute('aria-expanded',button===opener?'true':'false');});
showPickerRuntime();}
function closePicker(){
if(!picker||picker.hidden){return;}rememberPickerSelection();
picker.hidden=true;picker.setAttribute('aria-hidden','true');setPickerRole('target');
document.body.classList.remove('model-picker-open');
document.querySelectorAll('[data-open-model-picker]').forEach(function(button){
button.setAttribute('aria-expanded','false');});
applyTargetFilters(scopeSet(),'target');
if(pickerLastFocus&&typeof pickerLastFocus.focus==='function'){pickerLastFocus.focus();}}
document.querySelectorAll('[data-open-model-picker]').forEach(function(button){
button.addEventListener('click',function(){openPicker(this.getAttribute('data-open-model-picker'),this);});});
document.querySelectorAll('[data-close-model-picker]').forEach(function(button){
button.addEventListener('click',closePicker);});
document.querySelectorAll('[data-picker-kind]').forEach(function(button){
button.addEventListener('click',function(){showPickerModels(this.getAttribute('data-picker-kind'));});});
document.querySelectorAll('[data-picker-step]').forEach(function(button){
button.addEventListener('click',function(){
var step=this.getAttribute('data-picker-step');
if(step==='runtime'){showPickerRuntime();}
else if(step==='models'&&pickerKind){showPickerModels(pickerKind);}});});
if(picker){picker.addEventListener('click',function(event){if(event.target===picker){closePicker();}});
picker.addEventListener('keydown',function(event){
if(event.key==='Escape'){event.preventDefault();closePicker();return;}
if(event.key!=='Tab'){return;}
var focusable=Array.prototype.filter.call(picker.querySelectorAll(
'button:not([disabled]),input:not([disabled]):not([hidden]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'),
function(node){return !node.hidden&&node.offsetParent!==null;});
if(!focusable.length){event.preventDefault();return;}
var first=focusable[0];var last=focusable[focusable.length-1];
if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}});}
form.querySelectorAll('.modelbox').forEach(function(input){
input.addEventListener('change',function(){
rememberPickerSelection();updateSelectionSummaries();});});
function namedValue(name,fallback){var field=form.elements.namedItem(name);
var value=field&&typeof field.value==='string'?field.value.trim():'';
return value||fallback;}
function checkedName(name){var field=form.querySelector("input[name='"+name+"']");
return !!(field&&field.checked);}
function selectionLabel(values){if(!values.length){return 'none selected';}
var shown=values.slice(0,3).join(', ');return shown+(values.length>3?
' +'+(values.length-3)+' more':'');}
function pairState(pathName,digestName){var path=namedValue(pathName,'');
var digest=namedValue(digestName,'');if(path&&digest){return 'set';}
if(path||digest){return 'incomplete';}return 'not set';}
function setBuildSummary(id,value){var out=document.getElementById(id);
if(out){out.textContent=value;}}
function refresh(){rememberPickerSelection();updateUnknownPrecisionBadges();
applyScope();applyPreparedFields();
syncSampleSizeControl();
updateSelectionSummaries();
// live preview
var mode=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
var flagFor={dry_run:'--dry-run',attestation_probe:'--attestation-probe',
diagnostic_canary:'--diagnostic-canary',measured:''};
var parts=['run_matrix'];
if(flagFor[mode]){parts.push(flagFor[mode]);}
var drySynthetic=mode==='diagnostic_canary'&&checkedName('canary_dry');
if(drySynthetic){parts.push('--dry-run');}
var api=checkedKind('api','data-model');if(api.length&&!drySynthetic){parts.push('--api '+api.join(','));}
var loc=checkedKind('local','data-model');if(loc.length&&!drySynthetic){parts.push('--local '+loc.join(','));}
var arms=checked('.armbox','data-arm');
if(drySynthetic){parts.push('--corpora synth');}
else if(arms.length){parts.push('--corpora '+arms.join(','));}
var fw=checked('.fwbox','data-fw');if(fw.length){parts.push('--attackers '+fw.join(','));}
var jg=checked('.judgebox','data-judge');if(jg.length){parts.push('--judges '+jg.join(','));}
var lim=form.querySelector('input[name=limit]').value;
var judgeModelValue=namedValue('judge_model','');
var hostedJudge=jg.indexOf('llm')>=0&&Array.prototype.some.call(
form.querySelectorAll(".modelbox[data-kind='api']"),
function(b){return (b.getAttribute('data-model')||'')===judgeModelValue;});
// a blank limit composes --limit 0 (the complete release) only where
// validation admits it: a measured lane with no hosted target and no hosted
// LLM judge; hosted paid lanes, probes, and canaries must type a value
// (a positive bound or an explicit 0 for a separately approved full cohort)
var localOnlyMeasured=mode==='measured'&&!api.length&&!hostedJudge;
if(lim){parts.push('--limit '+lim);}
else if(localOnlyMeasured){parts.push('--limit 0');}
var grp=namedValue('group','');if(grp){parts.push('--group '+grp);}
if(checkedName('exclude_tool_conditioned')){parts.push('--exclude-tool-conditioned');}
if(checkedName('reset_open_circuits')&&mode==='measured'){parts.push('--reset-open-circuits');}
var stale=namedValue('lock_stale_seconds','');if(stale){parts.push('--lock-stale-seconds '+stale);}
var mods=checked('.modbox','data-mod');var targets=api.concat(loc);
setBuildSummary('build-summary-composition',mode+'; modalities: '+
selectionLabel(mods)+'; targets: '+selectionLabel(drySynthetic?[]:targets)+
'; corpora: '+selectionLabel(drySynthetic?['synth (automatic)']:arms)+
'; attacks: '+selectionLabel(fw));
var judgeModel=namedValue('judge_model','not selected');
var approx=checkedName('approximate_common_metrics')?'enabled':'off';
var defense=namedValue('defense','none');var defenseGuard=namedValue('defense_guard','rules');
var scoringGuard=namedValue('guardrail_model','')?'configured':'not set';
var defenseGuardrail=namedValue('defense_guardrail_model','')?'configured':'not set';
setBuildSummary('build-summary-evaluation','judges: '+selectionLabel(jg)+
'; LLM model: '+judgeModel+'; approximate metrics: '+approx+'; defense: '+
defense+' / '+defenseGuard+'; scoring guardrail: '+scoringGuard+
'; defense guardrail: '+defenseGuardrail);
var completeAtt=0;var incompleteAtt=0;
form.querySelectorAll('.attrow').forEach(function(row){var fields=row.querySelectorAll('input');
var path=(fields[0]&&fields[0].value.trim())||'';
var digest=(fields[1]&&fields[1].value.trim())||'';
if(path&&digest){completeAtt++;}else if(path||digest){incompleteAtt++;}});
setBuildSummary('build-summary-admission','project receipt: '+
pairState('project_revision','project_revision_sha')+'; source receipt: '+
pairState('source_conformance','source_conformance_sha')+'; attestations: '+
completeAtt+' complete'+(incompleteAtt?(', '+incompleteAtt+' incomplete'):'')+
'; scope: '+namedValue('scope','not set')+'; max age: '+namedValue('max_age','not set'));
setBuildSummary('build-summary-trajectory','per-arm limit: '+namedValue('limit',
localOnlyMeasured?'0 (complete release)':'not set')+
'; sample seed: '+namedValue('sample_seed','not set')+'; seeds: '+
namedValue('seeds','not set')+'; queries: '+namedValue('max_queries','not set')+
'; turns: '+namedValue('max_turns','not set')+'; group: '+namedValue('group','CLI default')+
'; exclude tool-conditioned: '+(checkedName('exclude_tool_conditioned')?'on':'off')+
'; reset open circuits: '+(checkedName('reset_open_circuits')?'on':'off')+
'; lock stale seconds: '+namedValue('lock_stale_seconds','CLI default'));
setBuildSummary('build-summary-budget','target / judge / HTTP: '+
namedValue('cap_target','not set')+' / '+namedValue('cap_judge','not set')+
' / '+namedValue('cap_http','not set')+'; local call-start budget: '+
namedValue('local_budget_hours','not set')+' h; call-start window: '+
namedValue('deadline','not set')+' s (not a completion timeout)');
var localPrecisions=[];
form.querySelectorAll(".modelbox[data-kind='local'][data-target-selected='true']")
.forEach(function(input){var row=input.closest('.modelrow');var precision=row&&
row.querySelector('.modelquant select');if(precision){localPrecisions.push(
(input.getAttribute('data-model')||'local')+': '+precision.value);}});
setBuildSummary('build-summary-local','dtype: '+namedValue('dtype','auto')+
'; default quantization: '+namedValue('quantization','auto')+
(localPrecisions.length?'; selected model: '+localPrecisions.join(', '):''));
setBuildSummary('build-summary-output',namedValue('out','not set'));
var prev=document.getElementById('buildpreview');
if(prev){prev.textContent=parts.join(' ');}}
form.addEventListener('change',refresh);
form.addEventListener('input',refresh);
// The tool-conditioned exclusion is an offline-smoke-only diagnostic.  It is
// enabled and defaults ON only for a standalone dry run; evidence-bearing
// preflight, probe, canary, and measured routes must retain whole clusters.
function applyExclusionDefault(){var box=form.querySelector("input[name='exclude_tool_conditioned']");
if(!box){return;}var m=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
box.disabled=m!=='dry_run';box.checked=m==='dry_run';refresh();}
form.querySelectorAll("input[name='mode'],input[name='canary_dry']").forEach(function(el){
el.addEventListener('change',applyExclusionDefault);});
// The two maximum-parameter controls are one filter, expressed in billions.
var paramRange=document.getElementById('local-param-range');
var paramNumber=document.getElementById('local-param-number');
function boundedParam(value){var n=parseFloat(value);
if(!Number.isFinite(n)){return 3000;}
return Math.min(3000,Math.max(.01,Math.round(n*100)/100));}
if(paramRange&&paramNumber){
paramRange.addEventListener('input',function(){paramNumber.value=this.value;refresh();});
paramNumber.addEventListener('input',function(){
if(this.value===''){paramRange.value='3000';refresh();return;}
var n=boundedParam(this.value);this.value=String(n);paramRange.value=String(n);
refresh();});
paramNumber.addEventListener('blur',function(){
var n=boundedParam(this.value);this.value=String(n);paramRange.value=String(n);
refresh();});}
// per-group All / None bulk selection over the group's visible arms
form.querySelectorAll('.linkbtn').forEach(function(btn){
btn.addEventListener('click',function(){
var on=this.getAttribute('data-sel')==='all';
var group=this.closest('.modgroup');
group.querySelectorAll('.armbox').forEach(function(b){
var lab=b.closest('.check');
if(!lab||lab.style.display!=='none'){b.checked=on;}});refresh();});});
// server-side re-render prefill: re-check the composed selections
var preEl=document.getElementById('builder-prefill');
if(preEl){try{var pre=JSON.parse(preEl.textContent);
function apply(list,sel,attr){if(!list||!list.length){return;}
form.querySelectorAll(sel).forEach(function(b){
b.checked=list.indexOf(b.getAttribute(attr))>=0;});}
apply(pre.corpora,'.armbox','data-arm');
apply(pre.attackers,'.fwbox','data-fw');
if((pre.api&&pre.api.length)||(pre.local&&pre.local.length)){
form.querySelectorAll('.modelbox').forEach(function(b){
var kind=b.getAttribute('data-kind');
var list=kind==='api'?(pre.api||[]):(pre.local||[]);
var selected=list.indexOf(b.getAttribute('data-model'))>=0;
b.setAttribute('data-target-selected',selected?'true':'false');
if(pickerRole==='target'){b.checked=selected;}});}
}catch(e){}}
// repeatable live-attestation receipt/digest rows (paired in order)
var addBtn=document.getElementById('addatt');
if(addBtn){addBtn.addEventListener('click',function(){
var rows=document.getElementById('attrows');
var n=rows.querySelectorAll('.attrow').length+1;
if(n>12){return;}
var div=document.createElement('div');div.className='attrow';
div.setAttribute('data-row',n);
div.innerHTML="<input class='wide' type='text' name='att_path"+n+
"' placeholder='runs/thesis/attest/receipt.live-attestation.json'>"+
"<input class='wide' type='text' name='att_sha"+n+
"' placeholder='exact 64-hex sha256'>";
rows.appendChild(div);refresh();});}
form.addEventListener('submit',function(){
form.querySelector("input[name=corpora]").value=checked('.armbox','data-arm').join(',');
form.querySelector("input[name=api]").value=checkedKind('api','data-model').join(',');
form.querySelector("input[name=local]").value=checkedKind('local','data-model').join(',');
form.querySelector("input[name=attackers]").value=checked('.fwbox','data-fw').join(',');
form.querySelector("input[name=judges]").value=checked('.judgebox','data-judge').join(',');});
refresh();
})();</script>"""


_NAV_LINKS = (
    ("/", "grid", "Dashboard"),
    ("/build", "flask", "Build"),
    ("/commands", "terminal", "Run"),
    ("/jobs", "pulse", "Jobs"),
    ("/stats", "chart", "Stats"),
    ("/config", "sliders", "Config"),
    ("/artifacts", "folder", "Artifacts"),
)


def _page_tablist(
    label: str,
    tabs: tuple[tuple[str, str], ...],
    *,
    default: str,
) -> str:
    """Render a shared, progressively enhanced top-level page tab list."""
    buttons = []
    for panel_id, tab_label in tabs:
        selected = panel_id == default
        buttons.append(
            "<button type='button' class='page-tab' role='tab' "
            f"id='{html.escape(panel_id)}-tab' "
            f"aria-controls='{html.escape(panel_id)}' "
            f"aria-selected='{'true' if selected else 'false'}' "
            f"tabindex='{'0' if selected else '-1'}' "
            f"data-page-tab='{html.escape(panel_id)}'>"
            f"{html.escape(tab_label)}</button>"
        )
    return (
        "<div class='page-tablist' role='tablist' aria-orientation='horizontal' "
        f"aria-label='{html.escape(label)}'>"
        + "".join(buttons)
        + "</div>"
    )


def _page_tabpanel(panel_id: str, body: str) -> str:
    """Render an initially visible panel; JavaScript hides inactive peers."""
    escaped_id = html.escape(panel_id)
    return (
        f"<section class='page-tabpanel' id='{escaped_id}' role='tabpanel' "
        f"aria-labelledby='{escaped_id}-tab' tabindex='0' "
        f"data-page-panel='{escaped_id}'>{body}</section>"
    )


_PAGE_TABS_SCRIPT = """<script>(function(){
function owned(root,selector){return Array.prototype.filter.call(
root.querySelectorAll(selector),function(node){return node.closest(
"[data-page-tabs]")===root;});}
function hashPanel(root){var raw=window.location.hash.slice(1);if(!raw){return null;}
var id;try{id=decodeURIComponent(raw);}catch(error){id=raw;}
var target=document.getElementById(id);if(!target||!root.contains(target)){return null;}
var panel=target.matches("[data-page-panel]")?target:
target.closest("[data-page-panel]");
return panel&&panel.closest("[data-page-tabs]")===root?panel:null;}
function init(root){var tabs=owned(root,"[data-page-tab]");
var panels=owned(root,"[data-page-panel]");if(!tabs.length||!panels.length){return;}
var key="ura-page-tab:"+(root.getAttribute("data-tab-key")||window.location.pathname);
function valid(id){return tabs.some(function(tab){return tab.getAttribute(
"data-page-tab")===id;});}
function remember(id){try{window.sessionStorage.setItem(key,id);}catch(error){}}
function activate(id,options){options=options||{};if(!valid(id)){return false;}
tabs.forEach(function(tab){var on=tab.getAttribute("data-page-tab")===id;
tab.setAttribute("aria-selected",on?"true":"false");tab.tabIndex=on?0:-1;
if(on&&options.focus){tab.focus();}});
panels.forEach(function(panel){panel.hidden=panel.getAttribute(
"data-page-panel")!==id;});remember(id);
if(options.hash){var next=window.location.pathname+window.location.search+"#"+
encodeURIComponent(id);window.history.replaceState(window.history.state,"",next);}
return true;}
root.classList.add("tabs-ready");
tabs.forEach(function(tab,index){tab.addEventListener("click",function(){
activate(tab.getAttribute("data-page-tab"),{hash:true});});
tab.addEventListener("keydown",function(event){var next=index;
if(event.key==="ArrowRight"){next=(index+1)%tabs.length;}
else if(event.key==="ArrowLeft"){next=(index+tabs.length-1)%tabs.length;}
else if(event.key==="Home"){next=0;}else if(event.key==="End"){next=tabs.length-1;}
else{return;}event.preventDefault();activate(tabs[next].getAttribute(
"data-page-tab"),{focus:true,hash:true});});});
var initialPanel=hashPanel(root);var initial=initialPanel?
initialPanel.getAttribute("data-page-panel"):"";
if(!initial&&root.getAttribute("data-force-default")!=="true"){
try{initial=window.sessionStorage.getItem(key)||"";}catch(error){initial="";}}
if(!valid(initial)){initial=root.getAttribute("data-default-tab")||"";}
if(!valid(initial)){initial=tabs[0].getAttribute("data-page-tab");}
activate(initial);root._activatePageTab=activate;}
var roots=Array.prototype.slice.call(document.querySelectorAll("[data-page-tabs]"));
roots.forEach(init);window.addEventListener("hashchange",function(){
roots.forEach(function(root){var panel=hashPanel(root);if(panel&&root._activatePageTab){
root._activatePageTab(panel.getAttribute("data-page-panel"));}});});
})();</script>"""

_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
    "<path fill='#0a5fb4' d='M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z'/>"
    "<path fill='none' stroke='#ffffff' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round' "
    "d='M8.5 12.5l2.5 2.5 4.5-5'/></svg>"
).encode("utf-8")


def _page(title: str, body: str, active: str = "") -> bytes:
    links = "".join(
        f"<a href='{href}'"
        + (" class='active'" if label == active else "")
        + f">{_icon(icon, size=16)}{label}</a>"
        for href, icon, label in _NAV_LINKS
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<link rel='icon' type='image/svg+xml' href='/static/favicon.svg'>"
        "<link rel='stylesheet' href='/static/style.css'></head><body>"
        f"<nav><span class='brand'>{_icon('logo', size=21)}URA rig console"
        f"</span>{links}</nav>"
        f"<main>{body}"
        "<footer class='note'>The CLI and filesystem artifacts remain "
        "authoritative. This console never reinterprets experiment "
        "semantics; diagnostic evidence never authorizes a campaign."
        "</footer></main>" + _PAGE_TABS_SCRIPT + _BUSY_OVERLAY + "</body></html>"
    ).encode("utf-8")


#: A modal busy overlay shown while a slow POST (a pricing fetch, a reindex) is
#: in flight, so the operator sees progress and cannot double-submit.  A form
#: opts in with ``data-busy="<message>"``; the overlay is dismissed if the page
#: is restored from the back/forward cache.
_BUSY_OVERLAY = (
    "<div id='busy-overlay' role='alert' aria-live='assertive'>"
    "<div class='box'><div class='spin'></div>"
    "<div class='msg' id='busy-msg'>Working...</div>"
    "<div class='sub'>This can take up to a minute. Keep this tab open.</div>"
    "</div></div>"
    "<script>(function(){"
    "var ov=document.getElementById('busy-overlay');"
    "var msg=document.getElementById('busy-msg');"
    "document.addEventListener('submit',function(e){"
    "var f=e.target;"
    "if(!f||!f.hasAttribute('data-busy'))return;"
    "if(f.dataset.busyGo){e.preventDefault();return;}"  # block double-submit
    "f.dataset.busyGo='1';"
    "msg.textContent=f.getAttribute('data-busy')||'Working...';"
    "ov.classList.add('on');"
    "var b=f.querySelector('button[type=submit],button:not([type])');"
    "if(b)b.classList.add('is-busy');"
    "},true);"
    "window.addEventListener('pageshow',function(ev){"
    "if(!ev.persisted)return;"
    "ov.classList.remove('on');"
    "document.querySelectorAll('form[data-busy]').forEach(function(f){"
    "delete f.dataset.busyGo;"
    "var b=f.querySelector('button');if(b)b.classList.remove('is-busy');});"
    "});})();</script>"
)


def _badges_html(badges: list[tuple[str, str]]) -> str:
    return "".join(
        f"<span class='badge {html.escape(tone)}'>{html.escape(label)}</span>"
        for label, tone in badges
    )


def _human_size(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.0f} {unit}" if unit == "B" else f"{size:,.1f} {unit}"
        size /= 1024
    return f"{size:,.1f} TB"


def _human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def _crumbs(relative: str) -> str:
    parts = [part for part in relative.replace("\\", "/").split("/") if part]
    links = ["<a href='/artifacts'>runs</a>"]
    so_far: list[str] = []
    for part in parts:
        so_far.append(part)
        target = quote("/".join(so_far))
        links.append(f"<a href='/artifacts?path={target}'>{html.escape(part)}</a>")
    return "<p class='crumbs'>" + "<span class='sep'>/</span>".join(links) + "</p>"
