"""Shared HTML, CSS, JavaScript, and compact rendering helpers."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from urllib.parse import quote

from .catalog import _icon
from .campaign_guide import STYLE as _CAMPAIGN_GUIDE_STYLE

_STYLE = """
:root { color-scheme: light;
  --bg:#eef1f5; --card:#ffffff; --ink:#182430; --muted:#5b6b7c;
  --line:#d9e0e8; --accent:#0a5fb4; --accent-ink:#ffffff;
  --soft:#f4f7fa; --shadow:0 1px 2px rgba(16,24,32,.06),
  0 4px 14px rgba(16,24,32,.05);
  --m-text:#0a66c2; --m-text-bg:#e4eefb; --m-image:#1d7a43;
  --m-image-bg:#e1f2e8; --m-audio:#a86400; --m-audio-bg:#f7ecd9;
  --m-video:#7a3fb8; --m-video-bg:#f0e7fa;
  --ok:#1d6b35; --ok-soft:#d9f4e1; --bad:#8c1d24; --bad-soft:#fde0e2;
  --warn:#7a5200; --warn-soft:#ffe9c2;
  --badge-green-bg:var(--ok); --badge-green-ink:var(--ok-soft);
  --badge-red-bg:var(--bad); --badge-red-ink:var(--bad-soft);
  --badge-amber-bg:var(--warn); --badge-amber-ink:var(--warn-soft);
  --badge-blue-bg:#0b4c8c; --badge-blue-ink:#dcecfd;
  --chevron:url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%20fill='none'%20stroke='%235b6b7c'%20stroke-width='2.2'%20stroke-linecap='round'%20stroke-linejoin='round'%3E%3Cpath%20d='M6%209l6%206%206-6'/%3E%3C/svg%3E"); }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme]), :root[data-theme=harbor] { color-scheme:dark;
    --bg:#10161d; --card:#19212b; --ink:#e7edf3; --muted:#92a3b4;
    --line:#28323e; --accent:#59a3ea; --accent-ink:#0d1621;
    --soft:#141b23; --shadow:0 1px 2px rgba(0,0,0,.35);
    --m-text:#79b7f7; --m-text-bg:#16304a; --m-image:#63cb90;
    --m-image-bg:#12301f; --m-audio:#f0b25e; --m-audio-bg:#3a2a10;
    --m-video:#c89df3; --m-video-bg:#2d1b41;
    --chevron:url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%20fill='none'%20stroke='%2392a3b4'%20stroke-width='2.2'%20stroke-linecap='round'%20stroke-linejoin='round'%3E%3Cpath%20d='M6%209l6%206%206-6'/%3E%3C/svg%3E"); } }
/* Four named palettes, mapped onto the console's existing tokens. */
:root[data-theme=slate] {
  --bg:#eef1f4; --card:#ffffff; --ink:#16191c; --muted:#57616b; --line:#d4dae0;
  --accent:#0e7c96; --accent-ink:#ffffff; --soft:#dcf0f5;
  --ok:#12683a; --ok-soft:#dff2e6; --bad:#a52016; --bad-soft:#fbe6e4;
  --warn:#7d5300; --warn-soft:#faf0da;
}
:root[data-theme=parchment] {
  --bg:#f2ede2; --card:#fbf8f1; --ink:#241f18; --muted:#6a5f4e; --line:#ddd4c2;
  --accent:#14657d; --accent-ink:#ffffff; --soft:#e2eef2;
  --ok:#4a6317; --ok-soft:#edf2df; --bad:#97331d; --bad-soft:#f7e6e0;
  --warn:#8a5a12; --warn-soft:#f7eddb;
}
:root[data-theme=midnight] {
  --bg:#0e1116; --card:#161b22; --ink:#e8ecf1; --muted:#96a3b1; --line:#262d36;
  --accent:#35b3d0; --accent-ink:#06161c; --soft:#142530;
  --ok:#58d089; --ok-soft:#10261a; --bad:#ff9a90; --bad-soft:#2c1512;
  --warn:#e8bd62; --warn-soft:#2a2010;
}
:root[data-theme=ash] {
  --bg:#1a1a1c; --card:#232326; --ink:#ececed; --muted:#9c9ca1; --line:#333338;
  --accent:#7aa2c4; --accent-ink:#10161c; --soft:#1f2a34;
  --ok:#7fcf95; --ok-soft:#16241a; --bad:#f0938c; --bad-soft:#2a1614;
  --warn:#ddb96c; --warn-soft:#281f11;
}
:root[data-theme=slate], :root[data-theme=parchment], :root[data-theme=midnight], :root[data-theme=ash] {
  --badge-green-bg:var(--ok-soft); --badge-green-ink:var(--ok);
  --badge-red-bg:var(--bad-soft); --badge-red-ink:var(--bad);
  --badge-amber-bg:var(--warn-soft); --badge-amber-ink:var(--warn);
  --badge-blue-bg:var(--soft); --badge-blue-ink:var(--accent);
  --shadow:0 1px 2px rgba(16,24,32,.05),0 3px 10px rgba(16,24,32,.04);
}
:root[data-theme=midnight], :root[data-theme=ash] {
  color-scheme:dark;
  --shadow:0 1px 2px rgba(0,0,0,.45),0 4px 14px rgba(0,0,0,.3);
  --m-text:#79b7f7; --m-text-bg:#16304a; --m-image:#63cb90; --m-image-bg:#12301f;
  --m-audio:#f0b25e; --m-audio-bg:#3a2a10; --m-video:#c89df3; --m-video-bg:#2d1b41;
  --chevron:url("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%2024%2024'%20fill='none'%20stroke='%2392a3b4'%20stroke-width='2.2'%20stroke-linecap='round'%20stroke-linejoin='round'%3E%3Cpath%20d='M6%209l6%206%206-6'/%3E%3C/svg%3E");
}
* { box-sizing: border-box; }
[hidden] { display:none !important; }
body { margin:0; font:15px/1.55 system-ui, "Segoe UI", sans-serif;
  background:var(--bg); color:var(--ink); }
main { max-width:1160px; margin:0 auto; padding:1.4rem 1.2rem 2rem; }
body > nav { position:sticky; top:0; z-index:5; }
nav { background:var(--card);
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
.display-preferences { display:flex; flex-wrap:wrap; align-items:center; gap:.5rem 1rem; margin-left:auto; }
.theme-control, .language-control { display:flex; align-items:center; gap:.5rem;
  padding:.25rem 0; color:var(--muted); font-size:.82rem; font-weight:600; }
.theme-control select { min-width:8rem; max-width:100%; font-size:.82rem; }
.language-choice { position:relative; display:inline-flex; }
.language-choice svg { position:absolute; left:.65rem; top:50%; transform:translateY(-50%);
  width:1.3rem; height:.9rem; pointer-events:none; border:1px solid var(--line); border-radius:2px; }
.language-control select { min-width:5.5rem; max-width:100%; font-size:.82rem; padding-left:2.3rem; }
.review-theme-bar { max-width:960px; margin:.75rem auto 0; padding:0 1.2rem;
  display:flex; justify-content:flex-end; }
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
.campaign-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr)); gap:1rem; margin:1.25rem 0; }
.campaign-grid[hidden] { display:none; }
.campaign-grid .campaign-card { margin:0; padding:1.35rem; min-width:0; }
.campaign-assessment-options { min-width:0; border:1px solid var(--line); border-radius:10px; padding:1rem; margin:1.25rem 0; }
.campaign-assessment-options legend { font-weight:600; padding:0 .4rem; }
.campaign-card h2 { margin-bottom:1.25rem; overflow-wrap:anywhere; }
.campaign-card > .button { align-self:flex-start; }
.campaign-ownership { display:grid; gap:.65rem; }
.campaign-ownership-row { display:flex; flex-wrap:wrap; align-items:flex-end; gap:1rem; }
.campaign-field { display:grid; gap:.5rem; min-width:0; font-weight:600; font-size:.9rem; }
.campaign-field[hidden] { display:none !important; }
.campaign-field.separated-field { margin-top:1rem; }
.haiku-judging-controls { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:1rem; margin:1rem 0; }
.judging-funding-summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(14rem,1fr)); gap:1rem; margin:1.5rem 0; }
.judging-funding-summary>div { background:var(--card); border:1px solid var(--line); border-radius:.65rem; padding:1rem; }
.judging-funding-summary dt { color:var(--muted); }
.judging-funding-summary dd { margin:.5rem 0 0; font-size:1.6rem; font-weight:700; }
.judging-inventory-table { width:100%; }
.judging-inventory-table td:nth-child(2) { overflow-wrap:anywhere; }
@media(max-width:640px) {
  .judging-inventory-table, .judging-inventory-table tbody { display:block; }
  .judging-inventory-table thead { display:none; }
  .judging-inventory-table tbody tr { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); padding:.75rem 0; border-bottom:1px solid var(--line); }
  .judging-inventory-table td { display:block; border:0; padding:.35rem; min-width:0; }
  .judging-inventory-table td:first-child, .judging-inventory-table td:nth-child(2) { grid-column:1/-1; }
  .judging-inventory-table td:nth-child(2) { font-weight:600; }
  .judging-inventory-table td[data-label]::before { content:attr(data-label); display:block; font-size:.7rem; color:var(--muted); }
}
@media(max-width:640px) { .haiku-judging-controls { grid-template-columns:minmax(0,1fr); } }
.campaign-ownership-row .campaign-field { flex:1 1 280px; max-width:36rem; }
.campaign-field select, .campaign-field input { box-sizing:border-box; width:100%; min-width:0; min-height:2.65rem; margin:0;
  padding:.65rem .8rem; border:1px solid var(--line); border-radius:8px; background-color:var(--bg); color:var(--ink); font:inherit; font-weight:400; }
.campaign-field select { padding-right:2.2rem; }
.campaign-field input:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
.campaign-result-filters { display:grid; gap:1rem; margin:1rem 0; }
.campaign-result-filters form { display:flex; flex-wrap:wrap; gap:.75rem; align-items:flex-end; margin:0; }
.campaign-result-filters .campaign-field { flex:1 1 20rem; max-width:48rem; }
.campaign-result-filters button { margin:0; min-height:2.65rem; }
.comparison-condition { min-width:0; overflow-wrap:anywhere; margin:0; padding:1rem;
  border:1px solid var(--line); border-radius:10px; }
.comparison-condition legend { padding:0 .4rem; font-weight:600; }
.comparison-pair { margin:1rem 0; padding:1rem; border:1px solid var(--line); border-radius:10px; overflow-wrap:anywhere; }
.comparison-pair > summary { cursor:pointer; padding:.35rem 0; font-weight:600; }
.comparison-condition .campaign-field + .campaign-field { margin-top:1rem; }
.campaign-ownership > .note { margin:0; line-height:1.55; }
.campaign-create-card { max-width:44rem; padding:1.5rem; margin:1.5rem 0; }
.campaign-create-form { display:grid; gap:1.5rem; margin:0; }
.campaign-actions { display:flex; flex-wrap:wrap; align-items:center; gap:.75rem; padding-top:1rem; border-top:1px solid var(--line); }
.source-preparation { min-width:0; }
.source-preparation > p { max-width:85ch; }
.source-steps { display:flex; flex-wrap:wrap; gap:.6rem 1.25rem; margin:1.25rem 0; color:var(--muted); font-size:.85rem; }
.source-campaign-row { display:flex; align-items:flex-end; flex-wrap:wrap; gap:.85rem; margin:1.25rem 0; }
.source-campaign-row .campaign-field { flex:1 1 18rem; max-width:36rem; }
.source-campaign-row button { min-height:2.65rem; margin:0; }
.source-run-fieldset { min-width:0; border:0; padding:0; margin:1.5rem 0; }
.source-run-fieldset legend { font-weight:700; margin-bottom:.75rem; }
.source-run-picker { max-height:24rem; overflow:auto; margin-top:.8rem; border:1px solid var(--line); border-radius:8px; }
.source-run-choice { display:flex; align-items:flex-start; gap:.8rem; padding:.9rem; border-bottom:1px solid var(--line); cursor:pointer; }
.source-run-choice:last-child { border-bottom:0; }
.source-run-choice[hidden] { display:none; }
.source-run-choice:has(input:checked) { background:var(--soft); }
.source-run-choice input { flex:0 0 auto; margin:.25rem 0 0; }
.source-run-choice > span { min-width:0; display:grid; gap:.3rem; overflow-wrap:anywhere; }
.source-run-choice small { color:var(--muted); }
@media(max-width:540px) { .source-campaign-row .campaign-field { max-width:none; } .source-campaign-row button { width:100%; } }
.work-kind-choices { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr)); gap:1rem; margin:1rem 0 1.5rem; }
.work-kind-choice { display:flex; align-items:flex-start; gap:.75rem; padding:1rem; border:1px solid var(--line); border-radius:10px; cursor:pointer; min-width:0; }
.work-kind-choice:has(input:checked) { border-color:var(--accent); background:var(--soft); }
.work-kind-choice input { flex:0 0 auto; margin-top:.2rem; }
.work-kind-choice > span { display:grid; gap:.4rem; }
.work-kind-choice > span > span { font-size:.9rem; color:var(--muted); line-height:1.5; }
.build-purpose [hidden] { display:none !important; }
.campaign-secondary { margin-top:1.5rem; }
@media (max-width:540px) {
  .campaign-create-card, .campaign-grid .campaign-card { padding:1rem; }
  .campaign-ownership-row { align-items:stretch; }
  .campaign-ownership-row .campaign-field { flex-basis:100%; max-width:none; }
  .campaign-actions > *, .campaign-ownership-row > .button { justify-content:center; min-height:2.65rem; }
}
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
.campaign-costs table { table-layout:fixed; min-width:58rem; }
.campaign-costs th, .campaign-costs td { overflow-wrap:anywhere; }
.campaign-costs th:nth-child(1) { width:27%; }
.campaign-costs th:nth-child(2) { width:8%; }
.campaign-costs th:nth-child(3) { width:13%; }
.campaign-costs th:nth-child(4), .campaign-costs th:nth-child(5) { width:16%; }
.campaign-costs th:nth-child(6) { width:20%; }
.campaign-output-table table { table-layout:fixed; min-width:58rem; }
.campaign-output-table th, .campaign-output-table td { overflow-wrap:anywhere; }
.campaign-output-table th { white-space:nowrap; font-size:.7rem; letter-spacing:.02em; }
.campaign-output-table td:nth-child(3), .campaign-output-table td:nth-child(4) { white-space:nowrap; }
.campaign-output-table th:nth-child(1) { width:19%; }
.campaign-output-table th:nth-child(2) { width:13%; }
.campaign-output-table th:nth-child(3) { width:9%; }
.campaign-output-table th:nth-child(4) { width:8%; }
.campaign-output-table th:nth-child(5) { width:17%; }
.campaign-output-table th:nth-child(6) { width:9%; }
.campaign-output-table th:nth-child(7) { width:10%; }
.campaign-output-table th:nth-child(8) { width:15%; }
pre { background:var(--soft); border:1px solid var(--line);
  border-radius:10px; padding:.8rem .95rem; overflow-x:auto;
  font-size:.82rem; white-space:pre-wrap; word-break:break-word; }
code { background:var(--soft); border-radius:5px; padding:.05rem .35rem;
  font-size:.85em; }
.badge { display:inline-flex; align-items:center; border-radius:999px;
  padding:.08rem .62rem; font-size:.74rem; font-weight:600;
  margin:0 .25rem .25rem 0; }
.badge.amber { background:var(--badge-amber-bg); color:var(--badge-amber-ink); }
.badge.blue { background:var(--badge-blue-bg); color:var(--badge-blue-ink); }
.badge.green { background:var(--badge-green-bg); color:var(--badge-green-ink); }
.badge.red { background:var(--badge-red-bg); color:var(--badge-red-ink); }
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
details.cmd > summary .name, details.cmd > summary .desc { min-width:0; overflow-wrap:anywhere; }
details.cmd[open] > summary { border-bottom:1px solid var(--line); }
details.cmd .inner { padding:.9rem 1.1rem 1.1rem; }
.group-head { display:flex; gap:.55rem; align-items:center;
  margin:1.6rem 0 .4rem; }
.group-head .ic { color:var(--accent); }
.group-head h2 { margin:0; }
.group-head .ref { color:var(--muted); font-size:.8rem; }
form.cmd { display:grid; grid-template-columns:minmax(200px,260px) minmax(0,1fr);
  gap:.4rem .8rem; align-items:center; }
form.cmd > .campaign-ownership, form.cmd > .notice { grid-column:1 / -1; }
form.cmd > label, form.cmd > .fieldwrap { min-width:0; overflow-wrap:anywhere; }
form.cmd > button { margin-top:.75rem; justify-self:start; }
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
@media (max-width:640px) {
  form.cmd { grid-template-columns:minmax(0,1fr); }
  form.cmd > label { margin-top:.6rem; }
  form.cmd > span:empty { display:none; }
  details.cmd > summary { flex-wrap:wrap; }
  details.cmd > summary .desc { flex-basis:100%; }
}
button { display:inline-flex; gap:.4rem; align-items:center;
  background:var(--accent); border:0; color:var(--accent-ink);
  font-weight:600; border-radius:9px; padding:.48rem 1rem; cursor:pointer;
  font-size:.9rem; }
button:hover:not(:disabled) { filter:brightness(1.08); }
button:disabled { opacity:.55; cursor:not-allowed; }
button.danger { background:#a4262f; color:#fff; }
button.small { padding:.28rem .6rem; font-size:.8rem; border-radius:7px; }
form.inline { display:inline; margin:0; }
.action-row, .review-actions { display:flex; flex-wrap:wrap; align-items:center;
  gap:.75rem; margin:1rem 0 0; }
.action-row > form { margin:0; }
p.action-row { margin-bottom:1rem; }
.action-row > button, .review-actions > button { max-width:100%; }
.checkrow { display:flex; align-items:flex-start; gap:.65rem;
  margin:.75rem 0; padding:.25rem 0; cursor:pointer; }
.checkrow > input[type=checkbox] { flex:0 0 auto; margin:.2rem 0 0; }
.checkrow > span { min-width:0; overflow-wrap:anywhere; }
.chips { display:flex; flex-wrap:wrap; gap:.4rem; margin:.2rem 0 .6rem; }
.chip { background:var(--card); color:var(--muted); border:1px solid var(--line);
  border-radius:999px; padding:.3rem .8rem; font-size:.82rem; font-weight:600;
  cursor:pointer; }
.chip:hover { color:var(--ink); }
.chip.on { background:var(--accent); color:var(--accent-ink);
  border-color:var(--accent); }
.page-tablist { display:none; }
.page-tabs.tabs-ready .page-tablist, .page-tablist.server-tablist { display:flex; align-items:center; gap:.25rem;
  overflow-x:auto; margin:.2rem 0 .9rem; padding:.28rem;
  background:var(--card); border:1px solid var(--line); border-radius:11px;
  box-shadow:var(--shadow); scrollbar-width:thin; }
.page-tab { flex:0 0 auto; border:1px solid transparent; border-radius:8px;
  padding:.46rem .85rem; background:transparent; color:var(--muted);
  font-size:.86rem; white-space:nowrap; }
.page-tab:hover { filter:none; color:var(--ink); background:var(--soft); }
.page-tab[aria-selected=true], .page-tab[aria-current=page] { color:var(--accent); background:var(--soft);
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
.notice:has(.notice-close) { padding-right:2.5rem; }
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
  color-scheme:inherit; }
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
.argv code { border:1px solid var(--line); padding:.12rem .45rem;
  min-width:0; max-width:100%; overflow-wrap:anywhere; }
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
.repeat-fields { display:flex; flex-direction:column; gap:.75rem; min-width:0; }
.repeat-row { display:flex; align-items:center; gap:.75rem; min-width:0; }
.repeat-row input, .repeat-row select, .repeat-row textarea { flex:1; min-width:0; }
.repeat-row button { flex:none; }
.repeat-fields > button { align-self:flex-start; }
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
.editor-actions { display:flex; flex-wrap:wrap; gap:.75rem; margin:1rem 0; }
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
.targetfilters input[type=search] { width:100%; min-width:0; padding:.55rem .7rem;
  font:inherit; font-size:.86rem; border:1px solid var(--line); border-radius:8px;
  background:var(--bg); color:var(--ink); }
.targetfilters input[type=search]:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
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
.workflow-actions { display:flex; align-items:center; flex-wrap:wrap; gap:.75rem;
  margin:0; }
.sample-size-control { display:grid; gap:.7rem; margin:0 0 1rem;
  padding:.85rem; background:var(--soft); border:1px solid var(--line);
  border-radius:10px; min-width:0; }
.sample-size-control[hidden] { display:none; }
.sample-range-field[hidden] { display:none; }
.sample-size-head { display:flex; align-items:flex-start; justify-content:space-between;
  gap:.75rem; flex-wrap:wrap; }
.sample-size-head h3, .sample-size-head p { margin:0; }
.sample-size-head p { margin-top:.25rem; }
.sample-size-grid { display:grid; grid-template-columns:minmax(0,2fr)
  repeat(2,minmax(10rem,1fr)); gap:.75rem; align-items:end; min-width:0; }
.sample-size-grid input[type=range] { width:100%; min-width:0;
  accent-color:var(--accent); }
.sample-size-grid select { width:100%; min-width:0; max-width:100%; }
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
.stats-campaign-actions { display:flex; flex-wrap:wrap; gap:.75rem; }
a.button { display:inline-flex; align-items:center; justify-content:center;
  padding:.42rem .8rem; border-radius:8px; text-decoration:none;
  font-size:.86rem; font-weight:600; }
a.button.ghost { color:var(--accent); border:1px solid var(--line);
  background:transparent; }
.stats-pagination { display:flex; align-items:center; justify-content:center;
  gap:.75rem; flex-wrap:wrap; margin:.7rem 0 1.2rem; }
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


_BUILDER_SCRIPT = _ui_template("""<script>(function(){
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
if(out){out.textContent=window.uraFormat([[js:ui.shown_items]],{count:count});}
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
var labels={none:'16-bit',fp8:[[js:ui.8_bit_fp8]],bitsandbytes:[[js:ui.4_bit_bitsandbytes]],
awq:[[js:ui.4_bit_awq]],gptq:[[js:ui.4_bit_gptq]]};
form.querySelectorAll(\".modelrow[data-compatible='unknown']\").forEach(function(row){
var badge=row.querySelector('.precision-badge');var select=row.querySelector('.modelquant select');
var label=badge&&badge.querySelector('.precision-label');
var tip=badge&&badge.querySelector('.tiptext');
if(!badge||!select||!label){return;}var value=select.value;
label.textContent=value==='auto'?[[js:ui.fit_unknown]]:
(labels[value]||value)+[[js:ui.selected_fit_unknown]];
if(tip){tip.textContent=value==='auto'?
[[js:ui.the_operator_must_choose_a_per_model_precision_before_a_live_run]]:
[[js:ui.operator_selected_precision_hardware_fit_remains_unknown]];}});
form.querySelectorAll(\".modelrow[data-profile-overrides='true']\").forEach(function(row){
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
var box=form.querySelector(\".fwbox[data-fw='\"+name+\"']\");
var visible=!!(box&&box.checked);panel.hidden=!visible;
panel.setAttribute('aria-hidden',visible?'false':'true');
if(box){box.setAttribute('aria-expanded',visible?'true':'false');}
if(visible){any=true;}});
 var group=document.getElementById('prepared-workflows');
 if(group){group.hidden=!any;group.setAttribute('aria-hidden',any?'false':'true');}}
function syncIdeatorPairLimit(){
 var status=document.getElementById('ideator-pair-status');
 var input=form.querySelector(\"[name='ideator_pair_limit']\");
 if(!status||!input){return;}
 var available=parseInt(status.getAttribute('data-available')||'',10);
 var raw=input.value.trim();
 if(!Number.isFinite(available)){
 status.textContent=[[js:ui.available_and_selected_pair_counts_appear_after_the_complete_mani]];return;}
 if(!/^[0-9]+$/.test(raw)){
 status.textContent=[[js:ui.enter_0_or_a_positive_ordered_prefix_pair_count]];return;}
 var requested=parseInt(raw,10);var selected=requested===0?available:Math.min(requested,available);
 status.textContent=selected+[[js:ui.selected_of]]+available+[[js:ui.verified_pairs_in_manifest_order]]+
 (requested>available?[[js:ui.requested_limit_exceeds_the_inventory]]:'')+'.';}
function syncHostedRetryPolicy(){
 var input=form.elements.namedItem('target_answer_retries');if(!input){return;}
 var hosted=checkedKind('api','data-model').length>0;
 if(hosted){input.value='0';input.readOnly=true;
 input.title=[[js:ui.paid_hosted_targets_use_no_answer_quality_retries]];}
 else{input.readOnly=false;input.removeAttribute('title');}}
var samplePanel=document.getElementById('sample-size-control');
var sampleRange=document.getElementById('sample-limit-range');
var sampleNumber=document.getElementById('sample-limit-number');
var sampleSeed=document.getElementById('sample-seed-input');
var samplePolicy=document.getElementById('sampling-policy-select');
function sampleArmCardinalities(){
 if(!samplePanel){return {};}try{
 var parsed=JSON.parse(samplePanel.getAttribute('data-arm-cardinalities')||'{}');
 return parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?parsed:{};
 }catch(_error){return {};}}
function syncSampleSizeControl(){
var arms=checked('.armbox','data-arm');
var mode=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
var drySynthetic=mode==='diagnostic_canary'&&checkedName('canary_dry');
var effectiveCount=drySynthetic?1:arms.length;var enabled=effectiveCount>0;
var counts=sampleArmCardinalities();var countKeys=Object.keys(counts).sort();
var selectedKeys=arms.slice().sort();var exact=!drySynthetic&&enabled&&
countKeys.length===selectedKeys.length&&countKeys.every(function(key,index){return key===selectedKeys[index];});
if(samplePanel){samplePanel.hidden=false;
samplePanel.setAttribute('aria-hidden','false');}
var prerequisite=document.getElementById('sample-arm-prerequisite');
if(prerequisite){prerequisite.hidden=enabled;}
if(sampleNumber){sampleNumber.disabled=!enabled;}if(sampleSeed){sampleSeed.disabled=!enabled;}
if(samplePolicy){samplePolicy.disabled=!enabled;}
var rangeField=sampleRange&&sampleRange.closest('.sample-range-field');
if(sampleRange){sampleRange.disabled=!exact;}if(rangeField){rangeField.hidden=!exact;}
var inventory=document.getElementById('sample-arm-inventory');
if(inventory&&countKeys.length){inventory.hidden=!exact;}
var count=document.getElementById('sample-arm-count');
if(count){count.textContent=drySynthetic?[[js:ui.synthetic_arm_selected_automatically]]:
window.uraFormat(arms.length===1?[[js:ui.one_selected_arm]]:[[js:ui.many_selected_arms]],{count:arms.length});}
if(!sampleRange||!sampleNumber){return;}
var raw=sampleNumber.value.trim();var valid=/^[0-9]+$/.test(raw);
if(mode==='diagnostic_canary'&&!raw){sampleNumber.value='1';raw='1';valid=true;}
var api=checkedKind('api','data-model');var judges=checked('.judgebox','data-judge');
var judgeModelValue=namedValue('judge_model','');
var hostedJudge=judges.indexOf('llm')>=0&&Array.prototype.some.call(
form.querySelectorAll(\".modelbox[data-kind='api']\"),
function(b){return (b.getAttribute('data-model')||'')===judgeModelValue;});
var localOnlyMeasured=mode==='measured'&&!api.length&&!hostedJudge;
var defaultValue=localOnlyMeasured?0:50;
var value=valid?parseInt(raw,10):defaultValue;
if(exact){var exactMax=countKeys.reduce(function(maximum,key){
return Math.max(maximum,parseInt(counts[key].total_clusters,10));},0);
sampleRange.max=String(exactMax);sampleRange.value=String(Math.min(value,exactMax));}
var status=document.getElementById('sample-limit-status');if(!status){return;}
if(!enabled){status.textContent=[[js:ui.select_one_or_more_arms_to_configure_sampling]];}
else if(!exact){status.textContent=[[js:ui.enter_a_non_negative_cluster_limit_now_the_exact_slider_range_and]];}
else{var effective=countKeys.reduce(function(total,key){var available=parseInt(counts[key].total_clusters,10);
return total+(value===0?available:Math.min(value,available));},0);
status.textContent=window.uraFormat([[js:ui.effective_selection_summary]],{clusters:effective,arms:effectiveCount});}}
if(sampleRange&&sampleNumber){
sampleRange.addEventListener('input',function(){sampleNumber.value=this.value;});}
function rememberPickerSelection(){
if(!pickerIsOpen()){return;}
if(pickerRole==='target'){
form.querySelectorAll('.modelbox').forEach(function(input){
input.setAttribute('data-target-selected',input.checked?'true':'false');});
return;}
var selected=form.querySelector('.modelbox:checked');
var judgeInput=document.getElementById('judge-model-input');
if(selected&&judgeInput){
judgeInput.value=selected.getAttribute('data-model')||'';
// Choosing a judge is an execution choice, not a dormant preference. Keep the
// submitted stage inventory coherent with the model the operator just chose.
var llmStage=form.querySelector(\".judgebox[data-judge='llm']\");
if(llmStage){llmStage.checked=true;}}}
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
targets.length+[[js:ui.selected]]+targets.join(', '):[[js:ui.no_target_models_selected]];}
var judgeInput=document.getElementById('judge-model-input');
var judgeOut=document.getElementById('judge-model-summary');
if(judgeOut){judgeOut.textContent=judgeInput&&judgeInput.value?
judgeInput.value:[[js:ui.no_llm_judge_model_selected]];}}
function setPickerRole(role){
pickerRole=role==='judge'?'judge':'target';
if(!picker){return;}picker.setAttribute('data-role',pickerRole);
var title=document.getElementById('model-picker-title');
if(title){title.textContent=pickerRole==='judge'?[[js:ui.choose_llm_judge_model]]:[[js:ui.choose_target_models]];}
var note=document.getElementById('model-picker-role-note');
if(note){note.textContent=pickerRole==='judge'?
[[js:ui.choose_exactly_one_judge_it_must_differ_from_every_target_model]]:
[[js:ui.choose_one_or_more_hosted_targets_and_at_most_one_local_target]];}
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
var panel=document.querySelector(\".picker-model-panel[data-picker-panel='\"+pickerKind+\"']\");
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
'button:not([disabled]),input:not([disabled]):not([hidden]),select:not([disabled]),[tabindex]:not([tabindex=\"-1\"])'),
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
function checkedName(name){var field=form.querySelector(\"input[name='\"+name+\"']\");
return !!(field&&field.checked);}
function selectionLabel(values){if(!values.length){return [[js:ui.none_selected]];}
var shown=values.slice(0,3).join(', ');return shown+(values.length>3?
window.uraFormat([[js:ui.additional_items]],{count:values.length-3}):'');}
function pairState(pathName,digestName){var path=namedValue(pathName,'');
var digest=namedValue(digestName,'');if(path&&digest){return [[js:ui.receipt_set]];}
if(path||digest){return [[js:ui.receipt_incomplete]];}return [[js:ui.not_set]];}
function setBuildSummary(id,value){var out=document.getElementById(id);
if(out){out.textContent=value;}}
function refresh(){rememberPickerSelection();updateUnknownPrecisionBadges();
applyScope();applyPreparedFields();
syncIdeatorPairLimit();
syncHostedRetryPolicy();
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
form.querySelectorAll(\".modelbox[data-kind='api']\"),
function(b){return (b.getAttribute('data-model')||'')===judgeModelValue;});
// a blank limit composes --limit 0 (the complete release) only where
// validation admits it: a measured lane with no hosted target and no hosted
// LLM judge; hosted paid lanes, probes, and canaries must type a value
// (a positive bound or an explicit 0 for a separately approved full cohort)
var localOnlyMeasured=mode==='measured'&&!api.length&&!hostedJudge;
if(lim){parts.push('--limit '+lim);}
else if(localOnlyMeasured){parts.push('--limit 0');}
var samplingPolicy=namedValue('sampling_policy','');
if(samplingPolicy&&(arms.length||drySynthetic)){
parts.push('--sampling-policy '+samplingPolicy);}
var grp=namedValue('group','');if(grp){parts.push('--group '+grp);}
if(checkedName('exclude_tool_conditioned')){parts.push('--exclude-tool-conditioned');}
if(checkedName('reset_open_circuits')&&mode==='measured'){parts.push('--reset-open-circuits');}
if(checkedName('verify_model_sha256')){parts.push('--verify-model-sha256');}
var stale=namedValue('lock_stale_seconds','');if(stale){parts.push('--lock-stale-seconds '+stale);}
var mods=checked('.modbox','data-mod');var targets=api.concat(loc);
form.querySelector('input[name=modality_scope]').value=mods.join(',');
setBuildSummary('build-summary-composition',mode+[[js:ui.modalities]]+
selectionLabel(mods)+[[js:ui.targets]]+selectionLabel(drySynthetic?[]:targets)+
[[js:ui.corpora]]+selectionLabel(drySynthetic?[[[js:ui.synth_automatic]]]:arms)+
[[js:ui.attacks]]+selectionLabel(fw));
var judgeModel=namedValue('judge_model',[[js:ui.not_selected]]);
var approx=checkedName('approximate_common_metrics')?[[js:ui.enabled_state]]:[[js:ui.off_state]];
var defense=namedValue('defense','none');var defenseGuard=namedValue('defense_guard','rules');
var scoringGuard=namedValue('guardrail_model','')?[[js:ui.configured_state]]:[[js:ui.not_set]];
var defenseGuardrail=namedValue('defense_guardrail_model','')?[[js:ui.configured_state]]:[[js:ui.not_set]];
var localJudge=jg.indexOf('llm')>=0&&Array.prototype.some.call(
form.querySelectorAll(\".modelbox[data-kind='local']\"),
function(b){return (b.getAttribute('data-model')||'')===judgeModelValue;});
var responseConditioned=fw.some(function(name){return name.toLowerCase()==='crescendo';});
var deferredLocalJudge=loc.length&&!drySynthetic&&!responseConditioned&&
(jg.indexOf('guardrail')>=0||localJudge)&&
(mode==='measured'||mode==='diagnostic_canary'||mode==='attestation_probe');
var judgeSchedule=deferredLocalJudge?[[js:ui.post_factum_after_target_gpu_release]]:[[js:ui.inline_schedule]];
setBuildSummary('build-summary-evaluation',[[js:ui.judges]]+selectionLabel(jg)+
 [[js:ui.schedule]]+judgeSchedule+[[js:ui.llm_model]]+judgeModel+
 [[js:ui.approximate_metrics]]+approx+[[js:ui.defense]]+
defense+' / '+defenseGuard+[[js:ui.scoring_guardrail]]+scoringGuard+
[[js:ui.defense_guardrail]]+defenseGuardrail);
var completeAtt=0;var incompleteAtt=0;
form.querySelectorAll('.attrow').forEach(function(row){var fields=row.querySelectorAll('input');
var path=(fields[0]&&fields[0].value.trim())||'';
var digest=(fields[1]&&fields[1].value.trim())||'';
if(path&&digest){completeAtt++;}else if(path||digest){incompleteAtt++;}});
setBuildSummary('build-summary-admission',[[js:ui.project_receipt]]+
pairState('project_revision','project_revision_sha')+[[js:ui.source_receipt]]+
pairState('source_conformance','source_conformance_sha')+[[js:ui.attestations]]+
completeAtt+[[js:ui.complete_count]]+(incompleteAtt?(', '+incompleteAtt+[[js:ui.incomplete_count]]):'')+
[[js:ui.scope]]+namedValue('scope',[[js:ui.not_set]])+[[js:ui.max_age]]+namedValue('max_age',[[js:ui.not_set]]));
setBuildSummary('build-summary-trajectory',[[js:ui.per_arm_limit]]+namedValue('limit',
localOnlyMeasured?[[js:ui.0_complete_release]]:[[js:ui.not_set]])+
 [[js:ui.sampling_policy]]+namedValue('sampling_policy',[[js:ui.legacy_seeded_default]])+
 [[js:ui.sample_seed]]+namedValue('sample_seed',[[js:ui.not_set]])+[[js:ui.seeds]]+
 namedValue('seeds',[[js:ui.not_set]])+[[js:ui.queries]]+namedValue('max_queries',[[js:ui.not_set]])+
 [[js:ui.turns]]+namedValue('max_turns',[[js:ui.not_set]])+[[js:ui.answer_retries]]+
 namedValue('target_answer_retries','1')+[[js:ui.hosted_http_error_retries]]+
 (api.length?[[js:ui.3_max_4_attempts]]:[[js:ui.not_applicable_short]])+[[js:ui.group]]+namedValue('group',[[js:ui.cli_default]])+
 [[js:ui.ideator_pair_limit]]+namedValue('ideator_pair_limit',[[js:ui.all_pairs]])+
[[js:ui.exclude_tool_conditioned]]+(checkedName('exclude_tool_conditioned')?[[js:ui.on_state]]:[[js:ui.off_state]])+
[[js:ui.reset_open_circuits]]+(checkedName('reset_open_circuits')?[[js:ui.on_state]]:[[js:ui.off_state]])+
[[js:ui.lock_stale_seconds]]+namedValue('lock_stale_seconds',[[js:ui.cli_default]]));
setBuildSummary('build-summary-budget',[[js:ui.target_judge_http]]+
(checkedName('automatic_caps')?[[js:ui.calculated_during_review]]:
namedValue('cap_target',[[js:ui.not_set]])+' / '+namedValue('cap_judge',[[js:ui.not_set]])+
 ' / '+namedValue('cap_http',[[js:ui.not_set]]))+[[js:ui.local_process_wall_time_cap]]+
 namedValue('local_budget_hours',[[js:ui.not_set]])+[[js:ui.h_independent_call_start_window]]+
namedValue('deadline',[[js:ui.not_set]])+[[js:ui.s_not_a_completion_timeout]]);
var localPrecisions=[];
form.querySelectorAll(\".modelbox[data-kind='local'][data-target-selected='true']\")
.forEach(function(input){var row=input.closest('.modelrow');var precision=row&&
row.querySelector('.modelquant select');if(precision){localPrecisions.push(
(input.getAttribute('data-model')||'local')+': '+precision.value);}});
setBuildSummary('build-summary-local',[[js:ui.dtype]]+namedValue('dtype','auto')+
[[js:ui.model_file_checks]]+(checkedName('verify_model_sha256')?[[js:ui.full_sha_slow]]:[[js:ui.metadata_no_weight_hashing]])+
[[js:ui.default_quantization]]+namedValue('quantization','auto')+
(localPrecisions.length?[[js:ui.selected_model]]+localPrecisions.join(', '):''));
setBuildSummary('build-summary-output',namedValue('setup_mode','')==='automatic'?
[[js:ui.assigned_automatically_on_review]]:namedValue('out',[[js:ui.not_set]]));
var prev=document.getElementById('buildpreview');
if(prev){prev.textContent=parts.join(' ');}}
form.addEventListener('change',refresh);
form.addEventListener('input',refresh);
var projectRefresh=document.getElementById('use-current-project-receipt');
if(projectRefresh){projectRefresh.addEventListener('click',function(){
form.querySelector('[name=project_revision]').value=this.getAttribute('data-path');
form.querySelector('[name=project_revision_sha]').value=this.getAttribute('data-sha');
document.getElementById('project-receipt-refresh-status').textContent=
[[js:ui.current_project_receipt_selected_save_campaign_then_compose_revie]]+
[[js:ui.repeat_preparation_for_the_new_software_revision_old_jobs_and_res]];
refresh();});}
// The tool-conditioned exclusion is an offline-smoke-only diagnostic.  It is
// enabled and defaults ON only for a standalone dry run; evidence-bearing
// preflight, probe, canary, and measured routes must retain whole clusters.
function applyExclusionDefault(){var box=form.querySelector(\"input[name='exclude_tool_conditioned']\");
if(!box){return;}var m=(form.querySelector('input[name=mode]:checked')||{}).value||'measured';
box.disabled=m!=='dry_run';box.checked=m==='dry_run';refresh();}
form.querySelectorAll(\"input[name='mode'],input[name='canary_dry']\").forEach(function(el){
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
div.innerHTML=\"<input class='wide' type='text' name='att_path\"+n+
\"' placeholder='runs/thesis/attest/receipt.live-attestation.json'>\"+
\"<input class='wide' type='text' name='att_sha\"+n+
(\"' placeholder='\"+[[jshtml:ui.exact_64_hex_sha256]]+\"'>\");
rows.appendChild(div);refresh();});}
form.addEventListener('submit',function(){
form.querySelector(\"input[name=corpora]\").value=checked('.armbox','data-arm').join(',');
form.querySelector(\"input[name=api]\").value=checkedKind('api','data-model').join(',');
form.querySelector(\"input[name=local]\").value=checkedKind('local','data-model').join(',');
form.querySelector(\"input[name=attackers]\").value=checked('.fwbox','data-fw').join(',');
form.querySelector(\"input[name=judges]\").value=checked('.judgebox','data-judge').join(',');});
refresh();
})();</script>""")


_NAV_LINKS = (
    ("/", "grid", _ui_text("ui.dashboard")),
    ("/build", "flask", _ui_text("ui.build")),
    ("/campaigns", "book", _ui_text("ui.campaigns")),
    ("/commands", "terminal", _ui_text("ui.tools")),
    ("/jobs?view=work", "pulse", _ui_text("ui.jobs")),
    ("/stats", "chart", _ui_text("ui.stats")),
    ("/config", "sliders", _ui_text("ui.config")),
    ("/artifacts", "folder", _ui_text("ui.artifacts")),
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
        f"aria-label='{html.escape(label)}'>" + "".join(buttons) + "</div>"
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
\"[data-page-tabs]\")===root;});}
function hashPanel(root){var raw=window.location.hash.slice(1);if(!raw){return null;}
var id;try{id=decodeURIComponent(raw);}catch(error){id=raw;}
var target=document.getElementById(id);if(!target||!root.contains(target)){return null;}
var panel=target.matches(\"[data-page-panel]\")?target:
target.closest(\"[data-page-panel]\");
return panel&&panel.closest(\"[data-page-tabs]\")===root?panel:null;}
function init(root){var tabs=owned(root,\"[data-page-tab]\");
var panels=owned(root,\"[data-page-panel]\");if(!tabs.length||!panels.length){return;}
var key=\"ura-page-tab:\"+(root.getAttribute(\"data-tab-key\")||window.location.pathname);
function valid(id){return tabs.some(function(tab){return tab.getAttribute(
\"data-page-tab\")===id;});}
function remember(id){try{window.sessionStorage.setItem(key,id);}catch(error){}}
function activate(id,options){options=options||{};if(!valid(id)){return false;}
tabs.forEach(function(tab){var on=tab.getAttribute(\"data-page-tab\")===id;
tab.setAttribute(\"aria-selected\",on?\"true\":\"false\");tab.tabIndex=on?0:-1;
if(on&&options.focus){tab.focus();}});
panels.forEach(function(panel){panel.hidden=panel.getAttribute(
\"data-page-panel\")!==id;});remember(id);
if(options.hash){var next=window.location.pathname+window.location.search+\"#\"+
encodeURIComponent(id);window.history.replaceState(window.history.state,\"\",next);}
return true;}
root.classList.add(\"tabs-ready\");
tabs.forEach(function(tab,index){tab.addEventListener(\"click\",function(){
activate(tab.getAttribute(\"data-page-tab\"),{hash:true});});
tab.addEventListener(\"keydown\",function(event){var next=index;
if(event.key==="ArrowRight"){next=(index+1)%tabs.length;}
else if(event.key==="ArrowLeft"){next=(index+tabs.length-1)%tabs.length;}
else if(event.key==="Home"){next=0;}else if(event.key==="End"){next=tabs.length-1;}
else{return;}event.preventDefault();activate(tabs[next].getAttribute(
\"data-page-tab\"),{focus:true,hash:true});});});
var initialPanel=hashPanel(root);var initial=initialPanel?
initialPanel.getAttribute(\"data-page-panel\"):\"\";
if(!initial&&root.getAttribute(\"data-force-default\")!==\"true\"){
try{initial=window.sessionStorage.getItem(key)||\"\";}catch(error){initial=\"\";}}
if(!valid(initial)){initial=root.getAttribute(\"data-default-tab\")||\"\";}
if(!valid(initial)){initial=tabs[0].getAttribute(\"data-page-tab\");}
activate(initial);root._activatePageTab=activate;}
var roots=Array.prototype.slice.call(document.querySelectorAll(\"[data-page-tabs]\"));
roots.forEach(init);
function revealHash(){
roots.forEach(function(root){var panel=hashPanel(root);if(panel&&root._activatePageTab){
root._activatePageTab(panel.getAttribute(\"data-page-panel\"));}});
requestAnimationFrame(function(){var id;try{id=decodeURIComponent(location.hash.slice(1));}catch(error){return;}
var target=id&&document.getElementById(id);if(!target||!target.getClientRects().length){return;}
var nav=document.querySelector('body > nav'),space=(nav?nav.getBoundingClientRect().height:0)+16;
var focus=target.matches('input,select,textarea,button,a[href]')?target:target.querySelector('h2,h3,h4')||target;
if(!focus.matches('input,select,textarea,button,a[href],[tabindex]')){focus.setAttribute('tabindex','-1');}
focus.focus({preventScroll:true});window.scrollTo({top:Math.max(0,scrollY+target.getBoundingClientRect().top-space),behavior:'instant'});
});}
window.addEventListener('hashchange',revealHash);
window.addEventListener('load',revealHash,{once:true});
document.addEventListener('click',function(event){
if(event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey){return;}
var link=event.target.closest&&event.target.closest('a[href]');if(!link||link.hasAttribute('download')||
(link.target&&link.target!=='_self')){return;}
var url=new URL(link.href,location.href);
if(url.origin===location.origin&&url.pathname===location.pathname&&url.search===location.search&&url.hash&&url.hash===location.hash){revealHash();}
});
})();</script>"""

_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
    "<path fill='#0a5fb4' d='M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z'/>"
    "<path fill='none' stroke='#ffffff' stroke-width='2' "
    "stroke-linecap='round' stroke-linejoin='round' "
    "d='M8.5 12.5l2.5 2.5 4.5-5'/></svg>"
).encode("utf-8")


_THEMES = (
    ("slate", _ui_text("ui.slate")),
    ("parchment", _ui_text("ui.parchment")),
    ("midnight", _ui_text("ui.midnight")),
    ("ash", _ui_text("ui.ash")),
    ("harbor", _ui_text("ui.harbor")),
)
_THEME_PICKER = (
    _ui_template(
        "<label class='theme-control' for='theme-picker'>[[text:ui.theme]] <select id='theme-picker' aria-label='[[attr:ui.colour_theme]]' title='[[attr:ui.harbor_follows_the_system_light_dark_preference]]'>"
    )
    + "".join(
        "<option value='"
        + key
        + "'"
        + (" selected" if key == "harbor" else "")
        + ">"
        + label
        + "</option>"
        for key, label in _THEMES
    )
    + "</select></label>"
)
_THEME_INIT = """<script>(function(){
var allowed=THEME_IDS,value='harbor';
try{var saved=localStorage.getItem('ura-theme');if(allowed.indexOf(saved)!==-1)value=saved;}catch(error){}
document.documentElement.setAttribute('data-theme',value);
})();</script>""".replace("THEME_IDS", json.dumps([key for key, _ in _THEMES]))
_LANGUAGE_PICKER = _ui_template(
    "<label class='language-control' for='language-picker'>[[text:language.label]] "
    "<span class='language-choice'>"
    "<svg data-language-flag='gb' aria-hidden='true' viewBox='0 0 60 30' xmlns='http://www.w3.org/2000/svg'>"
    "<path fill='#012169' d='M0 0h60v30H0z'/>"
    "<path stroke='#fff' stroke-width='6' d='m0 0 60 30M60 0 0 30'/>"
    "<path stroke='#c8102e' stroke-width='2' d='m0 0 60 30M60 0 0 30'/>"
    "<path stroke='#fff' stroke-width='10' d='M30 0v30M0 15h60'/>"
    "<path stroke='#c8102e' stroke-width='6' d='M30 0v30M0 15h60'/></svg>"
    "<select id='language-picker' aria-label='[[attr:language.label]]' "
    "title='[[attr:language.english_only]]'>"
    "<option value='en' selected lang='en'>[[text:language.english_short]]</option>"
    "</select></span></label>"
)
_THEME_SCRIPT = """<script>(function(){
var language=document.getElementById('language-picker');
if(language){language.value='en';language.addEventListener('change',function(){
language.value='en';document.documentElement.lang='en';});}
var picker=document.getElementById('theme-picker');if(!picker)return;
picker.value=document.documentElement.getAttribute('data-theme')||'harbor';
picker.addEventListener('change',function(){
document.documentElement.setAttribute('data-theme',picker.value);
try{localStorage.setItem('ura-theme',picker.value);}catch(error){}
});
})();</script>"""


_STYLE += _CAMPAIGN_GUIDE_STYLE


def _page(title: str, body: str, active: str = "") -> bytes:
    from .display_labels import script as display_script

    links = "".join(
        f"<a href='{href}'"
        + (" class='active'" if label == active else "")
        + f">{_icon(icon, size=16)}{label}</a>"
        for href, icon, label in _NAV_LINKS
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)}</title>"
        "<link rel='icon' type='image/svg+xml' href='/static/favicon.svg'>"
        + _THEME_INIT
        + "<link rel='stylesheet' href='/static/style.css'></head><body>"
        + display_script()
        + _BUSY_OVERLAY
        + (
            "<nav><span class='brand'>"
            + f"{_icon('logo', size=21)}"
            + _ui_template("[[text:ui.ura_rig_console]]</span>")
            + f"{links}"
        )
        + "<div class='display-preferences'>"
        + _THEME_PICKER
        + _LANGUAGE_PICKER
        + "</div>"
        + (
            "</nav><main>"
            + f"{body}"
            + _ui_template(
                "<footer class='note'>[[text:ui.the_cli_and_filesystem_artifacts_remain_authoritative_this_consol]]</footer></main>"
            )
        )
        + _PAGE_TABS_SCRIPT
        + _THEME_SCRIPT
        + "</body></html>"
    ).encode("utf-8")


# Every backend wait uses one shared guard. Form data-busy only customizes text.
_BUSY_SCRIPT = _ui_template("""(function(){
var overlay=document.getElementById('busy-overlay'),message=document.getElementById('busy-msg');
var pending=new Set(),blocked=[],lastFocus=null,navigationEnd=null;
function busy(){return pending.size>0;}
function restore(){
overlay.classList.remove('on');overlay.setAttribute('aria-hidden','true');
document.documentElement.removeAttribute('aria-busy');
blocked.forEach(function(item){item.node.inert=item.inert;});blocked=[];
if(lastFocus&&lastFocus.isConnected&&lastFocus.focus){lastFocus.focus();}lastFocus=null;
}
function begin(text){var token={};
if(!busy()){
lastFocus=document.activeElement;
blocked=Array.prototype.map.call(document.querySelectorAll('body > nav,body > main,body > .review-theme-bar'),
function(node){var previous=Boolean(node.inert);node.inert=true;return {node:node,inert:previous};});
overlay.classList.add('on');overlay.setAttribute('aria-hidden','false');
document.documentElement.setAttribute('aria-busy','true');overlay.focus();}
pending.add(token);message.textContent=text||[[js:ui.loading]];
return function(){if(!pending.delete(token)){return;}if(!busy()){restore();}};}
function reset(){pending.clear();navigationEnd=null;restore();}
function navigate(text){if(!navigationEnd){navigationEnd=begin(text);}}
function cancelled(event){setTimeout(function(){if(event.defaultPrevented&&navigationEnd){
var end=navigationEnd;navigationEnd=null;end();}},0);}
function block(event){event.preventDefault();event.stopImmediatePropagation();}
window.uraBusy={begin:begin,isBusy:busy,reset:reset,reload:function(){
if(busy()){return false;}navigate([[js:ui.refreshing]]);window.location.reload();return true;}};
document.addEventListener('click',function(event){
if(busy()){block(event);return;}
if(event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey){return;}
var link=event.target.closest&&event.target.closest('a[href]');
if(!link||link.hasAttribute('download')||(link.target&&link.target!=='_self')||
link.matches('[data-stats-job],[data-stats-report]')){return;}
var raw=link.getAttribute('href');if(!raw||raw.charAt(0)==='#'){return;}
var url=new URL(link.href,window.location.href);
if(url.origin!==window.location.origin||!/^https?:$/.test(url.protocol)){return;}
if(url.hash&&url.pathname===window.location.pathname&&url.search===window.location.search){return;}
navigate(link.getAttribute('data-busy')||[[js:ui.loading_page]]);cancelled(event);
},true);
document.addEventListener('submit',function(event){
if(busy()){block(event);return;}if(event.defaultPrevented){return;}
var form=event.target,target=(event.submitter&&event.submitter.formTarget)||form.target;
if((target&&target!=='_self')||form.method==='dialog'){return;}
navigate(form.getAttribute('data-busy')||[[js:ui.submitting]]);cancelled(event);
},true);
['keydown','change','input'].forEach(function(name){document.addEventListener(name,function(event){
if(busy()){block(event);}},true);});
window.addEventListener('beforeunload',function(event){navigate([[js:ui.loading_page]]);cancelled(event);});
window.addEventListener('pageshow',function(event){if(event.persisted){reset();}});
})();""")

_BUSY_OVERLAY = (
    _ui_template(
        "<div id='busy-overlay' role='status' aria-live='polite' aria-hidden='true' tabindex='-1'><div class='box'><div class='spin'></div><div class='msg' id='busy-msg'>[[text:ui.working]]</div><div class='sub'>[[text:ui.waiting_for_the_server_please_wait_before_trying_again]]</div></div></div><script>"
    )
    + _BUSY_SCRIPT
    + "</script>"
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
    links = [_ui_template("<a href='/artifacts'>[[text:ui.runs]]</a>")]
    so_far: list[str] = []
    for part in parts:
        so_far.append(part)
        target = quote("/".join(so_far))
        links.append(f"<a href='/artifacts?path={target}'>{html.escape(part)}</a>")
    return "<p class='crumbs'>" + "<span class='sep'>/</span>".join(links) + "</p>"
