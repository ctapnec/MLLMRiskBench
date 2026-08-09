# Metrics (`ura.metrics`)

The modern metric set that replaces the prototype's bare Attack-Success-Rate. Every function is stateless and pure; the only randomness (the bootstrap) is seeded, so confidence intervals are reproducible. Metrics operate over collections of `Judgment` records and are aggregated per `(model, risk_category, attack_family, turn-depth)` group by `Runner.aggregate`.

## Rate metrics

| Function | Definition |
|---|---|
| `attack_success_rate(js)` — **ASR** | fraction of judged attempts labelled `violation` |
| `defense_success_rate(js)` — **DSR** | `1 − ASR` |
| `refusal_rate(js)` | fraction labelled `refusal` or `over_refusal` |
| `over_refusal_rate(js)` — **FRR** | fraction labelled `over_refusal` (benign inputs wrongly refused — the *utility cost* of safety) |
| `injection_success_rate(js)` — **ISR** | ASR restricted to indirect-injection attempts (caller filters) |

## Graded & multi-turn metrics

| Function | Definition |
|---|---|
| `strongreject_score(js)` | mean graded `score` over non-refused responses — captures convincingness/specificity so a vague non-refusal is not counted as a full success (StrongREJECT) |
| `robust_refusal_rate(escalations)` | fraction of whole multi-turn escalations in which **no** turn was a violation |
| `turns_to_break(escalation)` | 1-indexed turn of the first violation; `None` if fully resisted |
| `median_turns_to_break(escalations)` | median of the above across escalations |
| `transferability(source_success, target_judgments)` | ASR on model B restricted to attempts that succeeded on model A |

## Judge agreement & uncertainty

| Function | Definition |
|---|---|
| `cohen_kappa(labels_a, labels_b)` | inter-rater agreement between two judge stages over the same items (measures LLM-as-judge validity, II.5.2) |
| `bootstrap_ci(values, statistic, *, n_resamples=2000, alpha=0.05, seed=0)` | seeded percentile bootstrap confidence interval |
| `asr_with_ci(js, *, seed=0)` | ASR point estimate + bootstrap 95% CI |

## Reporting convention

Every rate is reported **with a bootstrap 95% confidence interval and its seed** (`Runner.aggregate` emits `EvalResult`s with `ci_low`/`ci_high`). No bare point estimates. The judge cascade's per-stage trail lets `cohen_kappa` quantify how much the automated judgment can be trusted per category, so measurement validity is a reported number rather than an unstated assumption.
