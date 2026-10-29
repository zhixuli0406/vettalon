# Vettalon code explanations

These pages explain Vettalon evidence, proof gaps, coverage and verification codes. The same pages are embedded in the CLI and work offline. Page text stays in English; `--lang` selects the fixed CLI messages.

```sh
vettalon explain static_only
vettalon explain --list
vettalon --lang zh-TW explain verify_uncertain
```

Unknown codes exit with status 2 and show nearby code names. This reference describes recorded evidence and scope; a code alone does not establish that a repository is secure.

SARIF result properties include `vettalon.explain_uri`, an object mapping each carried code to its public explanation URL. Rule properties contain the union of those code-to-URL mappings across their results.

| Code | Meaning |
| --- | --- |
| [adversarial_review](adversarial_review.md) | A note from the second model that tried to disprove the finding |
| [ai_analysis](ai_analysis.md) | The finder model's explanation of why the code is vulnerable |
| [budget_cannot_fund_reserves](budget_cannot_fund_reserves.md) | The budget was too small to reserve room for verification |
| [candidate](candidate.md) | The module review reported at least one finding |
| [candidate_cap](candidate_cap.md) | The module was skipped because the run already had too many candidates |
| [carried_from_prior](carried_from_prior.md) | An earlier suppressed or refuted verdict was reused on an unchanged file |
| [comment_sensitivity](comment_sensitivity.md) | The refuter changed its answer when code comments were visible |
| [complete](complete.md) | The run did everything it was asked to do |
| [covered](covered.md) | The module was reviewed, found nothing, and listed what it checked |
| [critic_budget_exhausted](critic_budget_exhausted.md) | The time cap for the refuter step ran out |
| [deferred](deferred.md) | The module was ranked but never sent to a model |
| [diff_scope](diff_scope.md) | The module has no changed files, so a diff scan skipped it |
| [dual_finder_merge](dual_finder_merge.md) | Two finder models reported the same root cause and were merged |
| [engine_unavailable](engine_unavailable.md) | A model or tool the scan needed could not be used |
| [fix_check](fix_check.md) | The result of testing the finding's suggested fix |
| [fix_check_skipped](fix_check_skipped.md) | A step of the fix check could not run |
| [fix_context_v1](fix_context_v1.md) | The exact files and settings a fix check or reproduction used |
| [incomplete](incomplete.md) | Part of the requested work did not finish |
| [injection_uncrosschecked](injection_uncrosschecked.md) | Text aimed at the AI reviewer was found and only one model family reviewed it |
| [interrupted](interrupted.md) | The run was recorded as interrupted |
| [llm_failed](llm_failed.md) | The model call for this module failed |
| [maintainer_confirmed](maintainer_confirmed.md) | A person confirmed this finding |
| [max_modules](max_modules.md) | The module was ranked below the module limit |
| [model_refused](model_refused.md) | A model declined to review part of the code |
| [no_control](no_control.md) | No control run shows the effect is specific to the bug |
| [no_fresh_rerun](no_fresh_rerun.md) | The effect was not reproduced in a fresh container |
| [no_maintainer_confirmation](no_maintainer_confirmation.md) | No person has confirmed this finding |
| [no_poc](no_poc.md) | No PoC was run for this finding |
| [no_refuter](no_refuter.md) | No second model has given a verdict on this finding |
| [operator_decision](operator_decision.md) | A person's decision and the reason they gave |
| [operator_review](operator_review.md) | A human reviewer recorded a decision on this finding |
| [out_of_scope](out_of_scope.md) | The module was left out of the diff scan on purpose |
| [outside_diff_scope](outside_diff_scope.md) | A scanner finding sits in a file the diff did not change |
| [parse_failed](parse_failed.md) | The model's reply for this module was not valid output |
| [partial_by_design](partial_by_design.md) | The scan finished, but only on the part you asked for |
| [partially_reviewed](partially_reviewed.md) | The model saw only part of this module |
| [plausible](plausible.md) | The refuter tried to disprove the finding and could not |
| [poc_differential](poc_differential.md) | A sandbox test showed a real effect, and a control did not |
| [poc_effect_no_control](poc_effect_no_control.md) | A sandbox test showed an effect, but the proof is incomplete |
| [poc_generation_failed](poc_generation_failed.md) | The model did not produce a usable proof-of-concept |
| [poc_not_demonstrable](poc_not_demonstrable.md) | The model could not write a runnable demonstration |
| [poc_not_harness_judged](poc_not_harness_judged.md) | A PoC ran, but the harness did not confirm an effect |
| [poc_oracle](poc_oracle.md) | The harness's own verdict on a sandbox test |
| [poc_skipped](poc_skipped.md) | A PoC was attempted, but nothing ran in the sandbox |
| [poc_transcript](poc_transcript.md) | A proof-of-concept script really ran in the sandbox |
| [precheck](precheck.md) | Local checks found a problem with the finding's claim |
| [prescreen_cut](prescreen_cut.md) | A cheap model ranked this module too low to audit |
| [prior_changed_source](prior_changed_source.md) | An earlier scan judged this issue, but the file has changed since |
| [prior_confirmed_same_source](prior_confirmed_same_source.md) | An earlier report confirmed this issue, and it is being checked again |
| [prior_gap](prior_gap.md) | An earlier scan reviewed this module poorly, so it moved up the queue |
| [prior_not_rediscovered](prior_not_rediscovered.md) | An open issue from the last scan was not found again and is re-checked |
| [prompt_byte_budget](prompt_byte_budget.md) | This file did not fit in the module's prompt |
| [prompt_byte_budget_utf8_boundary](prompt_byte_budget_utf8_boundary.md) | Too little prompt space was left for even one character of this file |
| [prosecutor](prosecutor.md) | A third call tried to break the refuter's reason for closing a finding |
| [quick_profile_not_rechecked](quick_profile_not_rechecked.md) | A quick scan could not tell whether an old finding is still there |
| [reachability_unknown](reachability_unknown.md) | Nothing has shown that an attacker can actually reach this code |
| [read_failed_or_outside_repository](read_failed_or_outside_repository.md) | A file could not be read safely |
| [reasoning](reasoning.md) | The prefix of the finder model's explanation |
| [refute_basis](refute_basis.md) | The refuter's stated reason for closing a finding |
| [refuted](refuted.md) | A refuter judged the claim false |
| [refuter_consistent](refuter_consistent.md) | Three or more refuter runs all found the claim plausible |
| [refuter_impact_missing](refuter_impact_missing.md) | The refuter said "plausible" but gave no usable impact rating |
| [refuter_inconsistent](refuter_inconsistent.md) | The refuter runs could not agree on this finding |
| [refuter_run](refuter_run.md) | One of several refuter runs on this finding |
| [refuter_score](refuter_score.md) | The refuter's own probability that the claim is real |
| [refuter_survived](refuter_survived.md) | A refuter could not disprove the claim |
| [retrieval](retrieval.md) | Missing definitions were looked up and the refuter was asked again |
| [reviewed_no_checks](reviewed_no_checks.md) | The model reviewed the module, reported nothing, and listed no checks |
| [scope_not_fully_reviewed](scope_not_fully_reviewed.md) | Some of the code you asked about was not fully reviewed |
| [scope_note](scope_note.md) | A note from Vettalon about where a finding sits in the scan scope |
| [severity_capped](severity_capped.md) | The finder's severity was lowered to match its own impact rating |
| [severity_disagreement](severity_disagreement.md) | The refuter rated the impact differently from the finder |
| [shallow_missing_class_checks](shallow_missing_class_checks.md) | The finder skipped some attack classes it was asked to check |
| [shallow_no_checks](shallow_no_checks.md) | The module was reviewed, but the model listed no checks |
| [static_hit](static_hit.md) | A scanner reported this finding |
| [static_only](static_only.md) | Nothing but code reading supports this finding |
| [tier_disagreement](tier_disagreement.md) | The finder and refuter disagree on how hard the attack is |
| [time_budget](time_budget.md) | The module ran out of time |
| [time_budget_exhausted](time_budget_exhausted.md) | The scan hit its time limit with work left over |
| [units_failed](units_failed.md) | Some pieces of the scan produced no usable result |
| [unreadable](unreadable.md) | The module had no text the model could be sent |
| [unresolved](unresolved.md) | The refuter could not decide, so the finding stays open |
| [validation_budget_exhausted](validation_budget_exhausted.md) | The run reached its limit on AI candidates |
| [verifier_corrected](verifier_corrected.md) | The refuter fixed a wrong line number in the finding |
| [verifier_reflector](verifier_reflector.md) | The refuter's reply was malformed, so it was asked again once |
| [verify_error](verify_error.md) | The refuter gave no usable answer for this finding |
| [verify_uncertain](verify_uncertain.md) | The refuter could not settle this finding |
