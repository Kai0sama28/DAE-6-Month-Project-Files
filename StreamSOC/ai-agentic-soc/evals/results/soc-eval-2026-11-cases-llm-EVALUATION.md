# Evaluation results — soc-eval-2026-11

- Generated: 2026-11-04 17:33:22Z
- Dataset: `soc-eval-2026-11` (50 investigations)
- Mode: live LLM (`nvidia/nemotron-3-ultra-550b-a55b:free`)
- Scope: one investigation per case (highest-severity alert = trigger)

## Headline

| Metric | Result | Rate |
|---|---:|---:|
| Investigation completed | 45 / 50 | 90.0% |
| Correct ATT&CK (any expected technique) | 43 / 50 | 86.0% |
| Correct ATT&CK (exact set) | 13 / 50 | 26.0% |
| Correct recommendation (exact action) | 17 / 50 | 34.0% |
| Correct recommendation (lenient) | 40 / 50 | 80.0% |

## By label

| Label | Cases | Completed | ATT&CK correct | Recommendation correct | Exact ATT&CK |
|---|---:|---:|---:|---:|---:|
| benign | 10 | 5 (50.0%) | 3 (30.0%) | 3 (30.0%) | 3 |
| brute_force | 10 | 10 (100.0%) | 10 (100.0%) | 6 (60.0%) | 7 |
| credential_stuffing | 10 | 10 (100.0%) | 10 (100.0%) | 7 (70.0%) | 0 |
| phishing | 10 | 10 (100.0%) | 10 (100.0%) | 1 (10.0%) | 3 |
| ransomware_precursor | 10 | 10 (100.0%) | 10 (100.0%) | 0 (0.0%) | 0 |

## Recommendation confusion matrix

| Expected \ Predicted | contain | escalate | investigate | monitor | unknown |
|---|---:|---:|---:|---:|---:|
| contain | 1 | 12 | 5 | 0 | 0 |
| escalate | 0 | 13 | 9 | 0 | 0 |
| monitor | 0 | 0 | 2 | 3 | 5 |

## Investigations needing review (35)

| Case | Label | Completed | ATT&CK | Recommendation | Note |
|---|---|---|---|---|---|
| EVAL-BF-003 | brute_force | yes | yes | no | expected contain; got escalate |
| EVAL-BF-006 | brute_force | yes | yes | no | expected contain; got escalate |
| EVAL-BF-008 | brute_force | yes | yes | no | expected escalate; got investigate |
| EVAL-BF-010 | brute_force | yes | yes | no | expected contain; got escalate |
| EVAL-BN-001 | benign | yes | no | yes | expected -; got T1003.008, T1078, T1548.003 |
| EVAL-BN-003 | benign | yes | no | yes | expected -; got T1021.004 |
| EVAL-BN-004 | benign | yes | yes | no | expected monitor; got investigate |
| EVAL-BN-005 | benign | yes | yes | no | expected monitor; got investigate |
| EVAL-BN-006 | benign | no | no | no | no narrative; expected -; got -; expected monitor; got unknown; LLM failed: OpenRouter 429: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests  |
| EVAL-BN-007 | benign | no | no | no | no narrative; expected -; got -; expected monitor; got unknown; LLM failed: OpenRouter 429: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests  |
| EVAL-BN-008 | benign | no | no | no | no narrative; expected -; got -; expected monitor; got unknown; LLM failed: OpenRouter 429: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests  |
| EVAL-BN-009 | benign | no | no | no | no narrative; expected -; got -; expected monitor; got unknown; LLM failed: OpenRouter 429: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests  |
| EVAL-BN-010 | benign | no | no | no | no narrative; expected -; got -; expected monitor; got unknown; LLM failed: OpenRouter 429: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests  |
| EVAL-CS-005 | credential_stuffing | yes | yes | no | expected contain; got investigate |
| EVAL-CS-006 | credential_stuffing | yes | yes | no | expected escalate; got investigate |
| EVAL-CS-009 | credential_stuffing | yes | yes | no | expected contain; got investigate |
| EVAL-PH-001 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-002 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-003 | phishing | yes | yes | no | expected contain; got investigate |
| EVAL-PH-004 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-005 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-006 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-007 | phishing | yes | yes | no | expected contain; got escalate |
| EVAL-PH-008 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-PH-009 | phishing | yes | yes | no | expected escalate; got investigate |
| EVAL-RP-001 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-002 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-003 | ransomware_precursor | yes | yes | no | expected contain; got investigate |
| EVAL-RP-004 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-005 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-006 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-007 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-008 | ransomware_precursor | yes | yes | no | expected contain; got escalate |
| EVAL-RP-009 | ransomware_precursor | yes | yes | no | expected contain; got investigate |
| EVAL-RP-010 | ransomware_precursor | yes | yes | no | expected contain; got escalate |

## Per-case results

| Case | Label | Trigger rule | Expected action | Predicted action | ATT&CK match | Time (s) |
|---|---|---|---|---|---|---:|
| EVAL-BF-001 | brute_force | 5763 | escalate | escalate | yes | 72.3 |
| EVAL-BF-002 | brute_force | 5763 | escalate | escalate | yes | 92.4 |
| EVAL-BF-003 | brute_force | 40112 | contain | escalate | yes | 55.0 |
| EVAL-BF-004 | brute_force | 100002 | escalate | escalate | yes | 54.5 |
| EVAL-BF-005 | brute_force | 5763 | escalate | escalate | yes | 95.3 |
| EVAL-BF-006 | brute_force | 40112 | contain | escalate | yes | 76.5 |
| EVAL-BF-007 | brute_force | 100002 | escalate | escalate | yes | 80.8 |
| EVAL-BF-008 | brute_force | 5763 | escalate | investigate | yes | 86.5 |
| EVAL-BF-009 | brute_force | 100002 | escalate | escalate | yes | 47.4 |
| EVAL-BF-010 | brute_force | 40112 | contain | escalate | yes | 82.4 |
| EVAL-BN-001 | benign | 550 | monitor | monitor | no | 50.5 |
| EVAL-BN-002 | benign | 61110 | monitor | monitor | yes | 48.7 |
| EVAL-BN-003 | benign | 5502 | monitor | monitor | no | 34.8 |
| EVAL-BN-004 | benign | 19005 | monitor | investigate | yes | 31.2 |
| EVAL-BN-005 | benign | 23504 | monitor | investigate | yes | 45.0 |
| EVAL-BN-006 | benign | 61110 | monitor | unknown | no | 0.2 |
| EVAL-BN-007 | benign | 61138 | monitor | unknown | no | 0.2 |
| EVAL-BN-008 | benign | 550 | monitor | unknown | no | 0.3 |
| EVAL-BN-009 | benign | 5501 | monitor | unknown | no | 0.3 |
| EVAL-BN-010 | benign | 5760 | monitor | unknown | no | 0.3 |
| EVAL-CS-001 | credential_stuffing | 100031 | escalate | escalate | yes | 114.6 |
| EVAL-CS-002 | credential_stuffing | 100031 | escalate | escalate | yes | 68.9 |
| EVAL-CS-003 | credential_stuffing | 100031 | escalate | escalate | yes | 329.4 |
| EVAL-CS-004 | credential_stuffing | 100031 | escalate | escalate | yes | 98.3 |
| EVAL-CS-005 | credential_stuffing | 40112 | contain | investigate | yes | 97.2 |
| EVAL-CS-006 | credential_stuffing | 100031 | escalate | investigate | yes | 56.9 |
| EVAL-CS-007 | credential_stuffing | 100031 | escalate | escalate | yes | 90.8 |
| EVAL-CS-008 | credential_stuffing | 100031 | escalate | escalate | yes | 53.8 |
| EVAL-CS-009 | credential_stuffing | 40112 | contain | investigate | yes | 183.8 |
| EVAL-CS-010 | credential_stuffing | 100031 | escalate | escalate | yes | 99.9 |
| EVAL-PH-001 | phishing | 100040 | escalate | investigate | yes | 121.5 |
| EVAL-PH-002 | phishing | 100040 | escalate | investigate | yes | 70.2 |
| EVAL-PH-003 | phishing | 100040 | contain | investigate | yes | 128.7 |
| EVAL-PH-004 | phishing | 100040 | escalate | investigate | yes | 89.4 |
| EVAL-PH-005 | phishing | 100040 | escalate | investigate | yes | 85.7 |
| EVAL-PH-006 | phishing | 100040 | escalate | investigate | yes | 72.0 |
| EVAL-PH-007 | phishing | 100040 | contain | escalate | yes | 84.3 |
| EVAL-PH-008 | phishing | 100040 | escalate | investigate | yes | 132.0 |
| EVAL-PH-009 | phishing | 100040 | escalate | investigate | yes | 68.7 |
| EVAL-PH-010 | phishing | 100040 | contain | contain | yes | 91.3 |
| EVAL-RP-001 | ransomware_precursor | 100046 | contain | escalate | yes | 121.7 |
| EVAL-RP-002 | ransomware_precursor | 100046 | contain | escalate | yes | 72.2 |
| EVAL-RP-003 | ransomware_precursor | 100045 | contain | investigate | yes | 69.5 |
| EVAL-RP-004 | ransomware_precursor | 100046 | contain | escalate | yes | 47.8 |
| EVAL-RP-005 | ransomware_precursor | 100045 | contain | escalate | yes | 58.7 |
| EVAL-RP-006 | ransomware_precursor | 100046 | contain | escalate | yes | 78.2 |
| EVAL-RP-007 | ransomware_precursor | 100046 | contain | escalate | yes | 69.3 |
| EVAL-RP-008 | ransomware_precursor | 100046 | contain | escalate | yes | 87.1 |
| EVAL-RP-009 | ransomware_precursor | 100045 | contain | investigate | yes | 68.6 |
| EVAL-RP-010 | ransomware_precursor | 100046 | contain | escalate | yes | 59.3 |

## Run notes

- 5 investigation(s) produced no narrative. Their ATT&CK/recommendation fields are marked incorrect and excluded from the reasoning-accuracy claim; deterministic correlation facts are still present in the saved report.
- 5 of those were blocked by the OpenRouter free-tier daily limit (`429 free-models-per-day`), not by an engine failure: EVAL-BN-006, EVAL-BN-007, EVAL-BN-008, EVAL-BN-009, EVAL-BN-010. Re-run `python -m evals.run_eval --resume` after the quota resets.

## Method and scoring

Every case was replayed through `agent.graph.build_graph` with an in-memory indexer containing only that incident bundle. The agent ran its normal supervisor, SIEM correlation, LLM narrative and report stages; identity/EDR HTTP mocks and desktop notifications were disabled so the run is reproducible offline.

- **Investigation completed** = the LLM narrative was produced and a report was written. A deterministic-only fallback report counts as not completed because no ATT&CK/recommendation reasoning is present.
- **Correct ATT&CK** = the narrative's `mitre_mapping` contains at least one ground-truth technique. For benign cases it means the engine claimed no technique. *Exact* additionally requires set equality.
- **Correct recommendation** = the action inferred from the narrative's recommended/containment actions equals the case's expected action (`monitor`/`investigate`/`escalate`/`contain`). *Lenient* accepts an adjacent safe action.
- **Processing time** = wall clock around the agent graph invocation, including correlation and LLM latency. See `PROCESSING_TIMES.md`.
