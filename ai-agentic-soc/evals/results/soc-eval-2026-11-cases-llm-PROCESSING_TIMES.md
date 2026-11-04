# Processing times — soc-eval-2026-11

- Generated: 2026-11-04 17:33:22Z
- Investigations: 50
- Mode: live LLM (`nvidia/nemotron-3-ultra-550b-a55b:free`)

## Summary

| Statistic | Seconds |
|---|---:|
| Total wall clock | 3823.4 |
| Mean | 85.0 |
| Median | 76.5 |
| p95 | 132.0 |
| Min | 31.2 |
| Max | 329.4 |

_Statistics cover the 45 completed investigation(s) across 50 runs. Failed/no-narrative attempts are listed in the per-investigation table but excluded from the mean/median/p95._

## By label

| Label | N (completed) | Mean (s) | Median (s) | p95 (s) | Min (s) | Max (s) |
|---|---:|---:|---:|---:|---:|---:|
| benign | 5 | 42.1 | 45.0 | 50.5 | 31.2 | 50.5 |
| brute_force | 10 | 74.3 | 80.8 | 95.3 | 47.4 | 95.3 |
| credential_stuffing | 10 | 119.4 | 98.3 | 329.4 | 53.8 | 329.4 |
| phishing | 10 | 94.4 | 89.4 | 132.0 | 68.7 | 132.0 |
| ransomware_precursor | 10 | 73.2 | 69.5 | 121.7 | 47.8 | 121.7 |

## Per-investigation times

| Case | Label | Wall clock (s) | LLM attempts (s) | Correlated events |
|---|---|---:|---:|---:|
| EVAL-CS-003 | credential_stuffing | 329.4 | 329.3 | 7 |
| EVAL-CS-009 | credential_stuffing | 183.8 | 183.7 | 8 |
| EVAL-PH-008 | phishing | 132.0 | 132.0 | 4 |
| EVAL-PH-003 | phishing | 128.7 | 128.7 | 6 |
| EVAL-RP-001 | ransomware_precursor | 121.7 | 121.7 | 4 |
| EVAL-PH-001 | phishing | 121.5 | 121.5 | 4 |
| EVAL-CS-001 | credential_stuffing | 114.6 | 114.6 | 7 |
| EVAL-CS-010 | credential_stuffing | 99.9 | 99.9 | 7 |
| EVAL-CS-004 | credential_stuffing | 98.3 | 98.3 | 7 |
| EVAL-CS-005 | credential_stuffing | 97.2 | 97.2 | 8 |
| EVAL-BF-005 | brute_force | 95.3 | 95.3 | 6 |
| EVAL-BF-002 | brute_force | 92.4 | 92.4 | 6 |
| EVAL-PH-010 | phishing | 91.3 | 91.3 | 6 |
| EVAL-CS-007 | credential_stuffing | 90.8 | 90.8 | 7 |
| EVAL-PH-004 | phishing | 89.4 | 89.4 | 4 |
| EVAL-RP-008 | ransomware_precursor | 87.1 | 87.1 | 4 |
| EVAL-BF-008 | brute_force | 86.5 | 86.5 | 6 |
| EVAL-PH-005 | phishing | 85.7 | 85.7 | 4 |
| EVAL-PH-007 | phishing | 84.3 | 84.3 | 6 |
| EVAL-BF-010 | brute_force | 82.4 | 82.3 | 7 |
| EVAL-BF-007 | brute_force | 80.8 | 80.8 | 6 |
| EVAL-RP-006 | ransomware_precursor | 78.2 | 78.1 | 4 |
| EVAL-BF-006 | brute_force | 76.5 | 76.5 | 7 |
| EVAL-BF-001 | brute_force | 72.3 | 72.2 | 6 |
| EVAL-RP-002 | ransomware_precursor | 72.2 | 72.2 | 4 |
| EVAL-PH-006 | phishing | 72.0 | 72.0 | 4 |
| EVAL-PH-002 | phishing | 70.2 | 70.2 | 4 |
| EVAL-RP-003 | ransomware_precursor | 69.5 | 69.5 | 3 |
| EVAL-RP-007 | ransomware_precursor | 69.3 | 69.3 | 4 |
| EVAL-CS-002 | credential_stuffing | 68.9 | 68.9 | 7 |
| EVAL-PH-009 | phishing | 68.7 | 68.7 | 4 |
| EVAL-RP-009 | ransomware_precursor | 68.6 | 68.6 | 3 |
| EVAL-RP-010 | ransomware_precursor | 59.3 | 59.3 | 4 |
| EVAL-RP-005 | ransomware_precursor | 58.7 | 58.7 | 4 |
| EVAL-CS-006 | credential_stuffing | 56.9 | 56.9 | 7 |
| EVAL-BF-003 | brute_force | 55.0 | 55.0 | 7 |
| EVAL-BF-004 | brute_force | 54.5 | 54.4 | 6 |
| EVAL-CS-008 | credential_stuffing | 53.8 | 53.8 | 7 |
| EVAL-BN-001 | benign | 50.5 | 50.5 | 3 |
| EVAL-BN-002 | benign | 48.7 | 48.7 | 3 |
| EVAL-RP-004 | ransomware_precursor | 47.8 | 47.8 | 4 |
| EVAL-BF-009 | brute_force | 47.4 | 47.4 | 6 |
| EVAL-BN-005 | benign | 45.0 | 45.0 | 3 |
| EVAL-BN-003 | benign | 34.8 | 34.8 | 3 |
| EVAL-BN-004 | benign | 31.2 | 31.2 | 3 |
| EVAL-BN-009 | benign | 0.3 | 0.3 | 2 |
| EVAL-BN-010 | benign | 0.3 | 0.3 | 3 |
| EVAL-BN-008 | benign | 0.3 | 0.3 | 2 |
| EVAL-BN-006 | benign | 0.2 | 0.3 | 3 |
| EVAL-BN-007 | benign | 0.2 | 0.2 | 2 |

## Notes

Wall clock is measured around `graph.invoke` and includes the LLM request, retries/fallbacks and deterministic correlation. `LLM attempts` is the sum of the individual model attempt durations recorded by the agent; when a model fails and falls back, wall clock is larger than a single successful attempt.
