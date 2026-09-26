| Attack | M1 local, logs only | M2 local, logs + anchors | M3 on-chain |
|---|---|---|---|
| Modify one field | 100.0 | 0.0 | 100.0 |
| Delete one record | 100.0 | 0.0 | 100.0 |
| Insert a record (inside an epoch) | 100.0 | 0.0 | 100.0 |
| Insert after last anchor | 100.0 | 0.0 | 100.0 |
| Reorder two decisions | 100.0 | 0.0 | 100.0 |
| Truncate the log (1-10 records) | 100.0 | 0.0 | 100.0 |
| Modify 2-5 records | 100.0 | 0.0 | 100.0 |
| Replay a record from another run | 100.0 | 0.0 | 100.0 |
| Change a time step | 100.0 | 0.0 | 100.0 |
| Change agent_id (impersonation) | 100.0 | 0.0 | 100.0 |
| Delete an epoch | 100.0 | 0.0 | 100.0 |
| Substitute the whole history | n/a | 0.0 | 100.0 |
| Pre-anchor omission (negative control) | 0.0 | 0.0 | 0.0 |
| Fabrication by compromised logger (negative control) | 0.0 | 0.0 | 0.0 |
| False positives on honest runs | 0.0 | 0.0 | 0.0 |

Detection rate in %. 1000 trials per attack (10 seeds x 100); 2 agents, 50 steps, commit_every=10. Runtime 40 s.
