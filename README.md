# CrypAnchor

Tamper-evident decision logging for autonomous multi-agent systems.

CrypAnchor records the decisions of autonomous agents off-chain, aggregates
them into Merkle trees, and anchors a single 32-byte **run root** per run on
Bitcoin (OP_RETURN). Anyone who knows the anchoring transaction can later
check that a disclosed decision log is exactly the one that was committed, or
verify a single decision with a compact inclusion proof, without trusting
whoever stores the logs.

This repository accompanies the paper *Verifiable Accountability for
Autonomous AI Agents via Cryptographic Decision Anchoring* (Frontiers,
revised version).

## What is guaranteed, and what is not

**Detected:** any change made *after anchoring* to committed records or to
the epoch anchors (modification, deletion, insertion, truncation, reordering,
replay from another run, changed time steps or agent identifiers, deleted
epochs, substituted history), provided the verifier obtains the transaction
id from a source the log holder does not control (for example, the paper).

**Not detected, by design:** records manipulated or omitted *before* they are
committed (compromised agent or logger). The attack experiment reports these
as negative controls.

## Requirements

Python 3.9 or newer; the library uses only the standard library.
`matplotlib` is needed only for the benchmark plot.

## Quick start

```bash
python -m unittest discover tests          # unit tests
python examples/gridworld_demo.py          # simulate, commit, verify, tamper
python -m crypanchor demo --out demo_run   # logs, anchors, receipt, Electrum text
python -m crypanchor verify --logs demo_run/logs.jsonl --anchors demo_run/anchors.jsonl --run-root <RUN_ROOT>
python -m crypanchor prove  --logs demo_run/logs.jsonl --anchors demo_run/anchors.jsonl --agent A --seq 10
```

Verification against the blockchain (needs internet):

```bash
python -m crypanchor verify --logs L --anchors A --txid <TXID> --network testnet4
```

## Design

| Element | Construction |
|---|---|
| Record | `run_id, seq, t, agent_id, state_summary, intent, context`; canonical JSON (sorted keys, no whitespace, UTF-8) |
| Leaf | `SHA-256(0x00 ‖ record)` |
| Inner node | `SHA-256(0x01 ‖ left ‖ right)` on raw 32-byte digests; an odd node is promoted unchanged |
| Epoch | records of `commit_every` time steps, ordered by `(t, agent_id, seq)` |
| Epoch anchor | `epoch_index, epoch_end_t, leaf_count, epoch_root, run_id` |
| Run root | Merkle root over all epoch anchors (one per run) |
| On-chain payload | `"CRA1" ‖ run_root` (36 bytes) in an OP_RETURN output |
| Single-event proof | event → epoch root → run root (two Merkle paths, about 0.5 kB) |

The agents in `crypanchor/sim.py` follow a simple stochastic rule-based
policy; the logging layer treats the policy as a black box.

## Reproducing the paper's experiments

```bash
python scripts/attacks.py                 # Table 2: 14 attacks x 1,000 trials (~1 min)
python scripts/benchmark.py               # Table 3 and Figure 3 (30 repetitions; 30-60 min)
python scripts/make_runs.py --n 8         # runs to anchor on testnet4 (Table 4)
python scripts/onchain_stats.py watch <TXID> --run runs/run_00   # right after each broadcast
python scripts/onchain_stats.py summary
```

Results are written to `results/`, including `hardware.json`. The committed
benchmark numbers were produced on a 1-vCPU cloud VM; re-running the benchmark
overwrites them with results from your machine. The transaction ids of the
eight testnet4 anchors are in `results/onchain_anchors.csv`, and the matching
logs and run roots in `runs/`.

### Anchoring with Electrum (testnet4)

1. Start Electrum in testnet4 mode and fund the wallet from a testnet4 faucet.
2. Open `runs/run_XX/electrum.txt`, replace `YOUR_TESTNET_ADDRESS` with an
   address from your own wallet, and paste both lines into *Tools → Pay to many*.
3. Broadcast, copy the transaction id, and immediately run
   `python scripts/onchain_stats.py watch <TXID> --run runs/run_XX`.

## Repository layout

```
crypanchor/   merkle.py  core.py  chain.py  sim.py  cli.py
scripts/      attacks.py  benchmark.py  make_runs.py  onchain_stats.py
tests/        test_core.py
examples/     gridworld_demo.py
results/      experiment outputs
```

## License

MIT, see `LICENSE`.
