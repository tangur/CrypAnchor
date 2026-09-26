"""Create N independent runs to anchor on Bitcoin testnet (paper, Table 5).

Each runs/run_XX/ gets logs.jsonl, anchors.jsonl, anchor_receipt.json and
electrum.txt (paste into Electrum > Pay to many).
Usage: python scripts/make_runs.py --n 8
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypanchor import chain  # noqa: E402
from crypanchor.cli import write_receipt  # noqa: E402
from crypanchor.sim import run_simulation  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=8)
ap.add_argument("--steps", type=int, default=100)
ap.add_argument("--commit-every", type=int, default=10)
ap.add_argument("--network", default="testnet4")
a = ap.parse_args()
for i in range(a.n):
    d = os.path.join("runs", f"run_{i:02d}")
    os.makedirs(d, exist_ok=True)
    r = run_simulation(2, a.steps, a.commit_every, seed=100 + i,
                       logs_path=os.path.join(d, "logs.jsonl"), anchors_path=os.path.join(d, "anchors.jsonl"))
    write_receipt(os.path.join(d, "anchor_receipt.json"), r["run_root"], r["anchors"], a.network)
    with open(os.path.join(d, "electrum.txt"), "w") as f:
        f.write(chain.electrum_paytomany(r["run_root"]))
    print(f"{d}: run root {r['run_root'].hex()}")
print("\nFor each run: paste electrum.txt into Electrum (Tools/Pay to many), broadcast,")
print("then immediately run: python scripts/onchain_stats.py watch <TXID> --run runs/run_XX")
