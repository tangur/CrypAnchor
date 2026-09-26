"""Minimal end-to-end demo: simulate, commit, verify, tamper, verify again."""
import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypanchor import verify  # noqa: E402
from crypanchor.chain import electrum_paytomany  # noqa: E402
from crypanchor.sim import run_simulation  # noqa: E402

r = run_simulation(n_agents=2, steps=100, commit_every=10, seed=7)
print(f"{len(r['records'])} decisions, {len(r['anchors'])} epochs, run root {r['run_root'].hex()}")
print("honest run            :", verify(r["records"], r["anchors"], r["run_root"]).reason)

tampered = copy.deepcopy(r["records"])
tampered[42]["intent"] = "WAIT" if tampered[42]["intent"] != "WAIT" else "UP"
print("one intent changed    :", verify(tampered, r["anchors"], r["run_root"]).reason)

print("\nElectrum 'Pay to many' text for anchoring this run:\n" + electrum_paytomany(r["run_root"]))
