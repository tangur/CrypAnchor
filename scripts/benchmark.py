"""Timing benchmark (paper, Table 4 and Figure 3).

Grid: agents x steps x commit_every. For each configuration one simulation is
generated (not timed); then each operation is timed `--reps` times with
time.perf_counter_ns after one warm-up run:

  hash    canonical serialization + SHA-256 of every record (leaf hashes)
  commit  building all epoch Merkle trees and the run root from leaf hashes
  verify  full verification of all records against anchors and run root
  proof   verification of a single-event inclusion proof (event -> run root)

Writes results/benchmark.csv, results/hardware.json, results/benchmark_loglog.png.
Usage: python scripts/benchmark.py [--reps 30] [--quick]
"""
import argparse
import csv
import json
import os
import platform
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypanchor.core import (MerkleTree, record_leaf, sort_key, verify, prove_event,  # noqa: E402
                             verify_event, proof_bytes, compute_run_root)
from crypanchor.sim import run_simulation  # noqa: E402


def hardware():
    cpu = platform.processor() or ""
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
    except Exception:
        pass
    if not cpu and platform.system() == "Darwin":
        try:
            import subprocess
            cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
        except Exception:
            pass
    ram = None
    try:
        ram = round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1)
    except Exception:
        pass
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "ram_gb": ram,
            "os": f"{platform.system()} {platform.release()} {platform.machine()}",
            "python": f"{platform.python_implementation()} {platform.python_version()}",
            "timer": "time.perf_counter_ns"}


def timeit(fn, reps):
    fn()  # warm-up
    out = []
    for _ in range(reps):
        t0 = time.perf_counter_ns(); fn(); out.append((time.perf_counter_ns() - t0) / 1e6)
    q = statistics.quantiles(out, n=4) if len(out) > 1 else [out[0]] * 3
    return statistics.median(out), q[0], q[2]


def commit_all(leaves_by_epoch, anchors):
    for lv in leaves_by_epoch:
        MerkleTree(lv).root
    compute_run_root(anchors)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--quick", action="store_true", help="small grid for a smoke test")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    agents = [2, 10] if a.quick else [2, 10, 50]
    steps = [100, 1000] if a.quick else [100, 1000, 10000]
    commits = [10, 100]
    hw = hardware(); hw["reps"] = a.reps
    json.dump(hw, open(os.path.join(a.out, "hardware.json"), "w"), indent=2)
    print(json.dumps(hw))
    rows = []
    for n in agents:
        for T in steps:
            for ce in commits:
                run = run_simulation(n, T, ce, seed=0)
                recs, anchors, root = run["records"], run["anchors"], run["run_root"]
                ordered = sorted(recs, key=sort_key)
                ends = [x.epoch_end_t for x in anchors]
                leaves_by_epoch, idx = [], 0
                for e in ends:
                    lv = []
                    while idx < len(ordered) and ordered[idx]["t"] <= e:
                        lv.append(record_leaf(ordered[idx])); idx += 1
                    leaves_by_epoch.append(lv)
                rec = random.Random(1).choice(recs)
                proof = prove_event(recs, anchors, rec)
                assert verify_event(proof, root)
                h = timeit(lambda: [record_leaf(r) for r in recs], a.reps)
                c = timeit(lambda: commit_all(leaves_by_epoch, anchors), a.reps)
                v = timeit(lambda: verify(recs, anchors, root), a.reps)
                p = timeit(lambda: verify_event(proof, root), a.reps)
                row = {"agents": n, "steps": T, "commit_every": ce, "events": len(recs),
                       "epochs": len(anchors), "proof_bytes": proof_bytes(proof)}
                for name, (med, q1, q3) in (("hash", h), ("commit", c), ("verify", v), ("proof_verify", p)):
                    row[f"{name}_ms_median"] = round(med, 4)
                    row[f"{name}_ms_q1"] = round(q1, 4)
                    row[f"{name}_ms_q3"] = round(q3, 4)
                rows.append(row)
                print(f"agents={n:3d} steps={T:6d} ce={ce:4d} events={len(recs):7d} "
                      f"hash={h[0]:9.2f}ms commit={c[0]:8.2f}ms verify={v[0]:9.2f}ms "
                      f"proof={p[0]:.3f}ms ({row['proof_bytes']} B)", flush=True)
    with open(os.path.join(a.out, "benchmark.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 4.2))
        for ce, style in ((10, "-"), (100, "--")):
            sub = sorted((r for r in rows if r["commit_every"] == ce), key=lambda r: r["events"])
            x = [r["events"] for r in sub]
            for key, label in (("verify", "full verification"), ("hash", "leaf hashing"),
                               ("commit", "Merkle commitment"), ("proof_verify", "single-event proof")):
                ax.plot(x, [r[f"{key}_ms_median"] for r in sub], style, marker="o", ms=3,
                        label=f"{label} (commit_every={ce})")
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("logged decision events"); ax.set_ylabel("time (ms, median)")
        ax.grid(True, which="both", alpha=0.3); ax.legend(fontsize=6.5)
        fig.tight_layout(); fig.savefig(os.path.join(a.out, "benchmark_loglog.png"), dpi=200)
    except ImportError:
        print("matplotlib not installed; skipping plot")


if __name__ == "__main__":
    main()
