"""Adversarial evaluation (paper, Table 3).

For every trial a fresh honest run is simulated (2 agents, 50 steps,
commit_every=10 -> 100 records, 5 epochs). An attack is applied and the
result is verified under three settings:

  M1  local check; attacker edits the log file only (anchors file intact)
  M2  local check; attacker edits the log file AND rewrites the anchors file
      so that it is consistent with the tampered log (strong attacker)
  M3  on-chain check against the anchored run root; same strong attacker as M2

Two negative controls (pre-anchor omission, fabrication by a compromised
logger) manipulate records BEFORE they are committed. They are undetectable by
design and are reported to delimit the guarantee (paper, Section 3.7).

Usage: python scripts/attacks.py [--seeds 10] [--trials 100]
"""
import argparse
import copy
import csv
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypanchor.core import EpochAnchor, MerkleTree, record_leaf, sort_key, verify, compute_run_root  # noqa: E402
from crypanchor.sim import run_simulation, ACTIONS  # noqa: E402

N_AGENTS, STEPS, COMMIT_EVERY = 2, 50, 10


def build_anchors(records, ends, run_id):
    """What a strong attacker does: recompute a consistent anchors file."""
    ordered = sorted(records, key=sort_key)
    anchors, idx, prev = [], 0, -1
    ends = sorted(set(ends) | ({max(r["t"] for r in records)} if records else set()))
    for e in ends:
        epoch = []
        while idx < len(ordered) and ordered[idx]["t"] <= e:
            epoch.append(ordered[idx]); idx += 1
        if epoch:
            anchors.append(EpochAnchor(len(anchors), e, len(epoch),
                                       MerkleTree([record_leaf(r) for r in epoch]).root.hex(), run_id))
    return anchors


def repair(records, run_id, ends):
    """Make tampered records locally consistent: fix run_id, renumber seq."""
    recs = copy.deepcopy(records)
    for r in recs:
        r["run_id"] = run_id
    by_agent = {}
    for r in recs:
        by_agent.setdefault(r["agent_id"], []).append(r)
    for rs in by_agent.values():
        rs.sort(key=lambda r: (r["t"], r["seq"]))
        for k, r in enumerate(rs):
            r["seq"] = k
    return recs, build_anchors(recs, ends, run_id)


def other_intent(rng, x):
    return rng.choice([a for a in ACTIONS if a != x])


# --- attacks: (rng, honest run) -> (records, anchors_override or None) ---------

def a_modify(rng, run):
    recs = copy.deepcopy(run["records"]); r = rng.choice(recs)
    r["intent"] = other_intent(rng, r["intent"]); return recs, None

def a_delete(rng, run):
    recs = copy.deepcopy(run["records"]); recs.pop(rng.randrange(len(recs))); return recs, None

def a_insert(rng, run):
    recs = copy.deepcopy(run["records"]); src = rng.choice(recs)
    new = dict(copy.deepcopy(src), intent=other_intent(rng, src["intent"]),
               seq=max(r["seq"] for r in recs if r["agent_id"] == src["agent_id"]) + 1)
    recs.insert(rng.randrange(len(recs) + 1), new); return recs, None

def a_insert_after(rng, run):
    recs = copy.deepcopy(run["records"]); src = rng.choice(recs)
    last = run["anchors"][-1].epoch_end_t
    new = dict(copy.deepcopy(src), t=last + rng.randint(1, 5),
               seq=max(r["seq"] for r in recs if r["agent_id"] == src["agent_id"]) + 1)
    recs.append(new); return recs, None

def a_reorder(rng, run):
    recs = copy.deepcopy(run["records"])
    agent = rng.choice(sorted({r["agent_id"] for r in recs}))
    mine = [r for r in recs if r["agent_id"] == agent]
    x, y = rng.sample([r for r in mine if r["intent"] != mine[0]["intent"]] + [mine[0]], 2) \
        if len({r["intent"] for r in mine}) > 1 else rng.sample(mine, 2)
    # claim that two decisions happened in the opposite order: swap their
    # content but keep time steps (merely shuffling file lines is neutral by design)
    for k in ("state_summary", "intent", "context"):
        x[k], y[k] = y[k], x[k]
    return recs, None

def a_truncate(rng, run):
    recs = copy.deepcopy(sorted(run["records"], key=sort_key))
    return recs[:-rng.randint(1, 10)], None

def a_multi(rng, run):
    recs = copy.deepcopy(run["records"])
    for r in rng.sample(recs, rng.randint(2, 5)):
        r["intent"] = other_intent(rng, r["intent"])
    return recs, None

def a_replay(rng, run):
    recs = copy.deepcopy(run["records"])
    other = run_simulation(N_AGENTS, STEPS, COMMIT_EVERY, seed=rng.randrange(10**9))["records"]
    i = rng.randrange(len(recs)); recs[i] = copy.deepcopy(other[i]); return recs, None

def a_change_t(rng, run):
    recs = copy.deepcopy(run["records"]); r = rng.choice(recs)
    r["t"] = max(0, min(run["anchors"][-1].epoch_end_t, r["t"] + rng.choice([-1, 1])))
    if r["t"] == run["records"][recs.index(r)]["t"]:
        r["t"] = r["t"] - 1 if r["t"] > 0 else r["t"] + 1
    return recs, None

def a_swap_agent(rng, run):
    recs = copy.deepcopy(run["records"]); r = rng.choice(recs)
    r["agent_id"] = rng.choice(sorted({x["agent_id"] for x in recs} - {r["agent_id"]})); return recs, None

def a_delete_epoch(rng, run):
    e = rng.randrange(len(run["anchors"]))
    hi = run["anchors"][e].epoch_end_t; lo = run["anchors"][e - 1].epoch_end_t if e else -1
    recs = [copy.deepcopy(r) for r in run["records"] if not (lo < r["t"] <= hi)]
    return recs, None

def a_substitute(rng, run):
    """Replace the whole history (logs + anchors) with a fabricated run."""
    fake = run_simulation(N_AGENTS, STEPS, COMMIT_EVERY, seed=rng.randrange(10**9),
                          run_id=run["anchors"][0].run_id)
    return copy.deepcopy(fake["records"]), fake["anchors"]


ATTACKS = [
    ("Modify one field", a_modify), ("Delete one record", a_delete),
    ("Insert a record (inside an epoch)", a_insert), ("Insert after last anchor", a_insert_after),
    ("Reorder two decisions", a_reorder), ("Truncate the log (1-10 records)", a_truncate),
    ("Modify 2-5 records", a_multi), ("Replay a record from another run", a_replay),
    ("Change a time step", a_change_t), ("Change agent_id (impersonation)", a_swap_agent),
    ("Delete an epoch", a_delete_epoch), ("Substitute the whole history", a_substitute),
]


def detect(run, recs, anchors_override):
    ends = [a.epoch_end_t for a in run["anchors"]]
    rid = run["anchors"][0].run_id
    if anchors_override is not None:            # attacker necessarily edited anchors
        m1 = None
        recs2, anch2 = recs, anchors_override
    else:
        m1 = not verify(recs, run["anchors"]).ok
        recs2, anch2 = repair(recs, rid, ends)
    m2 = not verify(recs2, anch2).ok
    m3 = not verify(recs2, anch2, run["run_root"]).ok
    return m1, m2, m3


def negative_control(kind, rng, seed):
    target = rng.randrange(N_AGENTS * STEPS)
    counter = {"i": 0}

    def hook(rec):
        i = counter["i"]; counter["i"] += 1
        if i != target:
            return rec
        if kind == "omit":
            return None
        rec["intent"] = other_intent(rng, rec["intent"]); return rec

    run = run_simulation(N_AGENTS, STEPS, COMMIT_EVERY, seed=seed, hook=hook)
    ok_local = verify(run["records"], run["anchors"]).ok
    ok_chain = verify(run["records"], run["anchors"], run["run_root"]).ok
    return (not ok_local, not ok_local, not ok_chain)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h) * 100, min(1, c + h) * 100


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--trials", type=int, default=100, help="trials per seed")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    rows = []
    names = [n for n, _ in ATTACKS] + ["Pre-anchor omission (negative control)",
                                       "Fabrication by compromised logger (negative control)"]
    counts = {n: [0, 0, 0, 0] for n in names}   # m1, m1_n, m2, m3 ; n = total
    total = a.seeds * a.trials
    fp = [0, 0]
    for s in range(a.seeds):
        rng = random.Random(s)
        for j in range(a.trials):
            run = run_simulation(N_AGENTS, STEPS, COMMIT_EVERY, seed=s * 100000 + j)
            fp[0] += not verify(run["records"], run["anchors"]).ok
            fp[1] += not verify(run["records"], run["anchors"], run["run_root"]).ok
            for name, fn in ATTACKS:
                m1, m2, m3 = detect(run, *fn(rng, run))
                c = counts[name]
                if m1 is not None:
                    c[0] += m1; c[1] += 1
                c[2] += m2; c[3] += m3
            for name, kind in zip(names[-2:], ("omit", "fabricate")):
                m1, m2, m3 = negative_control(kind, rng, s * 100000 + j)
                c = counts[name]; c[0] += m1; c[1] += 1; c[2] += m2; c[3] += m3

    def pct(k, n):
        return "n/a" if n == 0 else f"{100 * k / n:.1f}"

    with open(os.path.join(a.out, "attack_detection.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack", "trials", "M1_local_logs_only_pct", "M2_local_logs_and_anchors_pct",
                    "M3_onchain_pct", "M3_wilson95_low", "M3_wilson95_high"])
        for n in names:
            c = counts[n]; lo, hi = wilson(c[3], total)
            w.writerow([n, total, pct(c[0], c[1]), pct(c[2], total), pct(c[3], total), f"{lo:.2f}", f"{hi:.2f}"])
        w.writerow(["False positives on honest runs", total, pct(fp[0], total), pct(fp[0], total),
                    pct(fp[1], total), *[f"{x:.2f}" for x in wilson(fp[1], total)]])

    md = ["| Attack | M1 local, logs only | M2 local, logs + anchors | M3 on-chain |", "|---|---|---|---|"]
    for n in names:
        c = counts[n]
        md.append(f"| {n} | {pct(c[0], c[1])} | {pct(c[2], total)} | {pct(c[3], total)} |")
    md.append(f"| False positives on honest runs | {pct(fp[0], total)} | {pct(fp[0], total)} | {pct(fp[1], total)} |")
    md.append(f"\nDetection rate in %. {total} trials per attack ({a.seeds} seeds x {a.trials}); "
              f"2 agents, {STEPS} steps, commit_every={COMMIT_EVERY}. Runtime {time.time() - t0:.0f} s.")
    open(os.path.join(a.out, "attack_detection.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
