"""Command line interface.

  python -m crypanchor.cli demo  [--out DIR]
  python -m crypanchor.cli verify --logs L --anchors A (--txid TXID [--network testnet4] | --run-root HEX | --receipt R)
  python -m crypanchor.cli prove  --logs L --anchors A --agent A --seq N
  python -m crypanchor.cli set-txid TXID --receipt R [--network testnet4]
"""
import argparse
import json
import os
import sys

from . import chain
from .core import load_anchors, load_jsonl, verify, prove_event, verify_event, compute_run_root, proof_bytes
from .sim import run_simulation


def write_receipt(path, run_root, anchors, network="testnet4", txid=None):
    rec = {"run_root": run_root.hex(), "op_return_payload": chain.payload(run_root).hex(),
           "run_id": anchors[0].run_id, "epochs": len(anchors),
           "network": network, "txid": txid}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    return rec


def cmd_demo(a):
    os.makedirs(a.out, exist_ok=True)
    L, A = os.path.join(a.out, "logs.jsonl"), os.path.join(a.out, "anchors.jsonl")
    r = run_simulation(n_agents=2, steps=a.steps, commit_every=a.commit_every, seed=a.seed,
                       logs_path=L, anchors_path=A)
    write_receipt(os.path.join(a.out, "anchor_receipt.json"), r["run_root"], r["anchors"])
    with open(os.path.join(a.out, "electrum.txt"), "w") as f:
        f.write(chain.electrum_paytomany(r["run_root"]))
    print(f"records: {len(r['records'])}, epochs: {len(r['anchors'])}, collisions: {r['collisions']}")
    print("run root:", r["run_root"].hex())
    print("honest verification:", verify(r["records"], r["anchors"], r["run_root"]).reason)
    print(f"\nElectrum 'Pay to many' text written to {a.out}/electrum.txt:\n")
    print(chain.electrum_paytomany(r["run_root"]))


def expected_root(a):
    if a.run_root:
        return bytes.fromhex(a.run_root), "run root given on command line"
    txid = a.txid
    if not txid and a.receipt:
        txid = json.load(open(a.receipt))["txid"]
        print("WARNING: txid taken from receipt file. For an independent audit, obtain the txid "
              "from the paper or the auditor, not from the party that holds the logs.", file=sys.stderr)
    if not txid:
        return None, "none (local consistency only)"
    return chain.onchain_run_root(txid, a.network, a.min_conf), f"OP_RETURN of {txid} ({a.network})"


def cmd_verify(a):
    root, src = expected_root(a)
    res = verify(load_jsonl(a.logs), load_anchors(a.anchors), root)
    print("reference:", src)
    print("RESULT:", "PASS" if res.ok else f"FAIL ({res.reason}" + (f", epoch {res.epoch_index})" if res.epoch_index is not None else ")"))
    sys.exit(0 if res.ok else 1)


def cmd_prove(a):
    recs, anchors = load_jsonl(a.logs), load_anchors(a.anchors)
    rec = next(r for r in recs if r["agent_id"] == a.agent and r["seq"] == a.seq)
    p = prove_event(recs, anchors, rec)
    root = compute_run_root(anchors)
    print(json.dumps(p, indent=2))
    print(f"\nproof size: {proof_bytes(p)} bytes; verifies against run root: {verify_event(p, root)}", file=sys.stderr)


def cmd_set_txid(a):
    rec = json.load(open(a.receipt))
    root = chain.onchain_run_root(a.txid, a.network, 1)
    if root.hex() != rec["run_root"]:
        sys.exit("transaction does not contain this run root")
    rec.update(txid=a.txid, network=a.network)
    json.dump(rec, open(a.receipt, "w"), indent=2)
    print("receipt updated")


def main(argv=None):
    p = argparse.ArgumentParser(prog="crypanchor")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--out", default="demo_run")
    d.add_argument("--steps", type=int, default=100); d.add_argument("--commit-every", type=int, default=10)
    d.add_argument("--seed", type=int, default=7); d.set_defaults(f=cmd_demo)
    v = sub.add_parser("verify")
    for x in ("--logs", "--anchors"): v.add_argument(x, required=True)
    v.add_argument("--txid"); v.add_argument("--run-root"); v.add_argument("--receipt")
    v.add_argument("--network", default="testnet4", choices=list(chain.EXPLORERS))
    v.add_argument("--min-conf", type=int, default=1); v.set_defaults(f=cmd_verify)
    q = sub.add_parser("prove")
    for x in ("--logs", "--anchors", "--agent"): q.add_argument(x, required=True)
    q.add_argument("--seq", type=int, required=True); q.set_defaults(f=cmd_prove)
    s = sub.add_parser("set-txid"); s.add_argument("txid"); s.add_argument("--receipt", required=True)
    s.add_argument("--network", default="testnet4", choices=list(chain.EXPLORERS)); s.set_defaults(f=cmd_set_txid)
    a = p.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
