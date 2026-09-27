"""Measure on-chain overhead of anchoring transactions (paper, Table 4).

  watch TXID [--run DIR]   start right after broadcasting; polls until 6
                           confirmations and appends a row to
                           results/onchain_watch.csv (also stores the txid
                           in DIR/anchor_receipt.json and checks the payload)
  stats TXID ...           one-off size/fee lookup for already confirmed txs
  summary                  prints a Markdown table from the CSV
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypanchor import chain  # noqa: E402

CSV = os.path.join("results", "onchain_watch.csv")
FIELDS = ["txid", "network", "vsize_vB", "weight_WU", "fee_sat", "feerate_sat_vB",
          "broadcast_utc", "sec_to_1conf", "sec_to_6conf", "block_height", "payload_ok"]


def size_fee(tx):
    w = tx["weight"]
    return {"vsize_vB": -(-w // 4), "weight_WU": w, "fee_sat": tx["fee"],
            "feerate_sat_vB": round(tx["fee"] / (-(-w // 4)), 2)}


def watch(a):
    start = time.time()
    row = {"txid": a.txid, "network": a.network,
           "broadcast_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start))}
    t1 = t6 = None
    while t6 is None:
        try:
            tx = chain.fetch_tx(a.txid, a.network)
            row.update(size_fee(tx))
            c = tx["confirmations"]
            if c >= 1 and t1 is None:
                t1 = time.time() - start; row["block_height"] = tx["status"]["block_height"]
            if c >= 6:
                t6 = time.time() - start
            print(f"{time.strftime('%H:%M:%S')} confirmations={c}", flush=True)
        except Exception as e:
            print("waiting:", e, flush=True)
        if t6 is None:
            time.sleep(a.interval)
    row.update(sec_to_1conf=round(t1), sec_to_6conf=round(t6))
    root = chain.extract_run_root(tx)
    if a.run:
        p = os.path.join(a.run, "anchor_receipt.json")
        rec = json.load(open(p))
        row["payload_ok"] = root is not None and root.hex() == rec["run_root"]
        rec.update(txid=a.txid, network=a.network)
        json.dump(rec, open(p, "w"), indent=2)
    else:
        row["payload_ok"] = root is not None
    os.makedirs("results", exist_ok=True)
    new = not os.path.exists(CSV)
    with open(CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
    print(json.dumps(row, indent=2))


def stats(a):
    for txid in a.txids:
        tx = chain.fetch_tx(txid, a.network)
        print(txid, size_fee(tx), "confirmations:", tx["confirmations"])


def summary(a):
    rows = list(csv.DictReader(open(CSV)))
    def col(k):
        return [float(r[k]) for r in rows if r.get(k)]
    print(f"n = {len(rows)} anchoring transactions\n")
    print("| Metric | Median | Min | Max |\n|---|---|---|---|")
    for k, label in (("vsize_vB", "Transaction size (vB)"), ("fee_sat", "Fee (sat)"),
                     ("feerate_sat_vB", "Fee rate (sat/vB)"), ("sec_to_1conf", "Time to 1 confirmation (s)"),
                     ("sec_to_6conf", "Time to 6 confirmations (s)")):
        v = col(k)
        if v:
            print(f"| {label} | {statistics.median(v):g} | {min(v):g} | {max(v):g} |")


ap = argparse.ArgumentParser()
sub = ap.add_subparsers(dest="cmd", required=True)
w = sub.add_parser("watch"); w.add_argument("txid"); w.add_argument("--run")
w.add_argument("--interval", type=int, default=20); w.set_defaults(f=watch)
s = sub.add_parser("stats"); s.add_argument("txids", nargs="+"); s.set_defaults(f=stats)
m = sub.add_parser("summary"); m.set_defaults(f=summary)
for p in (w, s):
    p.add_argument("--network", default="testnet4", choices=list(chain.EXPLORERS))
a = ap.parse_args(); a.f(a)
