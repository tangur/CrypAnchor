import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

HEX64 = set("0123456789abcdef")

def _is_hex64(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in HEX64 for c in s)

@dataclass(frozen=True)
class LastAnchor:
    epoch_end_t: int
    leaf_count: int
    timestamp_ns: int
    merkle_root: str

def load_last_anchor(anchor_file: str = "anchors_demo.jsonl") -> LastAnchor:
    p = Path(anchor_file)
    if not p.exists():
        raise FileNotFoundError(f"{anchor_file} not found. Run demo first or set correct filename.")

    last: Optional[Dict[str, Any]] = None
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last = json.loads(line)

    if not last:
        raise ValueError("Anchor file is empty.")

    root = last.get("merkle_root")
    if not _is_hex64(root):
        raise ValueError(f"Unexpected merkle_root format: {root}")

    return LastAnchor(
        epoch_end_t=int(last["epoch_end_t"]),
        leaf_count=int(last["leaf_count"]),
        timestamp_ns=int(last["timestamp_ns"]),
        merkle_root=root,
    )

def electrum_paytomany_template(opreturn_hex: str, self_testnet_address: str, amount_btc: str) -> str:
    if not _is_hex64(opreturn_hex):
        raise ValueError("opreturn_hex must be 64 hex chars (32 bytes).")
    return (
        f"script(OP_RETURN {opreturn_hex}),0\n"
        f"{self_testnet_address},{amount_btc}\n"
    )

def export_electrum_text(
    anchor_file: str = "anchors_demo.jsonl",
    receive_address: str = "tb1YOURTESTNETADDRESSHERE",
    amount_btc: str = "0.00001",
) -> Tuple[LastAnchor, str]:
    last = load_last_anchor(anchor_file)
    txt = electrum_paytomany_template(last.merkle_root, receive_address, amount_btc)
    return last, txt
