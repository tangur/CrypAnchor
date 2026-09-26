import json
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass(frozen=True)
class AnchorReceipt:
    network: str
    txid: str
    merkle_root: str
    epoch_end_t: int
    timestamp_ns: int
    leaf_count: int

def save_receipt(receipt: AnchorReceipt, path: str = "anchor_receipt.json") -> str:
    p = Path(path)
    p.write_text(json.dumps(asdict(receipt), indent=2, sort_keys=True), encoding="utf-8")
    return str(p)

def load_receipt(path: str = "anchor_receipt.json") -> AnchorReceipt:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return AnchorReceipt(**d)
