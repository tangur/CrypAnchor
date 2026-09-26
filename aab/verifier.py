from dataclasses import asdict
from typing import List, Optional, Tuple
from .core import DecisionRecord, AnchorRecord, hash_record, merkle_root_hex

def verify_logs_against_anchors(
    disclosed_logs: List[DecisionRecord],
    anchors: List[AnchorRecord],
) -> Tuple[bool, Optional[int]]:
    entries = [asdict(e) for e in disclosed_logs]
    entries.sort(key=lambda d: (d["t"], d["agent_id"]))

    idx = 0
    for ar in anchors:
        leaves = []
        end_t = ar.epoch_end_t
        while idx < len(entries) and entries[idx]["t"] <= end_t:
            leaves.append(hash_record(entries[idx]))
            idx += 1
        if merkle_root_hex(leaves) != ar.merkle_root:
            return False, end_t
    return True, None
