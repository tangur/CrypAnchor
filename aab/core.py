import json
import time
import hashlib
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Hashing + Merkle
# ============================================================

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical_json_bytes(obj))

def merkle_root(leaves: List[str]) -> str:
    """
    leaves: list of hex strings (already hashed)
    """
    if not leaves:
        return sha256_hex(b"")
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if (i + 1) < len(level) else left
            nxt.append(sha256_hex((left + right).encode("utf-8")))
        level = nxt
    return level[0]


# ============================================================
# Data structures
# ============================================================

@dataclass
class DecisionRecord:
    t: int
    agent_id: str
    state_summary: Dict[str, Any]
    intent: str
    context: Dict[str, Any]

@dataclass
class AnchorRecord:
    epoch_end_t: int
    merkle_root: str
    timestamp_ns: int
    leaf_count: int


# ============================================================
# Anchor store (JSONL)
# ============================================================

class JsonlAnchorStore:
    """
    Writes ONLY compact commitments (Merkle roots) to jsonl.
    """
    def __init__(self, path: str = "anchors.jsonl", truncate: bool = False):
        self.path = path
        if truncate:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("")

    def append(self, rec: AnchorRecord) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(rec), sort_keys=True) + "\n")

    def read_all(self) -> List[AnchorRecord]:
        out: List[AnchorRecord] = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    out.append(AnchorRecord(
                        epoch_end_t=int(obj["epoch_end_t"]),
                        merkle_root=str(obj["merkle_root"]),
                        timestamp_ns=int(obj["timestamp_ns"]),
                        leaf_count=int(obj["leaf_count"]),
                    ))
        except FileNotFoundError:
            return []
        return out


# ============================================================
# Accountability Blackbox
# ============================================================

class AccountabilityBlackbox:
    """
    Records per-decision minimal summaries to a local JSONL log file
    and periodically commits compact Merkle roots to an immutable-like
    anchor store (here JSONL store or real Bitcoin later).

    Key rule: record() NEVER commits. Commit happens only in maybe_commit(t)
    so each timestep has both agents' leaves before commit.
    """
    def __init__(
        self,
        anchor_store: JsonlAnchorStore,
        logs_path: str = "logs.jsonl",
        commit_every: int = 5,
        truncate_files: bool = False,
    ):
        self.anchor_store = anchor_store
        self.logs_path = logs_path
        self.commit_every = int(commit_every)

        self._pending_leaves: List[str] = []
        self._last_committed_t: Optional[int] = None

        if truncate_files:
            with open(self.logs_path, "w", encoding="utf-8") as f:
                f.write("")

    def record(
        self,
        t: int,
        agent_id: str,
        state_summary: Dict[str, Any],
        intent: str,
        context: Dict[str, Any],
    ) -> None:
        rec = DecisionRecord(
            t=int(t),
            agent_id=str(agent_id),
            state_summary=state_summary,
            intent=str(intent),
            context=context,
        )

        # append to local log
        with open(self.logs_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(rec), sort_keys=True) + "\n")

        # add leaf hash
        self._pending_leaves.append(hash_obj(asdict(rec)))

    def maybe_commit(self, t: int) -> Optional[AnchorRecord]:
        """
        Call once per timestep AFTER all agents recorded.
        Commits only when (t+1) % commit_every == 0.
        """
        t = int(t)
        if self.commit_every <= 0:
            return None

        if (t + 1) % self.commit_every != 0:
            return None

        # guard against double commit on same timestep
        if self._last_committed_t == t:
            return None

        root = merkle_root(self._pending_leaves)
        ar = AnchorRecord(
            epoch_end_t=t,
            merkle_root=root,
            timestamp_ns=time.time_ns(),
            leaf_count=len(self._pending_leaves),
        )
        self.anchor_store.append(ar)

        self._pending_leaves = []
        self._last_committed_t = t
        return ar

    def finalize(self, t_final: int) -> Optional[AnchorRecord]:
        """
        Call once at end of run. If there are pending leaves, anchor them at t_final.
        """
        t_final = int(t_final)
        if not self._pending_leaves:
            return None

        root = merkle_root(self._pending_leaves)
        ar = AnchorRecord(
            epoch_end_t=t_final,
            merkle_root=root,
            timestamp_ns=time.time_ns(),
            leaf_count=len(self._pending_leaves),
        )
        self.anchor_store.append(ar)

        self._pending_leaves = []
        self._last_committed_t = t_final
        return ar


# ============================================================
# Log / Anchor loading
# ============================================================

def load_logs_jsonl(path: str) -> List[DecisionRecord]:
    logs: List[DecisionRecord] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            logs.append(DecisionRecord(
                t=int(obj["t"]),
                agent_id=str(obj["agent_id"]),
                state_summary=obj["state_summary"],
                intent=str(obj["intent"]),
                context=obj["context"],
            ))
    return logs

def load_anchors_jsonl(path: str) -> List[AnchorRecord]:
    anchors: List[AnchorRecord] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            anchors.append(AnchorRecord(
                epoch_end_t=int(obj["epoch_end_t"]),
                merkle_root=str(obj["merkle_root"]),
                timestamp_ns=int(obj["timestamp_ns"]),
                leaf_count=int(obj["leaf_count"]),
            ))
    return anchors


# ============================================================
# Verification
# ============================================================

def verify_logs_against_anchors(
    logs_path: str,
    anchors_path: str,
) -> Tuple[bool, Optional[int]]:
    """
    Recompute Merkle roots epoch-by-epoch from disclosed logs.
    If any epoch root mismatches anchored root -> FAIL, return bad epoch_end_t.
    """

    logs = load_logs_jsonl(logs_path)
    anchors = load_anchors_jsonl(anchors_path)

    logs_sorted = sorted(logs, key=lambda r: (r.t, r.agent_id))
    anchors_sorted = sorted(anchors, key=lambda a: a.epoch_end_t)

    idx = 0
    for ar in anchors_sorted:
        leaves: List[str] = []
        end_t = ar.epoch_end_t

        while idx < len(logs_sorted) and logs_sorted[idx].t <= end_t:
            leaves.append(hash_obj(asdict(logs_sorted[idx])))
            idx += 1

        if merkle_root(leaves) != ar.merkle_root:
            return False, end_t

    return True, None


# ============================================================
# Electrum helper
# ============================================================

def electrum_paytomany_template(
    opreturn_hex: str,
    self_testnet_address: str = "tb1YOURTESTNETADDRESSHERE",
    amount_btc: str = "0.00001",
) -> str:
    """
    Electrum 'Pay to Many' accepts:
      script(OP_RETURN <hex>),0
      <addr>,<amount>
    """
    return (
        f"script(OP_RETURN {opreturn_hex}),0\n"
        f"{self_testnet_address},{amount_btc}\n"
    )
