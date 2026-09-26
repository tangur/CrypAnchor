"""Decision logging, epoch commitments, run root, and verification.

Record fields: run_id, seq (per agent, 0,1,2,...), t, agent_id,
state_summary, intent, context. Records are serialized as canonical JSON
(sorted keys, no whitespace, UTF-8) and hashed as Merkle leaves.

Every `commit_every` time steps the pending records form an epoch. Each epoch
is summarized by an EpochAnchor (epoch_index, epoch_end_t, leaf_count,
epoch_root, run_id). At the end of a run all epoch anchors are aggregated into
ONE run root, which is the only value anchored on-chain. Because the epoch
metadata is part of the run root, the anchors file cannot be rewritten without
changing the on-chain commitment.
"""
import json
import time
import uuid
from dataclasses import dataclass, asdict, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .merkle import MerkleTree, leaf_hash, verify_proof, Proof

Record = Dict[str, Any]


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_leaf(rec: Record) -> bytes:
    return leaf_hash(canonical(rec))


def sort_key(rec: Record) -> Tuple:
    return (int(rec["t"]), str(rec["agent_id"]), int(rec["seq"]))


@dataclass
class EpochAnchor:
    epoch_index: int
    epoch_end_t: int
    leaf_count: int
    epoch_root: str          # hex
    run_id: str
    timestamp_ns: int = 0    # informational, NOT bound into the run root

    def bound_fields(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("timestamp_ns")
        return d

    def leaf(self) -> bytes:
        return leaf_hash(canonical(self.bound_fields()))


def compute_run_root(anchors: List[EpochAnchor]) -> bytes:
    return MerkleTree([a.leaf() for a in anchors]).root


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class AccountabilityBlackbox:
    """Middleware that records decisions and commits them per epoch.

    `hook` (optional) is applied to each record BEFORE it is sequenced and
    hashed. It exists only to simulate a compromised logger in the attack
    experiments (return None to drop a record, or a modified record).
    """

    def __init__(self, commit_every: int = 10, run_id: Optional[str] = None,
                 logs_path: Optional[str] = None, anchors_path: Optional[str] = None,
                 hook: Optional[Callable[[Record], Optional[Record]]] = None):
        self.commit_every = int(commit_every)
        self.run_id = run_id or uuid.uuid4().hex[:16]
        self.logs_path, self.anchors_path, self.hook = logs_path, anchors_path, hook
        self.records: List[Record] = []
        self.anchors: List[EpochAnchor] = []
        self._pending: List[Record] = []
        self._seq: Dict[str, int] = {}
        self._finalized = False
        for p in (logs_path, anchors_path):
            if p:
                open(p, "w", encoding="utf-8").close()

    def record(self, t: int, agent_id: str, state_summary: Dict[str, Any],
               intent: str, context: Dict[str, Any]) -> Optional[Record]:
        if self._finalized:
            raise RuntimeError("run already finalized")
        rec: Optional[Record] = {"run_id": self.run_id, "t": int(t), "agent_id": str(agent_id),
                                 "state_summary": state_summary, "intent": str(intent),
                                 "context": context}
        if self.hook:
            rec = self.hook(rec)
            if rec is None:
                return None
        rec["seq"] = self._seq.get(rec["agent_id"], 0)
        self._seq[rec["agent_id"]] = rec["seq"] + 1
        self._pending.append(rec)
        self.records.append(rec)
        if self.logs_path:
            with open(self.logs_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        return rec

    def _commit(self, t: int) -> EpochAnchor:
        leaves = [record_leaf(r) for r in sorted(self._pending, key=sort_key)]
        a = EpochAnchor(epoch_index=len(self.anchors), epoch_end_t=int(t),
                        leaf_count=len(leaves), epoch_root=MerkleTree(leaves).root.hex(),
                        run_id=self.run_id, timestamp_ns=time.time_ns())
        self.anchors.append(a)
        self._pending = []
        if self.anchors_path:
            with open(self.anchors_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(a), sort_keys=True) + "\n")
        return a

    def maybe_commit(self, t: int) -> Optional[EpochAnchor]:
        """Call once per time step, after all agents have recorded."""
        if self.commit_every > 0 and (int(t) + 1) % self.commit_every == 0 and self._pending:
            return self._commit(t)
        return None

    def finalize(self, t_final: int) -> bytes:
        """Commit any pending records and return the run root (32 bytes)."""
        if self._pending:
            self._commit(t_final)
        self._finalized = True
        return compute_run_root(self.anchors)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_jsonl(path: str) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_anchors(path: str) -> List[EpochAnchor]:
    return [EpochAnchor(**d) for d in load_jsonl(path)]


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    ok: bool
    reason: str = "ok"
    epoch_index: Optional[int] = None

    def __bool__(self) -> bool:
        return self.ok


def verify(records: List[Record], anchors: List[EpochAnchor],
           expected_run_root: Optional[bytes] = None) -> VerifyResult:
    """Verify disclosed records against epoch anchors and (optionally) the
    on-chain run root. Without `expected_run_root` only local consistency is
    checked, which an attacker who can rewrite both files can defeat."""
    if not anchors:
        return VerifyResult(False, "no anchors")
    run_id = anchors[0].run_id
    for i, a in enumerate(anchors):
        if a.epoch_index != i:
            return VerifyResult(False, "epoch index gap", i)
        if a.run_id != run_id:
            return VerifyResult(False, "run_id mismatch in anchors", i)
        if i and a.epoch_end_t <= anchors[i - 1].epoch_end_t:
            return VerifyResult(False, "epoch order", i)

    # 1. on-chain commitment (checked first: it is the trust anchor)
    if expected_run_root is not None and compute_run_root(anchors) != expected_run_root:
        return VerifyResult(False, "run root does not match on-chain commitment")

    # 2. record-level checks
    per_agent: Dict[str, List[Record]] = {}
    for r in records:
        if r.get("run_id") != run_id:
            return VerifyResult(False, "record from another run")
        per_agent.setdefault(r["agent_id"], []).append(r)
    for agent, recs in per_agent.items():
        recs.sort(key=lambda r: r["seq"])
        for k, r in enumerate(recs):
            if r["seq"] != k:
                return VerifyResult(False, f"sequence gap or duplicate for {agent}")
            if k and r["t"] < recs[k - 1]["t"]:
                return VerifyResult(False, f"time order violated for {agent}")
    last_t = anchors[-1].epoch_end_t
    if any(r["t"] > last_t for r in records):
        return VerifyResult(False, "records after last anchor")

    # 3. epoch roots
    ordered = sorted(records, key=sort_key)
    idx, prev_end = 0, None
    for a in anchors:
        epoch: List[Record] = []
        while idx < len(ordered) and ordered[idx]["t"] <= a.epoch_end_t:
            epoch.append(ordered[idx])
            idx += 1
        if len(epoch) != a.leaf_count:
            return VerifyResult(False, "leaf count mismatch", a.epoch_index)
        if MerkleTree([record_leaf(r) for r in epoch]).root.hex() != a.epoch_root:
            return VerifyResult(False, "epoch root mismatch", a.epoch_index)
        prev_end = a.epoch_end_t
    return VerifyResult(True)


# ---------------------------------------------------------------------------
# Single-event inclusion proofs (event -> epoch root -> run root)
# ---------------------------------------------------------------------------

def prove_event(records: List[Record], anchors: List[EpochAnchor], record: Record) -> Dict[str, Any]:
    """Build a proof that `record` is committed under the run root. Only the
    record itself, the proof hashes and its epoch anchor need to be disclosed."""
    import bisect
    ends = [a.epoch_end_t for a in anchors]
    e = bisect.bisect_left(ends, record["t"])
    if e >= len(anchors):
        raise ValueError("record not covered by any anchor")
    a = anchors[e]
    lo = anchors[e - 1].epoch_end_t if e else None
    epoch = sorted((r for r in records if r["t"] <= a.epoch_end_t and (lo is None or r["t"] > lo)), key=sort_key)
    if record in epoch:
        inner = MerkleTree([record_leaf(r) for r in epoch]).prove(epoch.index(record))
        outer = MerkleTree([x.leaf() for x in anchors]).prove(a.epoch_index)
        return {"record": record, "epoch_anchor": asdict(a),
                "inner": [(s, h.hex()) for s, h in inner],
                "outer": [(s, h.hex()) for s, h in outer]}
    raise ValueError("record not found")


def verify_event(proof: Dict[str, Any], run_root: bytes) -> bool:
    a = EpochAnchor(**proof["epoch_anchor"])
    inner: Proof = [(s, bytes.fromhex(h)) for s, h in proof["inner"]]
    outer: Proof = [(s, bytes.fromhex(h)) for s, h in proof["outer"]]
    return (proof["record"].get("run_id") == a.run_id
            and verify_proof(record_leaf(proof["record"]), inner, bytes.fromhex(a.epoch_root))
            and verify_proof(a.leaf(), outer, run_root))


def proof_bytes(proof: Dict[str, Any]) -> int:
    """Size of the hashes in a proof (excluding the disclosed record itself)."""
    return 33 * (len(proof["inner"]) + len(proof["outer"])) + len(canonical(proof["epoch_anchor"]))
