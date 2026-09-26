"""CrypAnchor: tamper-evident decision logging for autonomous agents.

Decision records are kept off-chain, aggregated into Merkle trees per epoch,
and bound into a single run root that is anchored on Bitcoin via OP_RETURN.
"""
from .merkle import MerkleTree, leaf_hash, node_hash, verify_proof
from .core import (
    AccountabilityBlackbox, EpochAnchor, VerifyResult,
    compute_run_root, verify, load_jsonl, prove_event, verify_event,
)

__version__ = "1.0.0"
