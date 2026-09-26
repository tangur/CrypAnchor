"""Merkle tree with explicit domain separation and inclusion proofs.

Construction (documented in the paper, Section 3.4):
  leaf  = SHA-256(0x00 || data)
  node  = SHA-256(0x01 || left || right)        (raw 32-byte digests)
  odd   = if a level has an odd number of nodes, the last node is promoted
          unchanged to the next level (no duplication, so no CVE-2012-2459-style
          ambiguity between leaf lists).
  empty = SHA-256(b"")
"""
import hashlib
from typing import List, Sequence, Tuple

Proof = List[Tuple[str, bytes]]  # ("L" | "R", sibling digest)


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    def __init__(self, leaves: Sequence[bytes]):
        """leaves: already-hashed leaf digests (use leaf_hash)."""
        self.levels: List[List[bytes]] = [list(leaves)]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = [node_hash(cur[i], cur[i + 1]) for i in range(0, len(cur) - 1, 2)]
            if len(cur) % 2:
                nxt.append(cur[-1])  # promote odd node
            self.levels.append(nxt)

    @property
    def root(self) -> bytes:
        if not self.levels[0]:
            return hashlib.sha256(b"").digest()
        return self.levels[-1][0]

    def __len__(self) -> int:
        return len(self.levels[0])

    def prove(self, i: int) -> Proof:
        if not 0 <= i < len(self):
            raise IndexError(i)
        proof: Proof = []
        for level in self.levels[:-1]:
            if i % 2 == 0:
                if i + 1 < len(level):
                    proof.append(("R", level[i + 1]))
                # else: promoted, no sibling at this level
            else:
                proof.append(("L", level[i - 1]))
            i //= 2
        return proof


def verify_proof(leaf: bytes, proof: Proof, root: bytes) -> bool:
    h = leaf
    for side, sib in proof:
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == root


def proof_size_bytes(proof: Proof) -> int:
    return sum(1 + len(s) for _, s in proof)
