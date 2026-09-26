import copy
import random
import unittest

from crypanchor import MerkleTree, leaf_hash, verify_proof, verify, prove_event, verify_event
from crypanchor.chain import extract_run_root, payload
from crypanchor.sim import run_simulation


class TestMerkle(unittest.TestCase):
    def test_proofs_all_sizes(self):
        for n in range(1, 40):
            leaves = [leaf_hash(bytes([i])) for i in range(n)]
            t = MerkleTree(leaves)
            for i in range(n):
                self.assertTrue(verify_proof(leaves[i], t.prove(i), t.root))
                self.assertFalse(verify_proof(leaf_hash(b"x"), t.prove(i), t.root))

    def test_no_duplication_ambiguity(self):
        a, b, c = (leaf_hash(x) for x in (b"a", b"b", b"c"))
        self.assertNotEqual(MerkleTree([a, b, c]).root, MerkleTree([a, b, c, c]).root)


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.r = run_simulation(n_agents=2, steps=50, commit_every=10, seed=1)

    def test_honest(self):
        self.assertTrue(verify(self.r["records"], self.r["anchors"], self.r["run_root"]))

    def test_modify(self):
        recs = copy.deepcopy(self.r["records"])
        recs[7]["intent"] = "TELEPORT"
        self.assertFalse(verify(recs, self.r["anchors"], self.r["run_root"]))

    def test_after_last_anchor(self):
        recs = copy.deepcopy(self.r["records"])
        extra = dict(recs[-1], t=recs[-1]["t"] + 1, seq=recs[-1]["seq"] + 1)
        recs.append(extra)
        res = verify(recs, self.r["anchors"], self.r["run_root"])
        self.assertEqual(res.reason, "records after last anchor")

    def test_event_proof(self):
        rec = random.Random(0).choice(self.r["records"])
        p = prove_event(self.r["records"], self.r["anchors"], rec)
        self.assertTrue(verify_event(p, self.r["run_root"]))
        p["record"] = dict(rec, intent="X")
        self.assertFalse(verify_event(p, self.r["run_root"]))


class TestChain(unittest.TestCase):
    def test_extract(self):
        root = bytes(range(32))
        spk = (b"\x6a\x24" + payload(root)).hex()
        tx = {"vout": [{"scriptpubkey": "0014" + "00" * 20}, {"scriptpubkey": spk}]}
        self.assertEqual(extract_run_root(tx), root)


if __name__ == "__main__":
    unittest.main()
