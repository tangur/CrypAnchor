import os
import sys
import random
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional

# ✅ PATH FIX: aab_v1 root'u sys.path'e ekle (bu satırlar hatayı bitirir)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aab.core import (
    AccountabilityBlackbox,
    JsonlAnchorStore,
    verify_logs_against_anchors,
    electrum_paytomany_template,
)

ACTIONS = ["UP", "DOWN", "LEFT", "RIGHT", "WAIT"]


class Agent:
    def __init__(self, agent_id: str, start: Tuple[int, int]):
        self.id = agent_id
        self.pos = [start[0], start[1]]

    def perceive(self, other_pos: Tuple[int, int]) -> Dict[str, Any]:
        dx = other_pos[0] - self.pos[0]
        dy = other_pos[1] - self.pos[1]
        return {"x": self.pos[0], "y": self.pos[1], "other_dx": dx, "other_dy": dy}

    def decide(self, belief: Dict[str, Any], constraint: Dict[str, Any]) -> str:
        near = abs(belief["other_dx"]) + abs(belief["other_dy"]) <= 1
        if near and random.random() < 0.7:
            return "WAIT"
        if constraint.get("priority") == "STOP" and random.random() < 0.5:
            return "WAIT"
        return random.choice(ACTIONS)

    def step(self, action: str, grid_size: int):
        x, y = self.pos
        if action == "UP":
            y = max(0, y - 1)
        elif action == "DOWN":
            y = min(grid_size - 1, y + 1)
        elif action == "LEFT":
            x = max(0, x - 1)
        elif action == "RIGHT":
            x = min(grid_size - 1, x + 1)
        self.pos = [x, y]


def collision(a_pos: Tuple[int, int], b_pos: Tuple[int, int]) -> bool:
    return a_pos[0] == b_pos[0] and a_pos[1] == b_pos[1]


def main():
    # -------------------
    # Config
    # -------------------
    T = 30
    commit_every = 5
    grid_size = 8
    seed = 7

    logs_path = os.path.join(ROOT, "logs_demo.jsonl")
    anchors_path = os.path.join(ROOT, "anchors_demo.jsonl")

    random.seed(seed)

    # -------------------
    # Setup
    # -------------------
    A = Agent("A", (1, 1))
    B = Agent("B", (1, 5))

    anchor_store = JsonlAnchorStore(anchors_path, truncate=True)
    bb = AccountabilityBlackbox(
        anchor_store=anchor_store,
        logs_path=logs_path,
        commit_every=commit_every,
        truncate_files=True,
    )

    collision_t: Optional[int] = None

    print("\n--- SIM START ---")
    for t in range(T):
        constraintA = {"priority": "GO" if t % 2 == 0 else "STOP"}
        constraintB = {"priority": "STOP" if t % 2 == 0 else "GO"}

        beliefA = A.perceive(tuple(B.pos))
        beliefB = B.perceive(tuple(A.pos))

        actA = A.decide(beliefA, constraintA)
        actB = B.decide(beliefB, constraintB)

        # record BOTH agents
        bb.record(t, "A", beliefA, actA, {"constraint": constraintA, "msg": f"A@{t}"})
        bb.record(t, "B", beliefB, actB, {"constraint": constraintB, "msg": f"B@{t}"})

        print(f"[t={t:02d}] A pos={A.pos} intent={actA:5s} | B pos={B.pos} intent={actB:5s}")

        # step env
        A.step(actA, grid_size)
        B.step(actB, grid_size)

        if collision_t is None and collision(tuple(A.pos), tuple(B.pos)):
            collision_t = t
            print(f"  >>> COLLISION AFTER t={t} at pos={A.pos}")

        # ✅ commit AFTER both agents recorded in this timestep
        bb.maybe_commit(t)

    # ✅ final commit if leftover pending leaves
    bb.finalize(T - 1)
    print("--- SIM END ---\n")

    # -------------------
    # Verify (honest)
    # -------------------
    ok, bad_epoch = verify_logs_against_anchors(logs_path, anchors_path)
    print("== HONEST VERIFY ==", "PASS" if ok else f"FAIL (epoch_end_t={bad_epoch})")

    # -------------------
    # Tamper attack: edit log file and re-verify
    # (simple edit: change a line string replace)
    # -------------------
    if collision_t is not None:
        print("\n-- Tamper attack: change A intent at collision_t --")

        # naive tamper: replace first occurrence of '"t":<collision_t>,"agent_id":"A"... "intent":"X"'
        # We'll do safer parse-edit-write
        import json

        with open(logs_path, "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip()]

        recs = [json.loads(ln) for ln in lines]
        for r in recs:
            if int(r["t"]) == collision_t and r["agent_id"] == "A":
                before = r["intent"]
                r["intent"] = "WAIT" if before != "WAIT" else "GO"
                break

        with open(logs_path, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, sort_keys=True) + "\n")

        ok2, bad_epoch2 = verify_logs_against_anchors(logs_path, anchors_path)
        print("== ATTACK VERIFY ==", "PASS" if ok2 else f"FAIL (epoch_end_t={bad_epoch2})")

    # -------------------
    # Electrum export: last anchor root
    # -------------------
    anchors = anchor_store.read_all()
    last_root = anchors[-1].merkle_root if anchors else ""
    print("\n== ELECTRUM EXPORT ==")
    print("last merkle_root:", last_root)
    print("\nPASTE INTO ELECTRUM PAY TO MANY:\n")
    print(electrum_paytomany_template(last_root))


if __name__ == "__main__":
    main()
