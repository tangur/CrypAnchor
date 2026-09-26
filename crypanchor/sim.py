"""Gridworld simulation used in the paper.

Agents follow a stochastic rule-based policy (the 'AI agent' is a stand-in
decision-maker; the logging layer treats it as a black box):
  - observe own position and offset (dx, dy) to the nearest other agent
  - priority constraint GO/STOP alternates each time step
  - if another agent is within Manhattan distance 1: WAIT with p = 0.7
  - if constraint is STOP: WAIT with p = 0.5
  - otherwise uniform over {UP, DOWN, LEFT, RIGHT, WAIT}
Grid: 8 x 8 for two agents; larger grids for more agents (see grid_size()).
"""
import math
import random
from typing import Any, Callable, Dict, List, Optional

from .core import AccountabilityBlackbox

ACTIONS = ["UP", "DOWN", "LEFT", "RIGHT", "WAIT"]


def grid_size(n_agents: int) -> int:
    return max(8, math.ceil(4 * math.sqrt(n_agents)))


def agent_ids(n: int) -> List[str]:
    return ["A", "B"] if n == 2 else [f"agent{i:03d}" for i in range(n)]


def run_simulation(n_agents: int = 2, steps: int = 100, commit_every: int = 10, seed: int = 0,
                   run_id: Optional[str] = None, logs_path: Optional[str] = None,
                   anchors_path: Optional[str] = None,
                   hook: Optional[Callable] = None) -> Dict[str, Any]:
    rng = random.Random(seed)
    g = grid_size(n_agents)
    ids = agent_ids(n_agents)
    cells = rng.sample(range(g * g), n_agents)
    pos = {a: [c % g, c // g] for a, c in zip(ids, cells)}
    bb = AccountabilityBlackbox(commit_every=commit_every, run_id=run_id or f"seed{seed}-{rng.getrandbits(48):012x}",
                                logs_path=logs_path, anchors_path=anchors_path, hook=hook)
    collisions = 0
    for t in range(steps):
        snapshot = {a: tuple(p) for a, p in pos.items()}
        actions = {}
        for k, a in enumerate(ids):
            x, y = snapshot[a]
            others = [snapshot[b] for b in ids if b != a]
            ox, oy = min(others, key=lambda q: abs(q[0] - x) + abs(q[1] - y))
            obs = {"x": x, "y": y, "other_dx": ox - x, "other_dy": oy - y}
            con = {"priority": "GO" if (t + k) % 2 == 0 else "STOP"}
            if abs(ox - x) + abs(oy - y) <= 1 and rng.random() < 0.7:
                act = "WAIT"
            elif con["priority"] == "STOP" and rng.random() < 0.5:
                act = "WAIT"
            else:
                act = rng.choice(ACTIONS)
            actions[a] = act
            bb.record(t, a, obs, act, {"constraint": con, "msg": f"{a}@{t}"})
        for a, act in actions.items():
            x, y = pos[a]
            if act == "UP": y = max(0, y - 1)
            elif act == "DOWN": y = min(g - 1, y + 1)
            elif act == "LEFT": x = max(0, x - 1)
            elif act == "RIGHT": x = min(g - 1, x + 1)
            pos[a] = [x, y]
        occupied = [tuple(p) for p in pos.values()]
        collisions += len(occupied) - len(set(occupied))
        bb.maybe_commit(t)
    run_root = bb.finalize(steps - 1)
    return {"blackbox": bb, "records": bb.records, "anchors": bb.anchors,
            "run_root": run_root, "collisions": collisions, "grid": g}
