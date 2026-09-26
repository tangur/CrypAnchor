import json
from dataclasses import asdict
from typing import List
from .core import AnchorRecord

class JsonlAnchorStore:
    def __init__(self, path: str = "anchors.jsonl", truncate: bool = False):
        self.path = path
        if truncate:
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("")

    def append(self, ar: AnchorRecord) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(ar), sort_keys=True) + "\n")

    def read_all(self) -> List[AnchorRecord]:
        out: List[AnchorRecord] = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        d = json.loads(line)
                        out.append(AnchorRecord(**d))
        except FileNotFoundError:
            pass
        return out
