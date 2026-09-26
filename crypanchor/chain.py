"""Bitcoin anchoring helpers: OP_RETURN payload, Electrum export, explorer lookup.

Payload (36 bytes): b"CRA1" || run_root (32 bytes). On-chain script:
OP_RETURN (0x6a) PUSH36 (0x24) <payload>  -> 38-byte script, 47-byte output.
"""
import json
import urllib.request
from typing import Any, Dict, Optional

MAGIC = b"CRA1"
EXPLORERS = {
    "testnet4": ["https://mempool.space/testnet4/api"],
    "testnet": ["https://mempool.space/testnet/api", "https://blockstream.info/testnet/api"],
    "mainnet": ["https://mempool.space/api", "https://blockstream.info/api"],
}


def payload(run_root: bytes) -> bytes:
    assert len(run_root) == 32
    return MAGIC + run_root


def electrum_paytomany(run_root: bytes, change_address: Optional[str] = "YOUR_TESTNET_ADDRESS",
                       amount_btc: str = "0.00001") -> str:
    """Text for Electrum 'Pay to many' (Tools > Pay to many). Replace
    YOUR_TESTNET_ADDRESS with one of your own wallet addresses; Electrum needs
    one non-zero output next to the zero-value OP_RETURN output. Pass
    change_address=None to emit the OP_RETURN line only."""
    lines = [f"script(OP_RETURN {payload(run_root).hex()}),0"]
    if change_address:
        lines.append(f"{change_address},{amount_btc}")
    return "\n".join(lines) + "\n"


def extract_run_root(tx: Dict[str, Any]) -> Optional[bytes]:
    """Find a CrypAnchor OP_RETURN in an Esplora/mempool.space tx JSON."""
    for out in tx.get("vout", []):
        spk = bytes.fromhex(out.get("scriptpubkey", ""))
        if len(spk) >= 2 and spk[0] == 0x6A and spk[1] == 0x24 and spk[2:6] == MAGIC:
            return spk[6:38]
    return None


def _get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "crypanchor"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode()


def fetch_tx(txid: str, network: str = "testnet4") -> Dict[str, Any]:
    last_err: Exception = RuntimeError("no explorer configured")
    for base in EXPLORERS[network]:
        try:
            tx = json.loads(_get(f"{base}/tx/{txid}"))
            tip = int(_get(f"{base}/blocks/tip/height"))
            st = tx.get("status", {})
            tx["confirmations"] = (tip - st["block_height"] + 1) if st.get("confirmed") else 0
            tx["explorer"] = base
            return tx
        except Exception as e:  # try next explorer
            last_err = e
    raise last_err


def onchain_run_root(txid: str, network: str = "testnet4", min_conf: int = 1) -> bytes:
    tx = fetch_tx(txid, network)
    if tx["confirmations"] < min_conf:
        raise RuntimeError(f"transaction has {tx['confirmations']} confirmations, need {min_conf}")
    root = extract_run_root(tx)
    if root is None:
        raise RuntimeError("no CrypAnchor OP_RETURN output in transaction")
    return root
