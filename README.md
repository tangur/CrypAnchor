AAB — Accountable Agents with Bitcoin Anchors (Testnet Demo)

This project demonstrates verifiable accountability for autonomous AI agents.
Agents commit to their decisions off-chain and anchor a Merkle root on Bitcoin (testnet).
Any post-hoc change to agent logs becomes cryptographically detectable.

1. Run the demo

From the repository root:
cd aab_v1
python examples/gridworld_demo.py

When it finishes, you will see:

HONEST VERIFY == PASS

ATTACK VERIFY == FAIL

And a line like:

last merkle_root: <64-hex>

This merkle_root is the value that will be anchored on Bitcoin testnet.

2. Anchor the Merkle root on Bitcoin testnet (Electrum)
Step 1 — Open Electrum in testnet mode

Open Electrum and create or open a testnet wallet.
Your receive address must start with tb1.

Step 2 — Copy a receive address

Electrum → Receive tab → copy a tb1... address.

Step 3 — Create OP_RETURN transaction

Electrum → Send tab → click Pay to Many
Paste the following (replace placeholders):

script(OP_RETURN <MERKLE_ROOT>),0
<YOUR_TB1_ADDRESS>,0.00001

Where:

<MERKLE_ROOT> is the value printed by the demo

<YOUR_TB1_ADDRESS> is your Electrum receive address

Then click:
Send → Sign → Broadcast

Step 4 — Confirm OP_RETURN

Electrum → History → open the transaction → Outputs

You should see:

OP_RETURN <merkle_root>

a small amount sent back to your tb1... address

The transaction ID (txid) is your public, timestamped proof.

3. Generated files

After running the demo:

anchors_demo.jsonl — Merkle root commitments

logs_demo.jsonl — agent decision logs (off-chain)

4. One-sentence explanation (for judges)

We store only a 32-byte Merkle root on Bitcoin testnet; any post-hoc change to agent decisions causes verification to fail.