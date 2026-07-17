# Anvil log mirror

Read-only mirror of the [Anvil transparency log](https://anvil.yourarmor.ai) —
Armor's append-only, externally witnessed record of falsifiable claims.
Updated hourly. **The log's own domain is authoritative**; this mirror exists so
sandboxed auditors (e.g. AI agents that can only reach raw.githubusercontent.com)
can run the full cryptographic audit. A divergent mirror is detectable: every
artifact is bound by the checkpoint signature and Merkle root.

Layout: `log/` (checkpoint + tlog tiles) · `log.vkey` · `verify.py` (offline
verifier) · `verify_witness.py` (RFC 3161 backdating check) · `witness/`
(TSA tokens + roots) · `pack.json` / `pack.txt` (decoded rendering) ·
`exhibits/` (bytes sealed claims commit to).

Verify from this mirror alone:

    BASE=https://raw.githubusercontent.com/ytomar/anvil-mirror/main
    curl -fsSO $BASE/verify.py
    python3 verify.py --base-url $BASE/log --vkey-file <(curl -fsS $BASE/log.vkey)

Audit instructions (written for humans and AI models): https://anvil.yourarmor.ai/verify
