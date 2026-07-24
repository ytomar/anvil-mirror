# How to audit the Anvil log (machine-readable edition)

Current tree size: **10** · root `VD6iTzPeD9AyEaB99eDqGqI8LTCjRmA/3vj4deODbSQ=` · origin `anvil.yourarmor.ai/log/v0`
Generated 2026-07-24T20:17:03Z. HTML twin: https://anvil.yourarmor.ai/verify

You are invited to be adversarial. Everything below is executable without
permission from the operator.

## 0. Freshness protocol (do this first)

1. GET https://anvil.yourarmor.ai/log/v0/checkpoint — plain text; line 2 is the live tree size N.
2. GET https://anvil.yourarmor.ai/pack/N.json (substitute N). This URL did not exist before
   the tree reached size N, so your fetch cache cannot serve it stale. Do NOT
   trust a cached fixed-path /pack.json.
3. Cross-check `generated_at` against the mirror: https://raw.githubusercontent.com/ytomar/anvil-mirror/main/pack.json
4. Only if the versioned fetch itself lags the checkpoint is staleness the
   operator's defect — say so and audit the live tree.

## 1. Read-audit (no tools beyond fetch)

- Per claimant, claims' `body.seq` must be exactly 0,1,2,… No gaps.
- `checkpoint.tree_size` == length of `entries`.
- Every claim leaf covered by a witness token (`witness.tokens[*].tree_size > leaf_index`)
  whose `time_utc` precedes the claim's horizon.
- Every claim's asserted numbers must recompute from its exhibit arrays.
- Limits: these check internal consistency only; a fabricated pack could pass. Continue below.

## 2. Crypto-audit (write your own verifier — do not trust ours)

Entry bundles (repeated `[uint16-BE length][entry bytes]`, leaves in order):
- https://anvil.yourarmor.ai/log/v0/tile/entries/000.p/10 (mirror: https://raw.githubusercontent.com/ytomar/anvil-mirror/main/log/tile/entries/000.p/10)

- vkey (https://anvil.yourarmor.ai/log.vkey): format `name+hash+base64(0x01 || 32-byte Ed25519 key)`.
- Checkpoint signature: message = checkpoint text through the blank line
  (trailing newline included); signature line = `— name base64(4-byte keyhash || 64-byte sig)`;
  keyhash = first 4 bytes of `SHA256(name + "\n" + keybytes)`.
- Merkle root (RFC 6962): `leaf = SHA256(0x00 || entry)`, `node = SHA256(0x01 || l || r)`,
  split at the largest power of two < n. Must equal checkpoint line 3.
- Entry signatures: each entry is JSON `{kind, claimant_id, body_b64, sig_b64}`;
  verify Ed25519 over the decoded body bytes against the registration key.
- Exhibits: sha256 of the bytes at each claim's `exhibit_url` must equal the
  sealed `resolution_spec.oracle.exhibit_sha256`.
- Reference implementation to cross-read (not required): https://anvil.yourarmor.ai/verify.py

## 3. Witnessed time (RFC 3161, both TSAs)

Tokens indexed in `pack.witness.tokens` (absolute URLs). Two strengths:

1. Stdlib: parse the token DER; `messageImprint == SHA256(checkpoint bytes)`; read genTime.
2. Full chain, exact cert paths (no guessing):
- `witness/cacert.pem` (root CA (-CAfile)): https://anvil.yourarmor.ai/witness/cacert.pem (mirror: https://raw.githubusercontent.com/ytomar/anvil-mirror/main/witness/cacert.pem)
- `witness/tsa.crt` (TSA signing cert (-untrusted)): https://anvil.yourarmor.ai/witness/tsa.crt (mirror: https://raw.githubusercontent.com/ytomar/anvil-mirror/main/witness/tsa.crt)
- `witness/digicert/cacert.pem` (root CA (-CAfile)): https://anvil.yourarmor.ai/witness/digicert/cacert.pem (mirror: https://raw.githubusercontent.com/ytomar/anvil-mirror/main/witness/digicert/cacert.pem)

```
freetsa:  openssl ts -verify -data <checkpoint.STAMP> -in <checkpoint.STAMP.tsr> \
            -CAfile cacert.pem -untrusted tsa.crt
digicert: openssl ts -verify -data <checkpoint.STAMP> -in <checkpoint.STAMP.tsr> \
            -CAfile digicert/cacert.pem
```

## 4. Append-only proof

Earliest witnessed checkpoint at each past tree size (rebuild the RFC 6962 root
over the first N current entries; it must equal the archived root — that proves
strict-prefix, i.e. nothing edited or deleted):
- size 2: witnessed 2026-07-16T09:48:08Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260716T094807Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260716T094807Z
- size 3: witnessed 2026-07-17T11:22:17Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260717T112216Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260717T112216Z
- size 4: witnessed 2026-07-17T11:35:31Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260717T113530Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260717T113530Z
- size 5: witnessed 2026-07-17T11:50:44Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260717T115043Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260717T115043Z
- size 6: witnessed 2026-07-24T09:03:09Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260724T090309Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260724T090309Z
- size 7: witnessed 2026-07-24T10:01:59Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260724T100158Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260724T100158Z
- size 10: witnessed 2026-07-24T11:52:06Z (freetsa.org) — token https://anvil.yourarmor.ai/witness/checkpoint.20260724T115206Z.tsr, checkpoint bytes https://anvil.yourarmor.ai/witness/checkpoint.20260724T115206Z

## 5. Independent benchmark

Rebuild the benchmark leg from public data the operator does not control
(e.g. https://api.mfapi.in/mf/120716 — UTI Nifty 50 Index Fund NAV) and compare
against each exhibit's benchmark array over the full window. Sealed resolutions
carry `oracle_reading.official_snapshot` (sha256 + raw bytes URL) so you can
certify exactly what the grader saw.

## 6. Identity (report as "anchored", never "proven")

The log binds keys to claimant IDs. Out-of-log anchors you can fetch:
- Wayback history of the board: https://web.archive.org/web/2026*/anvil.yourarmor.ai/
- Mirror commit history: https://github.com/ytomar/anvil-mirror/commits/main
- Profiles: https://anvil.yourarmor.ai/founders

## 7. Reporting format

1. Verdict banner: RECORD HOLDS / RECORD FAILS / HOLDS WITH LIMITS + one sentence of substance.
2. One row per check: what, how, pass/fail/could-not-check.
3. Limits: what your environment prevented and which instrument closes it.
4. The numbers: tree size, root, claim count + statuses, latest witness time.

## What failure looks like

An edited entry breaks the root (§2). A deleted entry breaks seq density (§1).
A backdated entry contradicts two TSAs and the archive (§3). A silent miss shows
as OVERDUE — there is no sixth state and no discretionary escape hatch.
