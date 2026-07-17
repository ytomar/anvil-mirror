#!/usr/bin/env python3
"""Offline Anvil log verifier.

Verifies the log from its static artifacts alone — checkpoint, entry
bundles, and the log's public verifier key. No anvild, no Armor systems,
no Go. This is the reference implementation of "checking any claim is
nearly free for any party."

What it checks:
  1. The checkpoint's Ed25519 note signature (golang.org/x/mod/sumdb/note format).
  2. That the RFC 6962 Merkle root rebuilt from the sealed entries equals the
     signed root — i.e. the published entries ARE the tree the log committed to.
  3. Every entry's claimant signature, against registrations found in the log
     itself (the claimant population is part of the log).
  4. Per-claimant sequence density: no gaps, no denominator games.

v0 rebuilds the full tree from entry bundles, which is exact and honest at
Phase-0 scale; proof-based spot verification replaces the full rebuild when
the tree is large.

usage: verify.py --log-dir <dir> --vkey-file <file>
       verify.py --base-url http://host/log --vkey-file <file>
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ENTRY_BUNDLE_WIDTH = 256


# ---------- artifact access (files or URLs; static either way) ----------

class Source:
    def __init__(self, log_dir=None, base_url=None):
        self.log_dir = Path(log_dir) if log_dir else None
        self.base_url = base_url.rstrip("/") if base_url else None

    def read(self, rel):
        if self.log_dir:
            p = self.log_dir / rel
            return p.read_bytes() if p.exists() else None
        # Explicit UA: CDNs (incl. Cloudflare bot protection) 403 the default
        # Python-urllib agent. Transport detail only — checks are unchanged.
        req = urllib.request.Request(
            f"{self.base_url}/{rel}",
            headers={"User-Agent": "anvil-verify/0 (+https://anvil.yourarmor.ai/verify)"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise


def tile_path(index):
    """c2sp.org/tlog-tiles path encoding: base-1000 groups, x-prefixed but the last."""
    digits = []
    while True:
        digits.append(index % 1000)
        index //= 1000
        if index == 0:
            break
    digits.reverse()
    parts = [f"x{d:03d}" for d in digits[:-1]] + [f"{digits[-1]:03d}"]
    return "/".join(parts)


def read_entry_bundle(src, bundle_index, width):
    rel = f"tile/entries/{tile_path(bundle_index)}"
    data = src.read(rel)
    if data is None and width < ENTRY_BUNDLE_WIDTH:
        data = src.read(f"{rel}.p/{width}")
    if data is None:
        raise SystemExit(f"FAIL: missing entry bundle {rel} (width {width})")
    entries, off = [], 0
    while off < len(data):
        (n,) = struct.unpack(">H", data[off:off + 2])
        off += 2
        entries.append(data[off:off + n])
        off += n
    return entries


# ---------- RFC 6962 tree math ----------

def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()

def node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def merkle_root(hashes):
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(merkle_root(hashes[:k]), merkle_root(hashes[k:]))


# ---------- sumdb/note checkpoint verification ----------

def parse_vkey(vkey):
    name, _hash, key_b64 = vkey.strip().split("+", 2)
    key_data = base64.b64decode(key_b64)
    if key_data[0] != 0x01:
        raise SystemExit(f"FAIL: vkey algorithm {key_data[0]} is not Ed25519")
    key_hash = hashlib.sha256(name.encode() + b"\n" + key_data).digest()[:4]
    return name, key_hash, Ed25519PublicKey.from_public_bytes(key_data[1:])

def verify_checkpoint(note_bytes, vkey):
    name, key_hash, pubkey = parse_vkey(vkey)
    text, _, sig_block = note_bytes.partition(b"\n\n")
    msg = text + b"\n"
    for line in sig_block.splitlines():
        line = line.decode()
        if not line.startswith("— ") and not line.startswith("- "):
            continue
        _, sig_name, sig_b64 = line.split(" ", 2)
        if sig_name != name:
            continue
        raw = base64.b64decode(sig_b64)
        if raw[:4] != key_hash:
            continue
        try:
            pubkey.verify(raw[4:], msg)
        except InvalidSignature:
            raise SystemExit("FAIL: checkpoint signature INVALID")
        origin, size, root_b64 = msg.decode().splitlines()[:3]
        return origin, int(size), base64.b64decode(root_b64)
    raise SystemExit(f"FAIL: no signature by {name} on checkpoint")


# ---------- entry-level verification ----------

def verify_entries(entries):
    """Claimant signatures + seq density, using registrations from the log itself."""
    keys, next_seq, problems = {}, {}, []
    for i, raw in enumerate(entries):
        env = json.loads(raw)
        body = base64.b64decode(env["body_b64"])
        sig = base64.b64decode(env["sig_b64"])
        parsed = json.loads(body)
        cid = env["claimant_id"]

        if env["kind"] == "claimant_registration":
            pub = base64.b64decode(parsed["public_key_b64"])
        elif cid in keys:
            pub = keys[cid]
        else:
            problems.append(f"leaf {i}: {cid} not registered before use")
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, body)
        except InvalidSignature:
            problems.append(f"leaf {i}: claimant signature INVALID for {cid}")
            continue

        if env["kind"] == "claimant_registration":
            if cid in keys:
                problems.append(f"leaf {i}: duplicate registration for {cid}")
            keys[cid] = pub
            next_seq.setdefault(cid, 0)
        else:
            want = next_seq.get(cid, 0)
            if parsed["seq"] != want:
                problems.append(f"leaf {i}: {cid} seq {parsed['seq']}, expected {want} — GAP")
            next_seq[cid] = parsed["seq"] + 1
    return problems, next_seq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", help="local log directory (static files)")
    ap.add_argument("--base-url", help="base URL serving checkpoint + tiles")
    ap.add_argument("--vkey-file", required=True, help="log verifier key file")
    args = ap.parse_args()
    if not args.log_dir and not args.base_url:
        ap.error("one of --log-dir or --base-url is required")

    src = Source(args.log_dir, args.base_url)
    vkey = Path(args.vkey_file).read_text()

    cp = src.read("checkpoint")
    if cp is None:
        raise SystemExit("FAIL: no checkpoint found")
    origin, size, want_root = verify_checkpoint(cp, vkey)
    print(f"checkpoint: origin={origin} size={size} sig=OK")

    entries = []
    full, rem = divmod(size, ENTRY_BUNDLE_WIDTH)
    for b in range(full):
        entries.extend(read_entry_bundle(src, b, ENTRY_BUNDLE_WIDTH))
    if rem:
        entries.extend(read_entry_bundle(src, full, rem)[:rem])
    entries = entries[:size]
    if len(entries) != size:
        raise SystemExit(f"FAIL: expected {size} entries, found {len(entries)}")

    got_root = merkle_root([leaf_hash(e) for e in entries])
    if got_root != want_root:
        raise SystemExit(
            f"FAIL: root mismatch\n  signed:  {base64.b64encode(want_root).decode()}\n"
            f"  rebuilt: {base64.b64encode(got_root).decode()}")
    print(f"merkle root: OK ({size} entries rebuild to the signed root)")

    problems, seqs = verify_entries(entries)
    for p in problems:
        print(f"  PROBLEM: {p}")
    for cid, n in sorted(seqs.items()):
        print(f"  {cid}: {n} sealed entr{'y' if n == 1 else 'ies'}, seq dense")
    if problems:
        raise SystemExit("FAIL: entry-level problems found")
    print("VERIFIED: log is internally consistent, signed, and gap-free")


if __name__ == "__main__":
    main()
