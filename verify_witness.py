#!/usr/bin/env python3
"""Executable backdating check: verify RFC 3161 witness tokens over checkpoints.

Closes the audit gap "the backdating defense is asserted, not checked": this
makes the witness tokens machine-checkable at two strengths:

  1. Pure python (stdlib only, works in any sandbox): parse each token's DER
     and check (a) its messageImprint is SHA-256 of the exact checkpoint bytes
     it claims to witness, and (b) extract its genTime. This proves the token
     commits to THESE checkpoint bytes at THAT time — everything except the
     TSA's own signature chain.
  2. Full chain (if the `openssl` binary is available): `openssl ts -verify`
     against the TSA's CA certificate, which additionally proves the token was
     signed by the TSA. Falls back gracefully when openssl is absent.

usage: verify_witness.py --witness-dir <dir>          (files: checkpoint.<stamp> + .tsr)
       verify_witness.py --checkpoint <file> --token <file.tsr> [--cafile ca.pem]

The two TSAs Anvil uses are independent of Armor: freetsa.org and DigiCert.
A backdated entry would need BOTH to have co-signed a false time in the past.
"""

import argparse
import binascii
import datetime
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

SHA256_OID = bytes.fromhex("608648016503040201")  # 2.16.840.1.101.3.4.2.1


def _der_walk(data):
    """Yield (tag, content) for every TLV in a DER blob, recursively."""
    stack = [data]
    while stack:
        buf = stack.pop()
        i = 0
        while i + 2 <= len(buf):
            tag = buf[i]
            length = buf[i + 1]
            j = i + 2
            if length & 0x80:
                n = length & 0x7F
                if n == 0 or j + n > len(buf):
                    break
                length = int.from_bytes(buf[j:j + n], "big")
                j += n
            if j + length > len(buf):
                break
            content = buf[j:j + length]
            yield tag, content
            if tag in (0x30, 0x31) or (tag & 0xE0) == 0xA0:  # constructed
                stack.append(content)
            i = j + length
        # note: iterative reversed-order recursion is fine — we only collect


def token_facts(tsr_bytes):
    """Extract (imprint_hex, gen_time) from an RFC 3161 response/token.

    The messageImprint is the OCTET STRING that follows the SHA-256 AlgorithmIdentifier
    inside the TSTInfo; genTime is the GeneralizedTime in the TSTInfo.
    """
    imprint = None
    gen_time = None
    tlvs = list(_der_walk(tsr_bytes))
    # find the TSTInfo eContent: an OCTET STRING that itself parses as a SEQUENCE
    # containing the sha256 OID; simplest robust approach: scan all OCTET STRINGs.
    for tag, content in tlvs:
        if tag == 0x04 and SHA256_OID in content:
            for t2, c2 in _der_walk(content):
                if t2 == 0x04 and len(c2) == 32:
                    imprint = binascii.hexlify(c2).decode()
                elif t2 == 0x18:  # GeneralizedTime
                    try:
                        gen_time = datetime.datetime.strptime(
                            c2.decode()[:14], "%Y%m%d%H%M%S").replace(
                            tzinfo=datetime.timezone.utc)
                    except ValueError:
                        pass
            if imprint:
                break
    return imprint, gen_time


def check_pair(cp_path, tsr_path, cafile=None, untrusted=None):
    cp_bytes = Path(cp_path).read_bytes()
    tsr = Path(tsr_path).read_bytes()
    want = hashlib.sha256(cp_bytes).hexdigest()
    imprint, gen_time = token_facts(tsr)
    if imprint is None:
        return False, "could not parse messageImprint"
    if imprint != want:
        return False, ("IMPRINT MISMATCH: token commits to %s..., checkpoint bytes "
                       "hash to %s..." % (imprint[:16], want[:16]))
    msg = "imprint OK (sha256 %s...), genTime %s" % (want[:16], gen_time)
    if cafile and shutil.which("openssl"):
        cmd = ["openssl", "ts", "-verify", "-data", str(cp_path),
               "-in", str(tsr_path), "-CAfile", str(cafile)]
        if untrusted:
            cmd += ["-untrusted", str(untrusted)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return False, msg + " — but TSA signature verification FAILED"
        msg += ", TSA signature chain OK"
    elif cafile:
        msg += " (openssl unavailable: TSA signature chain not checked)"
    return True, msg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--witness-dir")
    ap.add_argument("--checkpoint")
    ap.add_argument("--token")
    ap.add_argument("--cafile")
    ap.add_argument("--untrusted")
    args = ap.parse_args()

    pairs = []
    if args.witness_dir:
        wd = Path(args.witness_dir)
        for tsr in sorted(wd.rglob("*.tsr")):
            cp = tsr.with_suffix("")
            if cp.exists():
                ca = tsr.parent / "cacert.pem"
                crt = tsr.parent / "tsa.crt"
                pairs.append((cp, tsr, ca if ca.exists() else None,
                              crt if crt.exists() else None))
    elif args.checkpoint and args.token:
        pairs.append((args.checkpoint, args.token, args.cafile, args.untrusted))
    else:
        ap.error("--witness-dir or (--checkpoint and --token) required")

    failed = 0
    for cp, tsr, ca, crt in pairs:
        ok, msg = check_pair(cp, tsr, ca, crt)
        print("%s %s: %s" % ("OK  " if ok else "FAIL", Path(tsr).name, msg))
        failed += not ok
    if failed:
        raise SystemExit("FAIL: %d token(s) failed" % failed)
    print("all %d token(s) commit to their checkpoint bytes" % len(pairs))


if __name__ == "__main__":
    main()
