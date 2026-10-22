#!/usr/bin/env python3
"""pack-vectors.py <ceremony dir> <out.tar.gz>

Packs the real-key test vectors from a finished ceremony: every circuit's genesis
zkey, contribution zkeys, final zkey, vk.json and r1cs, the ceremony's ceremony.json,
genesis/init.json (the pins the genesis keys are checked against) and transcript.json
(the chain the ceremony repo's attack suites walk), plus a provenance README. The archive is byte-for-byte
reproducible (sorted entries, fixed metadata, gzip without a timestamp), so its
SHA-256 can be pinned and anyone can rebuild it from the same ceremony.
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

CIRCUITS = ("shield", "unshield", "transfer")


def entries(ceremony: Path) -> list[tuple[str, bytes]]:
    files = []
    for c in CIRCUITS:
        files.append((f"genesis/{c}.genesis.zkey", ceremony / "genesis" / f"{c}.genesis.zkey"))
        files.append((f"final/{c}.final.zkey", ceremony / "final" / f"{c}.final.zkey"))
        files.append((f"r1cs/{c}.r1cs", ceremony / "r1cs" / f"{c}.r1cs"))
        files.append((f"final/{c}.vk.json", ceremony / "final" / f"{c}.vk.json"))
        for z in sorted((ceremony / "contributions" / c).glob("*.zkey"), key=lambda p: int(p.stem)):
            files.append((f"contributions/{c}/{z.name}", z))
    files.append(("ceremony.json", ceremony / "ceremony.json"))
    files.append(("genesis/init.json", ceremony / "genesis" / "init.json"))
    files.append(("transcript.json", ceremony / "transcript.json"))
    out = [(name, path.read_bytes()) for name, path in files]

    raw = (ceremony / "ceremony.json").read_bytes()
    a = json.loads(raw)
    src = a["circuits_source"]
    lines = [
        f"Test vectors: ceremony {a['ceremony_id']} ({a['network']}).",
        "A rehearsal: these keys must never be used for mainnet.",
        "",
        f"ceremony.json SHA-256: {hashlib.sha256(raw).hexdigest()}",
        f"Circuits: {src['repo']} {src['tag']} @ {src['commit']}",
        f"Minimum contributions: {a['min_contributions']}",
        f"Beacon: drand {a['beacon']['network']} round {a['beacon']['round']},"
        f" 2^{a['beacon']['iterations_exp']} iterations",
        "",
        "Files (SHA-256):",
    ]
    lines += [f"  {hashlib.sha256(data).hexdigest()}  {name}" for name, data in sorted(out)]
    out.append(("README.txt", ("\n".join(lines) + "\n").encode()))
    return sorted(out)


def pack(ceremony: Path, dest: Path) -> None:
    buf = io.BytesIO()
    root = ceremony.name
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in entries(ceremony):
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with open(dest, "wb") as f, gzip.GzipFile(fileobj=f, mode="wb", mtime=0, filename="") as gz:
        gz.write(buf.getvalue())
    print(f"{hashlib.sha256(dest.read_bytes()).hexdigest()}  {dest}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    pack(Path(sys.argv[1]), Path(sys.argv[2]))
