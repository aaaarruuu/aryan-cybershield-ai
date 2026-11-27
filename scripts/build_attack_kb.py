"""Convert MITRE ATT&CK enterprise STIX JSON into a compact markdown knowledge file for the RAG corpus.

Usage: python -I scripts/build_attack_kb.py <enterprise-attack.json> <output.md>
Source: https://github.com/mitre/cti (MITRE ATT&CK is (c) The MITRE Corporation, used under its terms of use).
The input file is treated as untrusted data: only whitelisted fields are read and text is truncated.
"""
import json
import re
import sys

MAX_DESC = 700


def clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def main(src: str, dst: str) -> None:
    with open(src, encoding="utf-8") as f:
        objs = json.load(f)["objects"]
    techniques = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tactics = ", ".join(p["phase_name"] for p in o.get("kill_chain_phases", []))
        desc = clean(o.get("description", ""))[:MAX_DESC]
        techniques.append((ext["external_id"], o["name"], tactics, desc))
    techniques.sort()
    with open(dst, "w", encoding="utf-8") as out:
        out.write("# MITRE ATT&CK Enterprise Techniques (summary)\n\n")
        out.write("Source: MITRE ATT&CK (github.com/mitre/cti). Descriptions truncated.\n\n")
        for tid, name, tactics, desc in techniques:
            out.write(f"## {tid} {name}\nTactics: {tactics}\n{desc}\n\n")
    print(f"wrote {len(techniques)} techniques to {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
