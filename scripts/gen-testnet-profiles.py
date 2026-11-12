#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""Generates core/tests/vectors/testnet_profiles.json from ycash6's sources at one commit.

The fixture is what YEW's per-network consensus table (core/src/params.rs `Network::upgrades`,
the YED lifecycle column) is pinned against: every upgrade's branch id and activation height on
mainnet and on each testnet profile (`-testnetprofile=fast|slow|legacy`, ycash6
`src/chainparams.cpp` CTestNetFastParams / CTestNetSlowParams / CTestNetLegacyParams), and the YED
module's term classes, GRACE and CLAIM_DELAY (`src/yellowback/params.cpp` SetCommon /
TestFastParams). The node declares them; YEW only copies them (scripts/check-testnet-profiles.sh
regenerates and compares).

    gen-testnet-profiles.py <commit> <chainparams.cpp> <upgrades.cpp> <upgrades.h> <yellowback/params.cpp>

Standard library only. Prints the JSON on stdout.
"""
import json
import re
import sys

UPGRADES = [  # (chainparams index, upgrades.cpp strName, the fixture's name)
    ("UPGRADE_OVERWINTER", "Overwinter", "overwinter"),
    ("UPGRADE_SAPLING", "Sapling", "sapling"),
    ("UPGRADE_YCASH", "Ycash", "ycash"),
    ("UPGRADE_BLOSSOM", "Blossom", "blossom"),
    ("UPGRADE_HEARTWOOD", "Heartwood", "heartwood"),
    ("UPGRADE_CANOPY", "Canopy", "canopy"),
    ("UPGRADE_NU5", "NU5", "nu5"),
    ("UPGRADE_NU6", "NU6", "nu6"),
    ("UPGRADE_NU6_1", "NU6.1", "nu6_1"),
    ("UPGRADE_NU6_2", "NU6.2", "nu6_2"),
    ("UPGRADE_SHADOW", "Shadow", "shadow"),
    ("UPGRADE_VAULT", "Vault", "vault"),
]
NO = "Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT"


def die(msg):
    sys.exit(f"gen-testnet-profiles: {msg}")


def class_body(src, name):
    m = re.search(r"^class " + re.escape(name) + r"\b.*?^\};", src, re.S | re.M)
    if not m:
        die(f"class {name} not found")
    return m.group(0)


def func_body(src, signature):
    i = src.find(signature)
    if i < 0:
        die(f"{signature!r} not found")
    j = src.find("\n}\n", i)
    return src[i:j]


def heights(body):
    """{index: height or None} for every vUpgrades[...].nActivationHeight the body assigns."""
    out = {}
    for idx, value in re.findall(
        r"vUpgrades\[Consensus::(UPGRADE_\w+)\]\.nActivationHeight\s*=\s*([^;]+);", body
    ):
        value = " ".join(value.split())
        out[idx] = None if value == NO else int(value)
    return out


def branch_overrides(body, consts):
    out = {}
    for idx, value in re.findall(r"vUpgrades\[Consensus::(UPGRADE_\w+)\]\.nBranchId\s*=\s*(\w+);", body):
        out[idx] = consts[value] if value in consts else int(value, 16)
    return out


def network(branches, h, b=None):
    b = b or {}
    rows = []
    for idx, str_name, name in UPGRADES:
        if idx not in h:
            die(f"no activation height for {idx}")
        rows.append(
            {"name": name, "branch_id": "%08x" % b.get(idx, branches[str_name]), "height": h[idx]}
        )
    return rows


def yed(body, prefix, base=None):
    def num(field):
        m = re.search(r"\b" + prefix + r"\." + field + r"\s*=\s*(\d+);", body)
        return int(m.group(1)) if m else None

    out = dict(base or {})
    for field in ("grace", "claimDelay"):
        v = num(field)
        if v is not None:
            out[field] = v
    classes = [dict(c) for c in out.get("classes", [{}, {}, {}])]
    for i in range(3):
        for field in ("classMin", "classMax", "baseRatioBps", "earlyRedeemFeeBps"):
            v = num(field + r"\[" + str(i) + r"\]")
            if v is not None:
                classes[i][field] = v
    out["classes"] = classes
    return out


def main():
    if len(sys.argv) != 6:
        die("usage: gen-testnet-profiles.py <commit> <chainparams.cpp> <upgrades.cpp> <upgrades.h> <yellowback/params.cpp>")
    commit, cp_path, up_path, uh_path, yb_path = sys.argv[1:]
    cp, up, uh, yb = (open(p, encoding="utf-8").read() for p in (cp_path, up_path, uh_path, yb_path))

    consts = {k: int(v, 16) for k, v in re.findall(r"static const uint32_t (\w+_BRANCH_ID) = (0x[0-9a-fA-F]+);", uh)}
    branches = {}
    for bid, name in re.findall(r"\.nBranchId = (\w+),\s*\.strName = \"([^\"]+)\"", up):
        branches[name] = consts[bid] if bid in consts else int(bid, 16)

    main_h = heights(class_body(cp, "CMainParams"))
    test_h = heights(class_body(cp, "CTestNetParams"))
    # Mainnet and the re-forked testnet never activate the shadow upgrade (pow.cpp).
    main_h.setdefault("UPGRADE_SHADOW", None)
    test_h.setdefault("UPGRADE_SHADOW", None)
    fast_h = dict(test_h, **heights(class_body(cp, "CTestNetFastParams")))

    m = re.search(r"static const int TESTNET_SHADOW_SPLIT_HEIGHT = (\d+);", cp)
    if not m:
        die("TESTNET_SHADOW_SPLIT_HEIGHT not found")
    split = int(m.group(1))
    shadow_body = class_body(cp, "CTestNetShadowParams")
    if "SetShadowSplitHeight(TESTNET_SHADOW_SPLIT_HEIGHT)" not in shadow_body or "nSplitHeight + 1" not in shadow_body:
        die("CTestNetShadowParams no longer activates the shadow upgrade at TESTNET_SHADOW_SPLIT_HEIGHT + 1")
    shadow_h = dict(main_h, UPGRADE_SHADOW=split + 1)
    profiles = {}
    for profile, cls in (("slow", "CTestNetSlowParams"), ("legacy", "CTestNetLegacyParams")):
        body = class_body(cp, cls)
        profiles[profile] = (dict(shadow_h, **heights(body)), branch_overrides(body, consts))

    yb_common = func_body(yb, "void SetCommon(Params& p)")
    yb_fast = func_body(yb, "const Params& TestFastParams()")
    main_yed = yed(yb_common, "p")
    fast_yed = yed(yb_fast, "f", main_yed)

    out = {
        "source": {
            "repo": "boyfromcave/ycash6",
            "commit": commit,
            "files": ["src/chainparams.cpp", "src/consensus/upgrades.cpp", "src/consensus/upgrades.h", "src/yellowback/params.cpp"],
        },
        "networks": {
            "main": {"upgrades": network(branches, main_h), "yed": main_yed},
            "test-fast": {"upgrades": network(branches, fast_h), "yed": fast_yed},
            "test-slow": {
                "shadow_split_height": split,
                "upgrades": network(branches, *profiles["slow"]),
                "yed": main_yed,
            },
            "test-legacy": {
                "shadow_split_height": split,
                "upgrades": network(branches, *profiles["legacy"]),
            },
        },
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
