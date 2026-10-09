#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or https://www.opensource.org/licenses/mit-license.php .
"""The in-term templates for core/tests/vectors/templates.json (the workspace's
docs/plans/yellowback-in-term-claims-plan.md, IT-1, IT-2, IT-9), from a running in-term devnet.

`yellowback-devnet vectors` (the node's devnet tool, wallet plan W0c) writes transparent.json,
addresses.json, params.json and templates.json with a MINT, a TRANSFER and a REDEEM at the
vault's lockHeight. This script adds what that procedure has no step for, by the same means
(node 0's wallet builds and broadcasts, the tool's own helpers mine, confirm and record):

  earlyRedeem   a second class-A MINT (`earlyRedeemMint`, with its carrier when ARMED) and its
                REDEEM before lockHeight: yed_estimateredeem first (`estimate`), then yed_redeem;
                the pool-payee output carries FEE-1 + the early-redeem fee (IT-9).
  claim         a class-C MINT of node 0 (`claimMint`, 240 blocks), a -80 % price shock, mining
                until yed_listclaimable reports it claimable in term (`claimableRow`), then
                yed_claim of it by node 0 itself (IT-2 (a)), with its carrier when ARMED.

Every record has the shape `vectors` uses ({hex, txid, decoded, txinfo, payloadHex,
payloadDecoded, result}); every transaction was accepted by the node and mined. The shock leaves
the devnet halted for further mints: run this last, then `down --wipe`.

    yellowback-devnet vectors --dir DIR --out OUT --seed 1
    scripts/vectors-in-term.py --tool <ycash-dd>/contrib/yellowback/devnet/yellowback-devnet --dir DIR --out OUT
    cp OUT/{transparent,addresses,templates,params}.json core/tests/vectors/

Run it with the workspace venv's Python.
"""
import argparse
import json
import os
import sys
import types


def load_tool(path):
    """The devnet tool as a module (it is a script without a .py name)."""
    module = types.ModuleType("yellowback_devnet")
    module.__file__ = os.path.abspath(path)
    with open(path) as f:
        code = compile(f.read(), module.__file__, "exec")
    sys.argv = [module.__file__]
    exec(code, module.__dict__)                      # main() only runs under __name__ == "__main__"
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tool", required=True, help="the in-term node's contrib/yellowback/devnet/yellowback-devnet")
    parser.add_argument("--dir", required=True, help="the devnet directory")
    parser.add_argument("--out", required=True, help="the directory holding the `vectors` output (templates.json is updated)")
    args = parser.parse_args()
    t = load_tool(args.tool)
    from test_framework.yellowback_util import CLASS_RANGES, EARLY_REDEEM_FEE_BPS, MIN_MINT  # on sys.path via the tool

    directory = os.path.abspath(args.dir)
    state = t.load(directory)
    node = t.rpc(state, t.USER, timeout=300)
    mine = t._pool_miner(state)
    path = os.path.join(os.path.abspath(args.out), "templates.json")
    with open(path) as f:
        templates = json.load(f)
    armed = bool(templates.get("armed"))

    def fresh_prices():
        for _ in range(80):
            if int(node.yed_getprice(node.getblockcount() - t.REF_LAG).get("pMint") or 0) > 0:
                return
            mine(1)

    def pool_fresh():
        # The agents attest at tick heights only; a chain that stopped between ticks leaves the
        # pool stale, so mine (as the heartbeat would) until it is fresh again.
        for _ in range(12):
            try:
                return t.wait_pool_fresh(state, timeout=8)
            except RuntimeError:
                mine(1)
        return t.wait_pool_fresh(state)

    def mint(lock_blocks, key):
        fresh_prices()
        if armed:
            pool_fresh()
        m = t._two_step(lambda: node.yed_mint(MIN_MINT, lock_blocks, "", "", True), mine)
        templates[key] = t._template(node, m["txid"], m, mine)
        if m.get("carrierTxid"):
            hex_ = node.gettransaction(m["carrierTxid"])["hex"]
            templates[key + "Carrier"] = {"hex": hex_, "txid": m["carrierTxid"], "decoded": node.decoderawtransaction(hex_)}
        print("%s %s (class %s, refHeight %s, lockHeight %s)" % (key, m["txid"], m.get("termClass"), m.get("refHeight"), m.get("lockHeight")))
        return m

    # 1. An early redeem (IT-9): mint class A, redeem it in term at once.
    m = mint(CLASS_RANGES["A"][0], "earlyRedeemMint")
    estimate = node.yed_estimateredeem(m["txid"])
    assert estimate["early"] and estimate["canRedeem"], estimate
    assert estimate["earlyRedeemFeeZat"] == m["collateralZat"] * EARLY_REDEEM_FEE_BPS[0] // 10_000, estimate
    redeem, attempts = t._with_retry(lambda: node.yed_redeem(m["txid"]))
    mine(1)
    record = t._template(node, redeem["txid"], redeem, mine)
    record["estimate"] = estimate
    record["redeemAttempts"] = attempts
    assert record["txinfo"]["height"] < int(m["lockHeight"]), "the early redeem was mined after lockHeight"
    assert redeem["earlyRedeemFeeZat"] == estimate["earlyRedeemFeeZat"] > 0, redeem
    templates["earlyRedeem"] = record
    print("earlyRedeem %s at %s < lockHeight %s (early fee %s zat)" % (redeem["txid"], record["txinfo"]["height"], m["lockHeight"], redeem["earlyRedeemFeeZat"]))

    # 2. An in-term claim (IT-2 (a)): mint class C, shock the price, claim it once it is claimable.
    m = mint(240, "claimMint")
    t.apply_price(state, (t.Decimal(t.read_mock(directory) or state["price_usd"]) * t.Decimal("0.2")).quantize(t.Decimal("0.000001")))
    row = None
    for _ in range(400):
        mine(1)
        rows = node.yed_listclaimable()
        row = next((x for x in rows if x.get("vault") == m["txid"] + ":0" and x.get("claimable")), None)
        if row:
            break
        assert node.getblockcount() < int(m["lockHeight"]), "the claim target left its term unclaimable"
    assert row, "the vault never became claimable"
    print("claimable in term at %d: %s" % (node.getblockcount(), json.dumps(row)))
    if armed:
        pool_fresh()
    claim = t._two_step(lambda: node.yed_claim(m["txid"], "", "", True), mine)
    record = t._template(node, claim["txid"], claim, mine)
    record["claimableRow"] = row
    if claim.get("carrierTxid"):
        hex_ = node.gettransaction(claim["carrierTxid"])["hex"]
        templates["claimCarrier"] = {"hex": hex_, "txid": claim["carrierTxid"], "decoded": node.decoderawtransaction(hex_)}
    assert record["txinfo"]["height"] < int(m["lockHeight"]), "the claim was mined after lockHeight"
    templates["claim"] = record
    print("claim %s at %s < lockHeight %s (path %s)" % (claim["txid"], record["txinfo"]["height"], m["lockHeight"], claim.get("claimPath")))

    with open(path, "w") as f:
        json.dump(templates, f, indent=1, default=str)
    print("templates.json: earlyRedeem and claim added")
    return 0


if __name__ == "__main__":
    sys.exit(main())
