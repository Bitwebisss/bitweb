// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BIP-53: 64-byte transaction rejection tests.
// Adapted from bitcoin-inquisition bip54_tests.cpp (bip54_txsize case).
// Targets the altcoin fork based on Bitcoin Core (uses GetArgon2idPoWHash).

#include <boost/test/unit_test.hpp>

#include <addresstype.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <validation.h>

#include <memory>
#include <string>
#include <vector>

using namespace util::hex_literals;

BOOST_AUTO_TEST_SUITE(bip53_tests)

// The forbidden non-witness serialization size defined by BIP-53.
static constexpr uint32_t INVALID_TX_NONWITNESS_SIZE{64};

/**
 * Mine a regtest block: increment nNonce until PoW condition is satisfied.
 * This altcoin uses Argon2id PoW, so we call GetArgon2idPoWHash().
 */
static void MineRegtestBlock(CBlock& block, const Consensus::Params& params)
{
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetArgon2idPoWHash(), block.nBits, params)) {
        Assert(++block.nNonce);
    }
}

/**
 * Test the BIP-53 rule that rejects transactions whose non-witness serialized
 * size is exactly 64 bytes. Such transactions are exploitable in Merkle-tree
 * attacks. Coinbase transactions are exempt from this check.
 *
 * Each test case is submitted inside a valid (mined) block via AcceptBlock().
 * Invalid (64-byte) cases are expected to fail with reject reason "bad-txns-64byte".
 * Valid cases (63, 65 bytes, or witness-carrying sub-64) must be accepted.
 */
BOOST_AUTO_TEST_CASE(bip53_txsize)
{
    struct TestCase {
        CTransaction tx;
        bool         valid;
        std::string  comment;
    };
    std::vector<TestCase> cases;

    auto record = [&](const CMutableTransaction& mtx, bool valid, std::string comment) {
        cases.push_back({CTransaction{mtx}, valid, std::move(comment)});
    };

    // Base transaction: 1 input spending a fictitious outpoint, 1 empty output.
    // Non-witness size of this base is 60 bytes; padding scriptPubKey gives us control.
    CMutableTransaction base;
    base.vin.emplace_back(
        COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
    base.vout.emplace_back(0, CScript{});

    // -------------------------------------------------------------------------
    // Boundary cases
    // -------------------------------------------------------------------------

    // 63 bytes — valid (one below the forbidden size)
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE - 1);
        record(t, /*valid=*/true, "A 63-byte legacy transaction.");
    }

    // 60-byte non-witness with witness data attached — valid
    // The check only looks at non-witness size; an innocent small tx is fine
    // even when it carries a witness.
    {
        CMutableTransaction t{base};
        t.vin.back().scriptWitness.stack.resize(1); // one empty stack item
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE - 4);
        record(t, /*valid=*/true, "A 60-byte (non-witness) transaction that also carries a witness.");
    }

    // 64 bytes via scriptPubKey padding — invalid
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, /*valid=*/false, "A 64-byte legacy transaction (4 bytes in scriptPubKey).");
    }

    // 64 bytes via scriptSig bytes — invalid
    // Shows the check is purely size-based, not layout-based.
    {
        CMutableTransaction t{base};
        t.vout.back().nValue = MAX_MONEY;
        t.vin.back().scriptSig << std::vector<uint8_t>{0x42, 0x42, 0x42};
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, /*valid=*/false, "A 64-byte legacy transaction (3-byte scriptSig + MAX_MONEY nValue).");
    }

    // 65 bytes — valid (one above the forbidden size)
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4 << OP_8;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE + 1);
        record(t, /*valid=*/true, "A 65-byte legacy transaction.");
    }

    // 64-byte non-witness + witness data present — still invalid
    // A witness does NOT save a 64-byte-non-witness transaction.
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        t.vin.back().scriptWitness.stack.push_back({0x21, 0x32, 0x45, 0x57, 0x62, 0x81, 0x94, 0x12});
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)),    INVALID_TX_NONWITNESS_SIZE);
        BOOST_REQUIRE      (GetSerializeSize(TX_WITH_WITNESS(t)) > INVALID_TX_NONWITNESS_SIZE);
        record(t, /*valid=*/false,
               "A 64-byte Segwit transaction (witness present but non-witness size is still 64).");
    }

    // Semi-realistic 64-byte Segwit transaction: 1 Taproot-style input, 1 Pay-to-Anchor output.
    // The non-witness serialization is 64 bytes; the rule must still fire.
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey = GetScriptForDestination(PayToAnchor{});
        // Attach a fake 64-byte Schnorr signature as witness (so it *looks* like a real spend).
        auto sig{"5a78b5a14a2527feb02c08b8124e74c3b9bcc1bd3dba1fbfa87f1c930f28a46f"
                 "ea2bf375105dfd835e212c9127aad4976c46ef86be02edbb681e6f38f9a9e06f01"_hex_v_u8};
        t.vin.back().scriptWitness.stack.emplace_back(std::move(sig));
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, /*valid=*/false,
               "A 64-byte Segwit transaction (1 P2TR-style input, 1 P2A output).");
    }

    // -------------------------------------------------------------------------
    // Historical 64-byte transactions from the Bitcoin blockchain.
    // Source: Chris Stewart's BIP-53 list.
    // -------------------------------------------------------------------------
    static constexpr std::string_view kHistoricalHex[]{
        "0200000001deb98691723fa71260ffca6ea0a7bc0a63b0a8a366e1b585caad47fb269a2ce4"
        "01000000030251b201000000010000000000000000016a00000000",

        "01000000010d0afe3d74062ee60c0ec55579d691d8c8af5c04eb97b777157a21a8c5fb143d"
        "00000000035101b100000000010000000000000000016a01000000",

        "02000000011658a33df410379bb512206659910c9fbd0e50bfb732f7be9936558ff0369194"
        "01000000035101b201000000010000000000000000016a00000000",

        "02000000011a7a4cf262fb7e53e2e6e0b2ef8b763f6ee97d8681ca968d1938418d56e6c387"
        "00000000035101b201000000010000000000000000016a00000000",

        "01000000019222bbb054bb9f94571dfe769af5866835f2a97e883959fa757de4064bed8bca"
        "01000000035101b100000000010000000000000000016a01000000",
    };

    for (const auto hex : kHistoricalHex) {
        CMutableTransaction hist;
        Assert(DecodeHexTx(hist, std::string{hex}));
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(hist)) == INVALID_TX_NONWITNESS_SIZE,
            "Historical tx must be exactly 64 bytes non-witness");
        cases.push_back({
            CTransaction{hist},
            /*valid=*/false,
            "Historical 64-byte transaction " + hist.GetHash().ToString()
        });
    }

    // -------------------------------------------------------------------------
    // Execute every test case: wrap the tx in a mined regtest block and call
    // AcceptBlock(). Blocks with a 64-byte tx must be rejected; others accepted.
    // -------------------------------------------------------------------------
    RegTestingSetup test_setup{};
    auto& chainman{*test_setup.m_node.chainman};
    const Consensus::Params& params{chainman.GetConsensus()};

    // AcceptBlock() requires cs_main (returned by GetMutex()) to be held.
    LOCK(chainman.GetMutex());

    for (const auto& tc : cases) {
        // Build a block template on the current chain tip.
        CBlock block{
            node::BlockAssembler{chainman.ActiveChainstate(), /*mempool=*/nullptr, {}}
                .CreateNewBlock()
                ->block};

        // Append the transaction under test after the coinbase.
        block.vtx.push_back(MakeTransactionRef(tc.tx));

        // Recompute Merkle root and witness commitment so the block is
        // structurally coherent for the preliminary checks in AcceptBlock().
        node::RegenerateCommitments(block, chainman);

        // Find a valid proof-of-work nonce (Argon2id).
        MineRegtestBlock(block, params);

        const auto pblock{std::make_shared<const CBlock>(std::move(block))};
        BlockValidationState state;
        const bool accepted{chainman.AcceptBlock(
            pblock,
            state,
            /*ppindex=*/nullptr,
            /*fRequested=*/true,
            /*dbp=*/nullptr,
            /*fNewBlock=*/nullptr,
            /*min_pow_checked=*/true)};

        BOOST_CHECK_MESSAGE(accepted == tc.valid, tc.comment);

        if (!tc.valid) {
            // CheckTransaction() in tx_check.cpp emits "bad-txns-64byte".
            BOOST_CHECK_MESSAGE(
                state.GetRejectReason() == "bad-txns-64byte",
                "Wrong reject reason for: " + tc.comment
                    + " — got: \"" + state.GetRejectReason() + "\"");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()