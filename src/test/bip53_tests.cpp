// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Adapted BIP54 64-byte transaction tests for altcoin fork (based on Bitcoin Core 0.30.2).
// Original source: bitcoin-inquisition bip54_tests.cpp (bip54_txsize test case).

#include <boost/test/unit_test.hpp>

#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <validation.h>

#include <memory>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(bip54_txsize_tests)

// Non-witness serialization size that is rejected by BIP54.
static constexpr uint32_t INVALID_TX_NONWITNESS_SIZE{64};

/**
 * Mine a regtest block by incrementing nNonce until PoW is satisfied.
 * Uses GetArgon2idPoWHash() as required by this altcoin fork.
 */
static void MineRegtestBlock(CBlock& block, const Consensus::Params& params)
{
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetArgon2idPoWHash(), block.nBits, params)) {
        Assert(++block.nNonce);
    }
}

/**
 * Test the BIP54 rule rejecting transactions that are exactly 64 bytes when
 * serialized without witness data. Such transactions can create ambiguity in
 * the Merkle tree (CVE-2012-2459 variant).
 *
 * The check lives in CheckTransaction() (tx_check.cpp) and fires with the
 * reject reason "bad-txns-64byte". Coinbase transactions are exempt.
 *
 * The test exercises:
 *  - Boundary cases: 63, 64, 65 bytes (legacy and segwit).
 *  - Historical 64-byte transactions from the real blockchain.
 */
BOOST_AUTO_TEST_CASE(bip54_txsize)
{
    // -----------------------------------------------------------------------
    // Build test vectors
    // -----------------------------------------------------------------------

    struct TestCase {
        CTransaction tx;
        bool         valid;
        std::string  comment;
    };
    std::vector<TestCase> test_cases;

    // Helper lambda to record a case once we have verified the expected size.
    auto record = [&](const CMutableTransaction& mtx, bool valid, std::string comment) {
        test_cases.push_back({CTransaction{mtx}, valid, std::move(comment)});
    };

    // Craft a base transaction we will copy-and-tweak for each case.
    // One input spending a fictitious outpoint, one empty output.
    // Base non-witness size is 60 bytes, so small script additions control the total.
    CMutableTransaction base_tx;
    base_tx.vin.emplace_back(
        COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
    base_tx.vout.emplace_back(0, CScript{});

    // --- Case 1: 63 bytes — valid (one below the forbidden size) ---
    {
        CMutableTransaction t{base_tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2;
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE - 1,
            "Unexpected size for 63-byte case");
        record(t, /*valid=*/true, "A 63-byte legacy transaction.");
    }

    // --- Case 2: 60-byte non-witness with a witness attached — valid ---
    // The check is on non-witness size only; a witness does not save a 64-byte tx,
    // but a genuinely sub-64-byte tx is fine even when it carries witness data.
    {
        CMutableTransaction t{base_tx};
        // Add one empty witness stack item; this does NOT change non-witness size.
        t.vin.back().scriptWitness.stack.resize(1);
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE - 4,
            "Unexpected non-witness size for witness+sub-64 case");
        record(t, /*valid=*/true, "A 60-byte non-witness transaction carrying a witness.");
    }

    // --- Case 3: 64 bytes via scriptPubKey padding — invalid ---
    {
        CMutableTransaction t{base_tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE,
            "Unexpected size for 64-byte spk case");
        record(t, /*valid=*/false, "A 64-byte legacy transaction (4 bytes in scriptPubKey).");
    }

    // --- Case 4: 64 bytes via scriptSig + nValue — invalid ---
    // Demonstrates that the check is purely size-based, not structure-based.
    {
        CMutableTransaction t{base_tx};
        t.vout.back().nValue = MAX_MONEY;
        t.vin.back().scriptSig << std::vector<uint8_t>{0x42, 0x42, 0x42};
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE,
            "Unexpected size for 64-byte scriptsig case");
        record(t, /*valid=*/false, "A 64-byte legacy transaction (3-byte scriptSig + MAX_MONEY value).");
    }

    // --- Case 5: 65 bytes — valid (one above the forbidden size) ---
    {
        CMutableTransaction t{base_tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4 << OP_8;
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE + 1,
            "Unexpected size for 65-byte case");
        record(t, /*valid=*/true, "A 65-byte legacy transaction.");
    }

    // --- Case 6: 64-byte non-witness even though witness is present — invalid ---
    // A witness does NOT exempt a transaction from the 64-byte non-witness size check.
    {
        CMutableTransaction t{base_tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        // Add witness data to make the *with-witness* size larger than 64.
        t.vin.back().scriptWitness.stack.push_back({0x21, 0x32, 0x45, 0x57, 0x62, 0x81, 0x94, 0x12});
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(t)) == INVALID_TX_NONWITNESS_SIZE,
            "Unexpected non-witness size for segwit+64 case");
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_WITH_WITNESS(t)) > INVALID_TX_NONWITNESS_SIZE,
            "Witness size should exceed 64 bytes");
        record(t, /*valid=*/false,
               "A 64-byte non-witness Segwit transaction (witness does not exempt it).");
    }

    // -----------------------------------------------------------------------
    // Historical 64-byte transactions sourced from Chris Stewart's BIP53 list.
    // These are real on-chain transactions that would be rejected by this rule.
    // -----------------------------------------------------------------------
    static constexpr std::string_view kHistoricalTxsHex[]{
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

    for (const auto hex : kHistoricalTxsHex) {
        CMutableTransaction hist;
        Assert(DecodeHexTx(hist, std::string{hex}));
        BOOST_REQUIRE_MESSAGE(
            GetSerializeSize(TX_NO_WITNESS(hist)) == INVALID_TX_NONWITNESS_SIZE,
            "Historical tx should be exactly 64 bytes");
        std::string comment{"Historical 64-byte transaction " + hist.GetHash().ToString()};
        test_cases.push_back({CTransaction{hist}, /*valid=*/false, std::move(comment)});
    }

    // -----------------------------------------------------------------------
    // Run each test case through AcceptBlock() on a fresh regtest chain.
    // We use a single RegTestingSetup so we can build blocks sequentially.
    // -----------------------------------------------------------------------
    RegTestingSetup test_setup{};
    auto& chainman{*test_setup.m_node.chainman};
    const Consensus::Params& params{chainman.GetConsensus()};

    // cs_main / chainman mutex must be held when calling AcceptBlock.
    LOCK(chainman.GetMutex());

    for (const auto& tc : test_cases) {
        // Assemble a template block on top of the current tip.
        CBlock block{
            node::BlockAssembler{chainman.ActiveChainstate(), /*mempool=*/nullptr, {}}
                .CreateNewBlock()
                ->block};

        // Inject the transaction under test after the coinbase.
        block.vtx.push_back(MakeTransactionRef(tc.tx));

        // Recompute the witness commitment in the coinbase (if any) and the
        // Merkle root so the block is structurally valid for AcceptBlock.
        node::RegenerateCommitments(block, chainman);

        // Mine the block (find a valid nNonce).
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
            // The 64-byte check in CheckTransaction() emits this reason.
            BOOST_CHECK_MESSAGE(
                state.GetRejectReason() == "bad-txns-64byte",
                "Wrong reject reason for: " + tc.comment
                + " (got: " + state.GetRejectReason() + ")");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
