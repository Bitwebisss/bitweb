// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Extracted from bip54_tests.cpp — only the 64-byte transaction rule tests.
// Adapted for bitweb (custom PoW / DifficultyAdjustmentInterval=1).

#include <boost/test/unit_test.hpp>

#include <addresstype.h>
#include <chainparams.h>
#include <core_io.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>

using namespace util::hex_literals;

// ---------------------------------------------------------------------------
// Helper: mine a regtest block by brute-forcing nNonce.
//
// In bitweb, GetNextWorkRequired() returns nProofOfWorkLimit for heights < 500,
// so the target is the easiest possible — this loop completes in microseconds.
// ---------------------------------------------------------------------------
static void MineRegtestBlock(CBlock& block, const Consensus::Params& params)
{
    while (!CheckProofOfWork(block.GetHash(), block.nBits, params)) {
        Assert(++block.nNonce);
    }
}

// ---------------------------------------------------------------------------
// Test vectors struct (mirrors the upstream one, but self-contained here).
// ---------------------------------------------------------------------------
struct TestVectorTxSize {
    const CTransaction tx;
    bool valid;
    std::string comment;

    explicit TestVectorTxSize(CTransaction t, bool val, std::string com)
        : tx{std::move(t)}, valid{val}, comment{std::move(com)} {}
};

static void RecordTestCase(std::vector<TestVectorTxSize>& v,
                           CTransaction t, bool valid, std::string com)
{
    v.emplace_back(std::move(t), valid, std::move(com));
}

// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_SUITE(txsize64_tests)

/**
 * Tests for the "no 64-byte transaction" rule (BIP 54 / CVE-2017-12842 fix).
 *
 * The rule rejects any transaction whose non-witness serialization size equals
 * exactly 64 bytes, because such transactions can be confused with interior
 * nodes of a Merkle tree and enable SPV proof forgery attacks.
 *
 * The check is performed in ContextualCheckBlock() / AcceptBlock() regardless
 * of whether the BIP 54 soft-fork is active — in Bitcoin Core it is controlled
 * by a compile-time guard that you should verify exists in your tree under
 * src/validation.cpp (look for 64 / "bad-txns-size").
 */
BOOST_AUTO_TEST_CASE(txsize_64byte_rule)
{
    std::vector<TestVectorTxSize> test_vectors;

    // Base transaction used to craft boundary cases.
    // One input, one empty output — we'll pad scriptPubKey / scriptSig to hit
    // exactly 63 / 64 / 65 non-witness bytes.
    CMutableTransaction tx;
    tx.vin.emplace_back(
        COutPoint{*Txid::FromHex(
            "83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"),
            21});
    tx.vout.emplace_back(0, CScript{});

    // -----------------------------------------------------------------------
    // 63 bytes — valid (below the forbidden size)
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2;
        Assert(GetSerializeSize(TX_NO_WITNESS(t)) == 64 - 1);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/true, "A 63-byte legacy transaction.");
    }

    // -----------------------------------------------------------------------
    // 61 bytes non-witness but 64 bytes with witness — valid
    // (the rule checks non-witness size only)
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vin.back().scriptWitness.stack.resize(1);
        Assert(GetSerializeSize(TX_NO_WITNESS(t)) == 64 - 4);
        Assert(GetSerializeSize(TX_WITH_WITNESS(t)) == 64);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/true,
                       "A 61-byte legacy transaction with a witness.");
    }

    // -----------------------------------------------------------------------
    // 64 bytes — INVALID
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        Assert(GetSerializeSize(TX_NO_WITNESS(t)) == 64);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/false,
                       "A 64-byte legacy transaction (4 bytes in spk).");
    }

    // -----------------------------------------------------------------------
    // 64 bytes built differently (bytes in scriptSig instead of scriptPubKey)
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vout.back().nValue = MAX_MONEY;
        t.vin.back().scriptSig << std::vector<uint8_t>{0x42, 0x42, 0x42};
        Assert(GetSerializeSize(TX_NO_WITNESS(t)) == 64);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/false,
                       "A 64-byte legacy transaction (4 bytes in scriptsig).");
    }

    // -----------------------------------------------------------------------
    // 65 bytes — valid (above the forbidden size)
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4 << OP_8;
        Assert(GetSerializeSize(TX_NO_WITNESS(t)) == 64 + 1);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/true, "A 65-byte legacy transaction.");
    }

    // -----------------------------------------------------------------------
    // 64 bytes non-witness with a witness attached — still INVALID
    // -----------------------------------------------------------------------
    {
        CMutableTransaction t{tx};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        t.vin.back().scriptWitness.stack.push_back(
            {0x21, 0x32, 0x45, 0x57, 0x62, 0x81, 0x94, 0x12});
        Assert(GetSerializeSize(TX_WITH_WITNESS(t)) > 64);
        Assert(GetSerializeSize(TX_NO_WITNESS(t))   == 64);
        RecordTestCase(test_vectors, CTransaction{t},
                       /*valid=*/false, "A 64-byte Segwit transaction.");
    }

    // -----------------------------------------------------------------------
    // Historical 64-byte transactions from the wild (taken from BIP 53 /
    // Chris Stewart's collection).  All must be rejected.
    // -----------------------------------------------------------------------
    constexpr std::string_view historical_txs_hex[]{
        "0200000001deb98691723fa71260ffca6ea0a7bc0a63b0a8a366e1b585caad47fb269a2ce401000000030251b201000000010000000000000000016a00000000",
        "01000000010d0afe3d74062ee60c0ec55579d691d8c8af5c04eb97b777157a21a8c5fb143d00000000035101b100000000010000000000000000016a01000000",
        "02000000011658a33df410379bb512206659910c9fbd0e50bfb732f7be9936558ff036919401000000035101b201000000010000000000000000016a00000000",
        "02000000011a7a4cf262fb7e53e2e6e0b2ef8b763f6ee97d8681ca968d1938418d56e6c38700000000035101b201000000010000000000000000016a00000000",
        "01000000019222bbb054bb9f94571dfe769af5866835f2a97e883959fa757de4064bed8bca01000000035101b100000000010000000000000000016a01000000",
    };
    for (const auto hex : historical_txs_hex) {
        CMutableTransaction hist_tx;
        Assert(DecodeHexTx(hist_tx, std::string{hex}));
        std::string comment{"Historical 64-byte transaction "};
        RecordTestCase(test_vectors, CTransaction(hist_tx),
                       /*valid=*/false,
                       comment + hist_tx.GetHash().ToString());
    }

    // -----------------------------------------------------------------------
    // Run every test case through AcceptBlock().
    //
    // We spin up a fresh RegTestingSetup for each case so that a previous
    // rejection cannot pollute the chain state for the next test.
    //
    // NOTE FOR BITWEB: RegTestingSetup initialises a REGTEST chainstate.
    // Because bitweb's GetNextWorkRequired() returns nProofOfWorkLimit for
    // heights < 500, MineRegtestBlock() above is essentially a no-op and the
    // loop exits on the very first nNonce value in practice.
    // -----------------------------------------------------------------------
    for (const auto& tc : test_vectors) {
        RegTestingSetup test_setup{};
        auto& chainman{*test_setup.m_node.chainman};
        const auto& params{chainman.GetConsensus()};
        LOCK(chainman.GetMutex());

        // Build a minimal block containing the transaction under test.
        auto block{
            node::BlockAssembler{
                chainman.ActiveChainstate(), /*mempool=*/nullptr, {}}
            .CreateNewBlock()->block};

        block.vtx.push_back(MakeTransactionRef(tc.tx));
        node::RegenerateCommitments(block, chainman);
        MineRegtestBlock(block, params);

        const auto pblock{std::make_shared<CBlock>(std::move(block))};
        BlockValidationState state;
        const bool res{
            chainman.AcceptBlock(pblock, state,
                                 /*ppindex=*/nullptr,
                                 /*fRequested=*/true,
                                 /*dbp=*/nullptr,
                                 /*fNewBlock=*/nullptr,
                                 /*min_pow_checked=*/true)};

        BOOST_CHECK_MESSAGE(res == tc.valid, tc.comment);
        if (!tc.valid) {
            BOOST_CHECK_MESSAGE(
                state.GetRejectReason() == "bad-txns-64byte", tc.comment);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()