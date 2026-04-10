// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// BIP-53: 64-byte transaction rejection tests.
// Adapted from bitcoin-inquisition bip54_tests.cpp (bip54_txsize case).
// Targets the altcoin fork based on Bitcoin Core v30.2 (uses GetArgon2idPoWHash).

#include <boost/test/unit_test.hpp>

#include <addresstype.h>
#include <consensus/tx_check.h>
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

// Non-witness serialization size forbidden by BIP-53.
static constexpr uint32_t INVALID_TX_NONWITNESS_SIZE{64};

/**
 * Mine a regtest block by incrementing nNonce until PoW is satisfied.
 * Uses GetArgon2idPoWHash() — required by this altcoin fork.
 */
static void MineRegtestBlock(CBlock& block, const Consensus::Params& params)
{
    block.nNonce = 0;
    while (!CheckProofOfWork(block.GetArgon2idPoWHash(), block.nBits, params)) {
        Assert(++block.nNonce);
    }
}

// ============================================================================
// PART 1 — Direct CheckTransaction() tests (unit-level, no block required)
//
// Tests the rule at the lowest level: CheckTransaction() in tx_check.cpp.
// Covers both normal-tx rejection AND the coinbase exemption.
//
// Why test CheckTransaction() directly?
//   AcceptBlock() calls CheckBlock() → CheckTransaction() for every tx.
//   Testing at this level ensures the rule fires (or is skipped for coinbase)
//   independently of block-level plumbing.
// ============================================================================

BOOST_AUTO_TEST_CASE(bip53_check_transaction_direct)
{
    TxValidationState state;

    // --- Regular 64-byte transaction is rejected by CheckTransaction() ---
    {
        CMutableTransaction t;
        t.vin.emplace_back(
            COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
        t.vout.emplace_back(0, CScript{} << OP_0 << OP_1 << OP_2 << OP_4);
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        // IsCoinBase() lives on CTransaction, not CMutableTransaction.
        BOOST_REQUIRE(!CTransaction{t}.IsCoinBase());

        state = TxValidationState{};
        BOOST_CHECK(!CheckTransaction(CTransaction{t}, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-64byte");
    }

    // --- Coinbase transaction: 64 bytes MUST be accepted (explicit exemption) ---
    //
    // tx_check.cpp: if (!tx.IsCoinBase() && size == 64) → reject
    // So a 64-byte coinbase must pass CheckTransaction().
    //
    // Byte layout of a minimal coinbase (non-witness):
    //   version      : 4
    //   vin_count    : 1
    //   prevout      : 36  (32 zero hash + 4 0xFFFFFFFF index)
    //   scriptSig_len: 1
    //   scriptSig    : N   (consensus requires 2..100 bytes)
    //   sequence     : 4
    //   vout_count   : 1
    //   value        : 8
    //   spk_len      : 1
    //   spk          : M
    //   locktime     : 4
    //   TOTAL        : 60 + N + M
    //
    // To reach 64: N + M = 4.
    // Using N=4 (four single-byte opcodes OP_1..OP_4), M=0 (empty scriptPubKey).
    //
    // NOTE: CScriptNum(0) serialises as OP_0 = 1 byte, so two CScriptNum(0)
    // would only give N=2.  Four opcodes give exactly N=4.
    {
        CMutableTransaction cb;
        cb.vin.resize(1);
        cb.vin[0].prevout.SetNull();
        cb.vin[0].scriptSig   = CScript() << OP_1 << OP_2 << OP_3 << OP_4; // 4 bytes
        cb.vin[0].nSequence   = CTxIn::SEQUENCE_FINAL;
        cb.vout.emplace_back(50 * COIN, CScript{});                          // empty spk (M=0)

        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(cb)), INVALID_TX_NONWITNESS_SIZE);
        // IsCoinBase() lives on CTransaction, not CMutableTransaction.
        BOOST_REQUIRE(CTransaction{cb}.IsCoinBase());

        state = TxValidationState{};
        // A 64-byte coinbase must PASS — the exemption must work.
        BOOST_CHECK_MESSAGE(CheckTransaction(CTransaction{cb}, state),
                            "64-byte coinbase must be accepted by CheckTransaction (BIP-53 exemption)");
        BOOST_CHECK(state.IsValid());
    }

    // --- 63-byte regular transaction is accepted ---
    {
        CMutableTransaction t;
        t.vin.emplace_back(
            COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
        t.vout.emplace_back(0, CScript{} << OP_0 << OP_1 << OP_2);
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE - 1);

        state = TxValidationState{};
        BOOST_CHECK(CheckTransaction(CTransaction{t}, state));
        BOOST_CHECK(state.IsValid());
    }

    // --- 65-byte regular transaction is accepted ---
    {
        CMutableTransaction t;
        t.vin.emplace_back(
            COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
        t.vout.emplace_back(0, CScript{} << OP_0 << OP_1 << OP_2 << OP_4 << OP_8);
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE + 1);

        state = TxValidationState{};
        BOOST_CHECK(CheckTransaction(CTransaction{t}, state));
        BOOST_CHECK(state.IsValid());
    }
}

// ============================================================================
// PART 2 — AcceptBlock() integration tests
//
// Wraps each transaction in a mined regtest block and calls AcceptBlock().
// This exercises the full pipeline: CheckBlock → CheckTransaction.
// ============================================================================

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

    // Base tx: 1 input spending a fictitious outpoint, 1 empty output.
    // Non-witness size of the bare base is 60 bytes.
    CMutableTransaction base;
    base.vin.emplace_back(
        COutPoint{*Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"), 21});
    base.vout.emplace_back(0, CScript{});

    // ------------------------------------------------------------------
    // Boundary cases
    // ------------------------------------------------------------------

    // 63 bytes — valid
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE - 1);
        record(t, true, "A 63-byte legacy transaction.");
    }

    // 60-byte non-witness tx with witness data — valid
    // The rule checks non-witness size only.
    {
        CMutableTransaction t{base};
        t.vin.back().scriptWitness.stack.resize(1);
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE - 4);
        record(t, true, "A 60-byte (non-witness) transaction that also carries witness data.");
    }

    // 64 bytes via scriptPubKey — invalid
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, false, "A 64-byte legacy transaction (4 bytes in scriptPubKey).");
    }

    // 64 bytes via scriptSig — invalid
    {
        CMutableTransaction t{base};
        t.vout.back().nValue = MAX_MONEY;
        t.vin.back().scriptSig << std::vector<uint8_t>{0x42, 0x42, 0x42};
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, false, "A 64-byte legacy transaction (3-byte scriptSig + MAX_MONEY nValue).");
    }

    // 65 bytes — valid
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4 << OP_8;
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE + 1);
        record(t, true, "A 65-byte legacy transaction.");
    }

    // 64-byte non-witness WITH witness — still invalid
    // Witness presence does NOT exempt a tx from the non-witness size check.
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey << OP_0 << OP_1 << OP_2 << OP_4;
        t.vin.back().scriptWitness.stack.push_back({0x21, 0x32, 0x45, 0x57, 0x62, 0x81, 0x94, 0x12});
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)),    INVALID_TX_NONWITNESS_SIZE);
        BOOST_REQUIRE      (GetSerializeSize(TX_WITH_WITNESS(t)) > INVALID_TX_NONWITNESS_SIZE);
        record(t, false, "A 64-byte Segwit transaction (witness present but non-witness size is still 64).");
    }

    // Semi-realistic 64-byte Segwit tx: 1 Taproot-style input + 1 Pay-to-Anchor output.
    //
    // PayToAnchor (P2A) is an output type introduced in Bitcoin Core v28 as part of
    // the TRUC / ephemeral-anchor mechanism. Its scriptPubKey is:
    //   OP_1 <0x4e73>   (SegWit v1 with a 2-byte witness program)
    // Anyone can spend a P2A output without a key — it is used to attach fee-bumping
    // child transactions to a parent in package relay without exposing private keys.
    // The non-witness serialization of this tx is still 64 bytes, so it must be rejected.
    {
        CMutableTransaction t{base};
        t.vout.back().scriptPubKey = GetScriptForDestination(PayToAnchor{});
        auto sig{"5a78b5a14a2527feb02c08b8124e74c3b9bcc1bd3dba1fbfa87f1c930f28a46f"
                 "ea2bf375105dfd835e212c9127aad4976c46ef86be02edbb681e6f38f9a9e06f01"_hex_v_u8};
        t.vin.back().scriptWitness.stack.emplace_back(std::move(sig));
        BOOST_REQUIRE_EQUAL(GetSerializeSize(TX_NO_WITNESS(t)), INVALID_TX_NONWITNESS_SIZE);
        record(t, false, "A 64-byte Segwit transaction (1 P2TR-style input, 1 P2A output).");
    }

    // ------------------------------------------------------------------
    // Historical 64-byte transactions (from Chris Stewart's BIP-53 list)
    // ------------------------------------------------------------------
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

    // ------------------------------------------------------------------
    // Execute all cases via AcceptBlock()
    // ------------------------------------------------------------------
    RegTestingSetup test_setup{};
    auto& chainman{*test_setup.m_node.chainman};
    const Consensus::Params& params{chainman.GetConsensus()};

    LOCK(chainman.GetMutex());

    for (const auto& tc : cases) {
        CBlock block{
            node::BlockAssembler{chainman.ActiveChainstate(), /*mempool=*/nullptr, {}}
                .CreateNewBlock()
                ->block};

        block.vtx.push_back(MakeTransactionRef(tc.tx));
        node::RegenerateCommitments(block, chainman);
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
            BOOST_CHECK_MESSAGE(
                state.GetRejectReason() == "bad-txns-64byte",
                "Wrong reject reason for: " + tc.comment
                    + " — got: \"" + state.GetRejectReason() + "\"");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()