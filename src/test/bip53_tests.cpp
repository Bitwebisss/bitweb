// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the BIP-53 / CVE-2017-12842 rule:
//   "reject non-coinbase transactions whose non-witness serialized size == 64"
//
// The rule lives in CheckTransaction() in consensus/tx_check.cpp, so we test
// it directly — no block assembly, no chainstate, no RegTestingSetup needed.
//
// Serialized size of the base transaction (1 input, 1 output, empty scripts):
//   version(4) + vin_cnt(1) + outpoint_hash(32) + outpoint_idx(4)
//   + scriptSig_len(1) + sequence(4)
//   + vout_cnt(1) + value(8) + scriptPubKey_len(1)
//   + locktime(4)  =  60 bytes
//
// Each opcode pushed via `<< OP_x` adds exactly 1 byte to scriptPubKey.
// Pushing N opcodes therefore raises the total to 60 + N bytes.

#include <boost/test/unit_test.hpp>

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>             // DecodeHexTx
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

// ── helpers ──────────────────────────────────────────────────────────────────

/** Non-witness serialized byte count. */
static size_t NWSize(const CMutableTransaction& mtx)
{
    return GetSerializeSize(TX_NO_WITNESS(mtx));
}

/**
 * Build a minimal, valid non-coinbase transaction.
 * scriptPubKey is empty; add opcodes via `tx.vout[0].scriptPubKey << OP_x`
 * to reach the desired serialized size (base = 60 bytes).
 *
 * Uses a known non-null prevout hash so CheckTransaction does not reject
 * the tx for "bad-txns-prevout-null" before it can reach the size check.
 */
static CMutableTransaction BaseTx()
{
    CMutableTransaction mtx;
    mtx.version   = 1;
    mtx.nLockTime = 0;

    CTxIn in;
    // Any non-null 32-byte hash works; borrow the one from BIP-53 test vectors.
    in.prevout  = COutPoint{
        uint256S("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82"),
        21};
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin.push_back(in);

    mtx.vout.emplace_back(0, CScript{});
    return mtx;
}

// ── test suite ────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(bip53_64byte_tests)

// ─── boundary: 63 bytes — must pass ──────────────────────────────────────────
BOOST_AUTO_TEST_CASE(bip53_boundary_63_bytes_passes)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1;   // +3 → 63 bytes
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 63u);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// ─── boundary: 64 bytes — must be rejected ───────────────────────────────────
BOOST_AUTO_TEST_CASE(bip53_boundary_64_bytes_rejected)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1;  // +4 → 64 bytes
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 64u);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-64byte");
}

// ─── boundary: 65 bytes — must pass ──────────────────────────────────────────
BOOST_AUTO_TEST_CASE(bip53_boundary_65_bytes_passes)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1 << OP_1;  // +5 → 65
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 65u);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// ─── a 64-byte coinbase is explicitly excluded from the rule ─────────────────
//
// Serialized layout (non-witness):
//   version(4) + vin_cnt(1) + prevout_hash(32) + prevout_idx(4)
//   + scriptSig_len(1) + scriptSig(4) + sequence(4)
//   + vout_cnt(1) + value(8) + spk_len(1) + spk(0)
//   + locktime(4)  =  64 bytes exactly
BOOST_AUTO_TEST_CASE(bip53_coinbase_64_bytes_is_allowed)
{
    CMutableTransaction cb;
    cb.version   = 1;
    cb.nLockTime = 0;

    CTxIn in;
    in.prevout   = COutPoint{};          // null prevout → coinbase
    // 4 opcode bytes; satisfies the 2..100 scriptSig length requirement.
    in.scriptSig << OP_1 << OP_1 << OP_1 << OP_1;
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    cb.vin.push_back(in);

    cb.vout.emplace_back(0, CScript{});  // empty scriptPubKey → 0 bytes

    BOOST_CHECK(CTransaction(cb).IsCoinBase());
    BOOST_REQUIRE_EQUAL(NWSize(cb), 64u);

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(cb), state));
    BOOST_CHECK(state.IsValid());
}

// ─── witness does NOT rescue a 64-byte tx (rule uses non-witness size) ────────
BOOST_AUTO_TEST_CASE(bip53_segwit_nonwitness_size_64_rejected)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1;  // nw = 64
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 64u);

    // Attach a witness — with-witness size > 64, but the rule still fires.
    mtx.vin[0].scriptWitness.stack.push_back({0x42, 0x42, 0x42});
    BOOST_CHECK_GT(GetSerializeSize(TX_WITH_WITNESS(mtx)), 64u);
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 64u);   // non-witness unchanged

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-64byte");
}

// ─── non-witness size 65 with a witness — must pass ──────────────────────────
BOOST_AUTO_TEST_CASE(bip53_segwit_nonwitness_65_not_rejected)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1 << OP_1;  // nw = 65
    BOOST_REQUIRE_EQUAL(NWSize(mtx), 65u);

    mtx.vin[0].scriptWitness.stack.push_back({0x42});

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// ─── historical real-world 64-byte transactions ───────────────────────────────
BOOST_AUTO_TEST_CASE(bip53_historical_64byte_transactions)
{
    // Five confirmed transactions that are exactly 64 bytes non-witness.
    // Source: BIP-53 / Chris Stewart's collection.
    const char* hexes[] = {
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

    for (const char* hex : hexes) {
        CMutableTransaction mtx;
        BOOST_REQUIRE_MESSAGE(DecodeHexTx(mtx, hex), hex);
        BOOST_CHECK_EQUAL_MESSAGE(NWSize(mtx), 64u, hex);

        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(mtx), state), hex);
        BOOST_CHECK_EQUAL_MESSAGE(
            state.GetRejectReason(), "bad-txns-64byte", hex);
    }
}

BOOST_AUTO_TEST_SUITE_END()
