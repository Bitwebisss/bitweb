// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for the BIP-53 / CVE-2017-12842 rule:
//   reject non-coinbase transactions whose non-witness serialized size == 64.
//
// The rule lives in CheckTransaction() (consensus/tx_check.cpp), so we call
// it directly — no block assembly or chainstate required.
//
// Base non-witness size of the minimal transaction used here (1 in, 1 out,
// empty scripts, fixed prevout hash):
//   version(4) + vin_cnt(1) + hash(32) + idx(4) + ss_len(1) + seq(4)
//   + vout_cnt(1) + value(8) + spk_len(1) + locktime(4)  =  60 bytes
//
// Each additional opcode pushed via << OP_x adds exactly 1 byte.

#include <boost/test/unit_test.hpp>

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <primitives/transaction_identifier.h>
#include <script/script.h>
#include <serialize.h>

// ── helpers ───────────────────────────────────────────────────────────────────

static size_t NWSize(const CMutableTransaction& mtx)
{
    return GetSerializeSize(TX_NO_WITNESS(mtx));
}

// Minimal non-coinbase transaction; scriptPubKey is empty (60 bytes total).
// Uses a known non-null prevout so CheckTransaction does not reject for
// "bad-txns-prevout-null" before the size check is reached.
static CMutableTransaction BaseTx()
{
    CMutableTransaction mtx;
    mtx.version   = 1;
    mtx.nLockTime = 0;

    CTxIn in;
    in.prevout   = COutPoint(
        Txid::FromHex("83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82").value(),
        21u);
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin.push_back(in);

    mtx.vout.emplace_back(0, CScript{});
    return mtx;
}

// ── test suite ────────────────────────────────────────────────────────────────

BOOST_AUTO_TEST_SUITE(bip53_64byte_tests)

// 63 bytes — below the forbidden size, must pass
BOOST_AUTO_TEST_CASE(bip53_boundary_63_bytes_passes)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1;  // 60 + 3 = 63
    BOOST_REQUIRE_MESSAGE(NWSize(mtx) == 63u,
        "expected 63 bytes, got " << NWSize(mtx));

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// 64 bytes — exactly forbidden, must be rejected
BOOST_AUTO_TEST_CASE(bip53_boundary_64_bytes_rejected)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1;  // 60 + 4 = 64
    BOOST_REQUIRE_MESSAGE(NWSize(mtx) == 64u,
        "expected 64 bytes, got " << NWSize(mtx));

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_MESSAGE(state.GetRejectReason() == "bad-txns-64byte",
        "wrong reject reason: " << state.GetRejectReason());
}

// 65 bytes — above the forbidden size, must pass
BOOST_AUTO_TEST_CASE(bip53_boundary_65_bytes_passes)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1 << OP_1;  // 60 + 5 = 65
    BOOST_REQUIRE_MESSAGE(NWSize(mtx) == 65u,
        "expected 65 bytes, got " << NWSize(mtx));

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// A 64-byte coinbase is explicitly excluded from the rule.
//
// Layout:  version(4) + vin_cnt(1) + null_hash(32) + idx(4)
//          + ss_len(1) + scriptSig(4) + seq(4)
//          + vout_cnt(1) + value(8) + spk_len(1) + spk(0)
//          + locktime(4)  =  64 bytes
BOOST_AUTO_TEST_CASE(bip53_coinbase_64_bytes_is_allowed)
{
    CMutableTransaction cb;
    cb.version   = 1;
    cb.nLockTime = 0;

    CTxIn in;
    in.prevout   = COutPoint{};  // null prevout → coinbase
    in.scriptSig << OP_1 << OP_1 << OP_1 << OP_1;  // 4 bytes (satisfies 2..100)
    in.nSequence = CTxIn::SEQUENCE_FINAL;
    cb.vin.push_back(in);

    cb.vout.emplace_back(0, CScript{});  // empty scriptPubKey

    BOOST_CHECK(CTransaction(cb).IsCoinBase());
    BOOST_REQUIRE_MESSAGE(NWSize(cb) == 64u,
        "expected 64 bytes, got " << NWSize(cb));

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(cb), state));
    BOOST_CHECK(state.IsValid());
}

// Witness does NOT rescue a 64-byte tx — rule checks non-witness size only
BOOST_AUTO_TEST_CASE(bip53_segwit_nonwitness_64_rejected)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1;  // nw = 64
    BOOST_REQUIRE_MESSAGE(NWSize(mtx) == 64u,
        "expected 64 bytes, got " << NWSize(mtx));

    mtx.vin[0].scriptWitness.stack.push_back({0x42, 0x42, 0x42});
    BOOST_CHECK_MESSAGE(GetSerializeSize(TX_WITH_WITNESS(mtx)) > 64u,
        "with-witness size should exceed 64");
    BOOST_REQUIRE_MESSAGE(NWSize(mtx) == 64u, "non-witness size changed unexpectedly");

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK_MESSAGE(state.GetRejectReason() == "bad-txns-64byte",
        "wrong reject reason: " << state.GetRejectReason());
}

// nw = 65 with a witness — must pass
BOOST_AUTO_TEST_CASE(bip53_segwit_nonwitness_65_passes)
{
    CMutableTransaction mtx = BaseTx();
    mtx.vout[0].scriptPubKey << OP_1 << OP_1 << OP_1 << OP_1 << OP_1;  // nw = 65
    mtx.vin[0].scriptWitness.stack.push_back({0x42});

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction(mtx), state));
    BOOST_CHECK(state.IsValid());
}

// Historical real-world 64-byte transactions — all must be rejected
BOOST_AUTO_TEST_CASE(bip53_historical_64byte_transactions)
{
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
        BOOST_REQUIRE_MESSAGE(DecodeHexTx(mtx, hex),
            "DecodeHexTx failed for: " << hex);
        BOOST_CHECK_MESSAGE(NWSize(mtx) == 64u,
            "expected 64 bytes for: " << hex);

        TxValidationState state;
        BOOST_CHECK_MESSAGE(!CheckTransaction(CTransaction(mtx), state),
            "should have been rejected: " << hex);
        BOOST_CHECK_MESSAGE(state.GetRejectReason() == "bad-txns-64byte",
            "wrong reject reason '" << state.GetRejectReason()
            << "' for: " << hex);
    }
}

BOOST_AUTO_TEST_SUITE_END()