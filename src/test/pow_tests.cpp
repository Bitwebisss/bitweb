// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Original Bitcoin Core difficulty-adjustment tests (kept for history).
// These tested CalculateNextWorkRequired() / the 2016-block retargeting rule
// that is NOT used in this coin (replaced by LWMA-3).  Commented out so they
// compile but do not run; preserved so the diff against upstream stays clear.
// ---------------------------------------------------------------------------

/* Test calculation of next difficulty target with no constraints applying
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1f0fffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}
*/

/* Test the constraint on the upper bound for next work
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1f0fffff;
    unsigned int expected_nbits = 0x1f0fffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}
*/

/* Test the constraint on the lower bound for actual time taken
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}
*/

/* Test the constraint on the upper bound for actual time taken
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}
*/

// ---------------------------------------------------------------------------
// Helper: build a chain of `count` blocks (indices 0..count-1) all carrying
// the same nBits, spaced `spacing` seconds apart starting at `t0`.
// The vector is pre-allocated so pprev pointers remain stable.
// ---------------------------------------------------------------------------
static std::vector<CBlockIndex> BuildChain(int count, unsigned int nBits,
                                           int64_t t0, int64_t spacing)
{
    std::vector<CBlockIndex> blocks(count);
    for (int i = 0; i < count; i++) {
        blocks[i].pprev      = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight    = i;
        blocks[i].nTime      = static_cast<uint32_t>(t0 + static_cast<int64_t>(i) * spacing);
        blocks[i].nBits      = nBits;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1])
                                 : arith_uint256(0);
    }
    return blocks;
}

// ---------------------------------------------------------------------------
// LWMA-3 tests
// All expected_nbits values are derived by running an exact Python simulation
// of the arith_uint256 integer arithmetic in Lwma3CalculateNextWorkRequired
// (see powlimit_converter.py in the repo root).  We hardcode the results so
// the tests are pure determinism checks — they catch any future accidental
// change to the algorithm, not just "is the result reasonable".
//
// Coin parameters: N=576, T=300 s, genesisBits=0x1f0fffff, powLimit same.
// Bootstrap threshold L = N+1 = 577; first LWMA-3 height is N+2 = 578.
// k = N*(N+1)*T/2 = 49 852 800.
//
// NOTE on the "stable hashrate" expected value:
//   With all solvetimes == T the math gives sumWeightedSolvetimes == k, so
//   ideally nextTarget == powLimit.  However the accumulator loop performs
//   two sequential integer divisions (target/N then /k) losing a few bits per
//   iteration; the aggregate rounding error is ~10^10, which is 57 orders of
//   magnitude smaller than 1 compact LSB (~2^224) — i.e. invisible in the
//   target value itself — yet GetCompact() rounds DOWN when the top bit of the
//   mantissa is set, producing a result exactly 1 compact LSB below powLimit.
//   This is a deterministic, reproducible property of the implementation, not
//   a bug.  We therefore hardcode 0x1f0ffffeU as the expected value.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 1: During bootstrap (height <= N+1) LWMA3 must return genesis nBits.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_bootstrap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // Bootstrap threshold L = N + 1 = 577.
    const int L = static_cast<int>(N + 1);
    auto blocks = BuildChain(L + 1, genesisBits, 1775674812, T);

    // At the boundary height L the bootstrap path is still taken.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[L], nullptr, consensus), genesisBits);

    // Heights well inside the bootstrap window also return genesis nBits.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[1],     nullptr, consensus), genesisBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[N / 2], nullptr, consensus), genesisBits);
}

// ---------------------------------------------------------------------------
// Test 2: Deterministic stable-hashrate result.
//   spacing == T on every block → expected_nbits == 0x1f0ffffeU.
//   (See the NOTE above for why this is genesisBits - 1, not genesisBits.)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_stable_hashrate)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // Hardcoded result from Python simulation of arith_uint256 arithmetic.
    // Derived once; from this point it is a pure regression / determinism check.
    const unsigned int expected_nbits = 0x1f0ffffeU;

    const int height = static_cast<int>(N + 2); // 578 — first post-bootstrap height
    auto blocks = BuildChain(height + 1, genesisBits, 1775674812, T);

    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // Sanity: result must never exceed powLimit.
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= UintToArith256(consensus.powLimit));
}

// ---------------------------------------------------------------------------
// Test 3: The computed target must never exceed powLimit even when every
//   solvetime hits the 6T cap.
//   spacing == 6T → sumWeightedSolvetimes == 6k → nextTarget == 6*powLimit
//   → clamped back to powLimit.  Expected: 0x1f0fffffU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_powlimit_cap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits   = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit     = UintToArith256(consensus.powLimit);

    // Hardcoded: spacing=6T always hits the cap → clamped to powLimit.
    const unsigned int expected_nbits = 0x1f0fffffU;

    const int height = static_cast<int>(N + 2);
    auto blocks = BuildChain(height + 1, genesisBits, 1775674812, 6 * T);

    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
}

// ---------------------------------------------------------------------------
// Test 4: The 6T solvetime cap must prevent difficulty from falling further
//   when block timestamps exceed 6*T.  A chain with spacing 100*T must yield
//   exactly the same next target as a chain with spacing 6*T.
//   Both expected: 0x1f0fffffU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_6T_solvetime_cap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;

    const unsigned int expected_nbits = 0x1f0fffffU; // cap → powLimit for both

    const int height = static_cast<int>(N + 2);
    auto blocks_6T   = BuildChain(height + 1, genesisBits, 1775674812, 6 * T);
    auto blocks_100T = BuildChain(height + 1, genesisBits, 1775674812, 100 * T);

    unsigned int result_6T   = GetNextWorkRequired(&blocks_6T[height],   nullptr, consensus);
    unsigned int result_100T = GetNextWorkRequired(&blocks_100T[height], nullptr, consensus);

    BOOST_CHECK_EQUAL(result_6T,   expected_nbits);
    BOOST_CHECK_EQUAL(result_100T, expected_nbits);
    BOOST_CHECK_EQUAL(result_6T,   result_100T);
}

// ---------------------------------------------------------------------------
// Test 5: Doubled hashrate (spacing = T/2).
//   Blocks arrive twice as fast → algorithm should raise difficulty
//   → nextTarget ≈ powLimit/2.  Expected: 0x1f07ffffU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_double_hashrate)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // Hardcoded: spacing=T/2 → difficulty×2 → target≈powLimit/2.
    const unsigned int expected_nbits = 0x1f07ffffU;

    const int height = static_cast<int>(N + 2);
    auto blocks = BuildChain(height + 1, genesisBits, 1775674812, T / 2);

    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // Target must be strictly below powLimit (difficulty rose).
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget < powLimit);
}

// ---------------------------------------------------------------------------
// Test 6: Mixed solvetimes — pure determinism check.
//   First N/2 blocks spaced 2T, next N/2 spaced T/2; weighted mean is close
//   to T but not equal, so the target lands between powLimit and powLimit/2.
//   Expected: 0x1f0e02a8U (Python-derived).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_mixed_solvetimes_determinism)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // Hardcoded: mixed spacing [2T]*288 + [T/2]*288, Python simulation.
    const unsigned int expected_nbits = 0x1f0e02a8U;

    // Build a chain where:
    //   blocks [0 .. N+1]  use spacing T  (bootstrap zone, nBits untouched)
    //   blocks [N+2 .. N+1+N/2]  use spacing 2T
    //   blocks [N+2+N/2 .. N+1+N] use spacing T/2
    //
    // Total chain length we need is height+1 = N+2+1 = 579 if we want the
    // LWMA window [N+2-N .. N+2-1] = [2..N+1] to be all-bootstrap blocks.
    // But here we want the MIXED blocks inside the LWMA window, so we build
    // a longer chain of length (N+1) + N + 1 = 2N+2 = 1154.
    const int height = static_cast<int>(N + 1 + N); // 1153 — last block index
    std::vector<CBlockIndex> blocks(height + 1);
    {
        int64_t ts = 1775674812;
        for (int i = 0; i <= height; i++) {
            blocks[i].pprev      = i ? &blocks[i - 1] : nullptr;
            blocks[i].nHeight    = i;
            blocks[i].nTime      = static_cast<uint32_t>(ts);
            blocks[i].nBits      = genesisBits;
            blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1])
                                     : arith_uint256(0);
            // spacing selection
            int64_t spacing;
            if (i <= static_cast<int>(N + 1)) {
                spacing = T;               // bootstrap zone
            } else if (i <= static_cast<int>(N + 1 + N / 2)) {
                spacing = 2 * T;           // first half of LWMA window
            } else {
                spacing = T / 2;           // second half of LWMA window
            }
            ts += spacing;
        }
        // Fix timestamps: nTime for block i should be the arrival time OF block i,
        // so shift: block[i].nTime = ts_after_block[i-1] + spacing_i
        // Rebuild cleanly.
        ts = 1775674812;
        for (int i = 0; i <= height; i++) {
            blocks[i].nTime = static_cast<uint32_t>(ts);
            int64_t next_spacing;
            if (i < static_cast<int>(N + 1)) {
                next_spacing = T;
            } else if (i < static_cast<int>(N + 1 + N / 2)) {
                next_spacing = 2 * T;
            } else {
                next_spacing = T / 2;
            }
            ts += next_spacing;
        }
    }

    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // Must still be within [0, powLimit].
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
    BOOST_CHECK(resultTarget > arith_uint256(0));
}

// ---------------------------------------------------------------------------
// Existing proof-of-work validity tests — NOT modified.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());
/*
    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);
*/
    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);
/*
    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
*/
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_SUITE_END()
