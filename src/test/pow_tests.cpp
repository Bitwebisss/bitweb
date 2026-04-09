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
//
// These tested CalculateNextWorkRequired() — the 2016-block retargeting rule
// that is NOT used in this coin (replaced by LWMA-3).
//
// BTC's retarget formula:
//   bnNew = bnLast * actualTimespan / targetTimespan
// At ideal hashrate: actualTimespan == targetTimespan → bnNew == bnLast exactly.
// No accumulation of integer-division error because it is a single multiply + divide.
//
// LWMA-3 accumulates N=576 iterations of (target / N / k), which introduces
// a systematic rounding loss that does NOT exist in the BTC formula.
// See the LWMA-3 test section below for details.
//
// Commented out so they compile but do not run; preserved so the diff against
// upstream Bitcoin Core stays transparent.
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

// ===========================================================================
// LWMA-3 difficulty algorithm tests
// ===========================================================================
//
// Coin parameters (mainnet):
//   N = lwmaAveragingWindow  = 576
//   T = nPowTargetSpacing    = 300 s
//   k = N*(N+1)*T/2          = 49 852 800
//   genesisBits              = 0x1f0fffff  (== powLimit compact)
//   powLimit                 = 0x000fffff00..00
//   Bootstrap threshold L    = N+1 = 577
//     height <= L  → bootstrap returns genesis nBits unchanged
//     height >  L  → first real LWMA at height N+2 = 578
//                    requires chain length >= N+3 = 579
//
// ── Why does the first LWMA result differ from genesisBits by 1 LSB? ──────
//
//   The accumulator does N iterations of:
//     avgTarget += target / N / k   (two sequential integer divisions)
//   Each truncates, so avgTarget is slightly below exact. After ×k, the
//   result is a few integer units below powLimit. GetCompact() rounds DOWN
//   when the MSB of the mantissa is set → genesisBits - 1 compact LSB.
//
//   The deficit in absolute units is ~10^10; one compact LSB at this
//   exponent is 2^224 ≈ 10^67 → the error is 57 orders of magnitude below
//   the resolution of the compact format. It is NOT a mining problem.
//
// ── Direction of drift and safety ────────────────────────────────────────
//
//   The target moves DOWN (harder, not easier) from powLimit.
//   0x1f0ffffe < 0x1f0fffff → slightly harder target → CheckProofOfWork
//   still accepts it because target < powLimit (not above it).
//   Miners at powLimit difficulty find valid blocks with probability
//   1 - 10^-7 % — effectively unchanged.
//
//   Genesis block nBits is hardcoded and is NEVER touched by LWMA-3.
//   Bootstrap blocks (height <= 577) also return genesis nBits unchanged.
//
// ── Does the -1 LSB accumulate / drift further? ───────────────────────────
//
//   No. Verified by iterative Python simulation (powlimit_converter.py):
//   the chain stabilises at 0x1f0ffffe from the second post-bootstrap block
//   and remains there indefinitely at constant hashrate. The window always
//   contains enough genesisBits blocks that the computation rounds to the
//   same value. Test 3 (lwma3_stable_hashrate_no_drift) confirms this in C++.
//
// ── Hardcoded expected values (Python arith_uint256 simulation) ───────────
//
//   stable_hashrate (height N+2 = 578)  : 0x1f0ffffeU
//   stabilised from height N+3 = 579 on : 0x1f0ffffeU  (no further drift)
//   spacing = 6T (cap boundary)          : 0x1f0fffffU  (clamped to powLimit)
//   spacing = 100T (above cap)           : 0x1f0fffffU  (== 6T result)
//   spacing = T/2 (2× hashrate)          : 0x1f07ffffU  (≈ powLimit / 2)
//   mixed window (2T first + T/2 second) : 0x1f0e02a8U
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: build a chain of `count` blocks (indices 0..count-1) carrying the
// same nBits, spaced `spacing` seconds apart starting at `t0`.
// Pre-allocated so pprev pointers remain stable across loop iterations.
// LWMA-3 reads only nBits and nTime — nChainWork is unused by the algorithm
// but computed for correctness of any other tests that inspect it.
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
// Test 1: Bootstrap path.
//   pindexLast->nHeight <= N+1 must always return genesis nBits unchanged.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_bootstrap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // L = N+1 = 577 — last height that takes the bootstrap path.
    const int L = static_cast<int>(N + 1);
    auto blocks = BuildChain(L + 1, genesisBits, 1775674812, T);

    // Boundary: height == L still triggers bootstrap.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[L], nullptr, consensus), genesisBits);

    // Interior heights.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[1],     nullptr, consensus), genesisBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[N / 2], nullptr, consensus), genesisBits);
}

// ---------------------------------------------------------------------------
// Test 2: First real LWMA-3 computation.
//   pindexLast at height N+2 = 578 (height > L → LWMA path).
//   All N window blocks carry genesisBits and spacing T.
//   Expected: 0x1f0ffffeU  (genesisBits - 1 compact LSB).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_stable_hashrate)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // Chain length N+3 = 579: heights 0..578, pindexLast = blocks[578].
    // height 578 = N+2 > L=577 → first real LWMA computation.
    const int lwma_height = static_cast<int>(N + 2); // 578
    auto blocks = BuildChain(lwma_height + 1, genesisBits, 1775674812, T);

    const unsigned int expected_nbits = 0x1f0ffffeU;
    unsigned int result = GetNextWorkRequired(&blocks[lwma_height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // Target must be <= powLimit (it is powLimit - 2^224, just barely below).
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
}

// ---------------------------------------------------------------------------
// Test 3: The -1 LSB result must NOT accumulate across blocks.
//   We simulate the real chain iteratively: each block's nBits is set to
//   GetNextWorkRequired(previous block), exactly as a live node would do.
//   No actual PoW mining is performed; LWMA-3 reads only nBits and nTime
//   via pprev so modifying nBits in the vector is sufficient.
//   Expected: every block from height N+3 = 579 onwards stays at 0x1f0ffffeU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_stable_hashrate_no_drift)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;

    // Build initial chain: all genesisBits, spacing T.
    // Heights 0 .. N+2+EXTRA, where EXTRA blocks will receive computed nBits.
    const int EXTRA     = 8;
    const int chain_len = static_cast<int>(N + 3 + EXTRA); // 587
    auto blocks = BuildChain(chain_len, genesisBits, 1775674812, T);

    // For each block h starting at N+3 = 579:
    //   blocks[h].nBits = GetNextWorkRequired(&blocks[h-1], ...)
    // This is exactly what a node does when extending the chain.
    // LWMA-3 accesses nBits and nTime via pprev pointers — nChainWork
    // is not read by the algorithm so it is safe to update nBits in place.
    for (int h = static_cast<int>(N + 3); h < chain_len; h++) {
        blocks[h].nBits = GetNextWorkRequired(&blocks[h - 1], nullptr, consensus);
    }

    // Must stay at genesisBits - 1 forever; must never drop further.
    const unsigned int expected_nbits = 0x1f0ffffeU;
    for (int h = static_cast<int>(N + 3); h < chain_len; h++) {
        BOOST_CHECK_EQUAL(blocks[h].nBits, expected_nbits);
    }
}

// ---------------------------------------------------------------------------
// Test 4: powLimit cap.
//   spacing = 6T → every solvetime hits the internal cap → uncapped result
//   would be 6 × powLimit → clamped to powLimit.  Expected: 0x1f0fffffU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_powlimit_cap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits  = chainParams->GenesisBlock().nBits;
    const unsigned int powLimitBits = UintToArith256(consensus.powLimit).GetCompact();
    const arith_uint256 powLimit    = UintToArith256(consensus.powLimit);

    const int lwma_height = static_cast<int>(N + 2);
    auto blocks = BuildChain(lwma_height + 1, genesisBits, 1775674812, 6 * T);

    const unsigned int expected_nbits = 0x1f0fffffU;
    unsigned int result = GetNextWorkRequired(&blocks[lwma_height], nullptr, consensus);

    BOOST_CHECK_EQUAL(result, expected_nbits);
    BOOST_CHECK_EQUAL(result, powLimitBits);

    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
}

// ---------------------------------------------------------------------------
// Test 5: The 6T cap is symmetric — any spacing >= 6T gives the same result.
//   spacing 100T must equal spacing 6T because both are clamped internally.
//   Expected for both: 0x1f0fffffU.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_6T_solvetime_cap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;

    const int lwma_height = static_cast<int>(N + 2);
    auto blocks_6T   = BuildChain(lwma_height + 1, genesisBits, 1775674812, 6 * T);
    auto blocks_100T = BuildChain(lwma_height + 1, genesisBits, 1775674812, 100 * T);

    const unsigned int expected_nbits = 0x1f0fffffU;
    unsigned int result_6T   = GetNextWorkRequired(&blocks_6T[lwma_height],   nullptr, consensus);
    unsigned int result_100T = GetNextWorkRequired(&blocks_100T[lwma_height], nullptr, consensus);

    BOOST_CHECK_EQUAL(result_6T,   expected_nbits);
    BOOST_CHECK_EQUAL(result_100T, expected_nbits);
    BOOST_CHECK_EQUAL(result_6T,   result_100T);
}

// ---------------------------------------------------------------------------
// Test 6: Doubled hashrate — difficulty must rise, target must fall.
//   spacing = T/2 → blocks 2× faster → algorithm halves the target.
//   Expected: 0x1f07ffffU  (≈ powLimit / 2).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_double_hashrate)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    const int lwma_height = static_cast<int>(N + 2);
    auto blocks = BuildChain(lwma_height + 1, genesisBits, 1775674812, T / 2);

    const unsigned int expected_nbits = 0x1f07ffffU;
    unsigned int result = GetNextWorkRequired(&blocks[lwma_height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // Target must be strictly below powLimit (difficulty rose).
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget < powLimit);
}

// ---------------------------------------------------------------------------
// Test 7: Mixed-spacing determinism — pure regression guard.
//   The LWMA window [3..578] (N=576 blocks, all genesisBits) is split by
//   timestamp only:
//     blocks [3 .. 3+N/2-1] : spacing 2T  (288 slow blocks)
//     blocks [3+N/2 .. 578] : spacing T/2 (288 fast blocks)
//   LWMA linearly weights more recent blocks higher so the fast second half
//   dominates. Expected: 0x1f0e02a8U  (≈ 87.6 % of powLimit).
//
//   Any change to loop weights, timestamp clamping, or accumulator arithmetic
//   will produce a different compact value and fail this test.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_mixed_solvetimes_determinism)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // pindexLast at height N+2 = 578, chain length N+3 = 579.
    // blockPreviousTimestamp = block[2]; window = blocks [3..578].
    // Blocks 0..2 use spacing T (only block[2].time matters as prev_ts).
    // Blocks 3 .. 3+HALF-1 : spacing 2T.
    // Blocks 3+HALF .. N+2 : spacing T/2.
    const int HALF      = static_cast<int>(N / 2); // 288
    const int chain_len = static_cast<int>(N + 3); // 579
    std::vector<CBlockIndex> blocks(chain_len);

    int64_t ts = 1775674812;
    for (int i = 0; i < chain_len; i++) {
        blocks[i].pprev      = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight    = i;
        blocks[i].nBits      = genesisBits;
        blocks[i].nTime      = static_cast<uint32_t>(ts);
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1])
                                 : arith_uint256(0);
        // Advance timestamp for the next block.
        if      (i < 3)          ts += T;
        else if (i < 3 + HALF)   ts += 2 * T;
        else                     ts += T / 2;
    }

    const unsigned int expected_nbits = 0x1f0e02a8U;
    unsigned int result = GetNextWorkRequired(&blocks[chain_len - 1], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

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
