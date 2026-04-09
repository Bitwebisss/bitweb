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
// No accumulation of integer-division error because it is a single multiply+divide.
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
//   T = nPowTargetSpacing    = 300 s  (5 minutes)
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
//   The accumulator performs N iterations of:
//     avgTarget += target / N / k   (two sequential truncating integer divisions)
//   Each division truncates, so avgTarget accumulates a small deficit below
//   the exact value. After multiplying by sumWeightedSolvetimes, the result
//   is a few integer units below powLimit. GetCompact() rounds DOWN when the
//   MSB of the mantissa is set → result is genesisBits - 1 compact LSB.
//
//   The deficit in absolute units is ~10^10; one compact LSB at this exponent
//   is 2^224 ≈ 10^67 → the error is 57 orders of magnitude below the
//   resolution of the compact format. This has zero effect on mining.
//
// ── Direction of drift and safety ────────────────────────────────────────
//
//   The target moves DOWN (harder) from powLimit.
//   0x1f0ffffe < 0x1f0fffff → slightly harder target → CheckProofOfWork
//   still accepts it because target < powLimit (not above it).
//   Genesis block nBits is hardcoded and is never touched by LWMA-3.
//   Bootstrap blocks (height <= 577) also return genesis nBits unchanged.
//
// ── Does the -1 LSB accumulate / drift further? ───────────────────────────
//
//   No. The chain stabilises at 0x1f0ffffe from the second post-bootstrap
//   block and stays there indefinitely at constant hashrate. Test 3
//   (lwma3_stable_hashrate_no_drift) verifies this in C++.
//
// ── Which chain types run LWMA-3? ────────────────────────────────────────
//
//   GetNextWorkRequired() routes through three branches in order:
//     1. fPowNoRetargeting == true  → return pindexLast->nBits   (REGTEST)
//     2. fPowAllowMinDifficultyBlocks == true → return powLimit  (unused)
//     3. Lwma3CalculateNextWorkRequired()     (MAIN, SIGNET, TESTNET, TESTNET4)
//
// ── Hardcoded expected values (verified by Python arith_uint256 simulation)
//
//   stable hashrate (height N+2 = 578)   : 0x1f0ffffeU
//   stabilised from height N+3 = 579 on  : 0x1f0ffffeU  (no further drift)
//   spacing = 6T (solvetime cap boundary) : 0x1f0fffffU  (clamped to powLimit)
//   spacing = 100T (above cap)            : 0x1f0fffffU  (same as 6T)
//   spacing = T/2  (2× hashrate)          : 0x1f07ffffU  (≈ powLimit / 2)
//   mixed window   (2T slow + T/2 fast)   : 0x1f0e0d51U
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: build a linear chain of `count` blocks (indices 0..count-1).
// All blocks carry the same nBits, spaced `spacing` seconds apart from t0.
// The vector is pre-allocated so pprev pointers remain valid after the loop.
// LWMA-3 reads only nBits and nTime — nChainWork is not used by the algorithm
// but is populated so other tests that inspect it remain consistent.
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
//   Any block at height <= L = N+1 = 577 must return genesis nBits unchanged.
//   LWMA-3 requires a full window of N=576 blocks; the first valid LWMA call
//   is at height N+2 = 578.  Heights below that use the bootstrap shortcut:
//     return genesis->nBits;
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_bootstrap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // L = N+1 = 577 is the last height that still takes the bootstrap path.
    const int L = static_cast<int>(N + 1);
    auto blocks = BuildChain(L + 1, genesisBits, 1775674812, T);

    // Boundary check: height == L must still return genesis nBits.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[L], nullptr, consensus), genesisBits);

    // Interior heights must also return genesis nBits unchanged.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[1],     nullptr, consensus), genesisBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[N / 2], nullptr, consensus), genesisBits);
}

// ---------------------------------------------------------------------------
// Test 2: First real LWMA-3 computation.
//   pindexLast at height N+2 = 578 (first height above bootstrap threshold L).
//   All N=576 window blocks carry genesisBits and ideal spacing T.
//   Expected result: 0x1f0ffffeU — one compact LSB below genesisBits.
//   This is caused by the systematic truncation in (target / N / k) × N
//   iterations; the absolute error is ~10^10, negligible for mining.
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
    const int lwma_height = static_cast<int>(N + 2); // 578
    auto blocks = BuildChain(lwma_height + 1, genesisBits, 1775674812, T);

    const unsigned int expected_nbits = 0x1f0ffffeU;
    unsigned int result = GetNextWorkRequired(&blocks[lwma_height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    // The resulting target must be at or below powLimit.
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
}

// ---------------------------------------------------------------------------
// Test 3: Rounding error must NOT accumulate across successive blocks.
//   Simulate the live chain: each block's nBits is set to the value returned
//   by GetNextWorkRequired for the previous block, exactly as a full node does.
//   No actual PoW is performed; LWMA-3 reads only nBits and nTime via pprev,
//   so updating nBits in the vector is sufficient.
//   Expected: every block from height N+3 = 579 onward stays at 0x1f0ffffeU.
//   A drift would indicate a compounding accumulator bug.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_stable_hashrate_no_drift)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;

    const int EXTRA     = 8;
    const int chain_len = static_cast<int>(N + 3 + EXTRA); // 587
    auto blocks = BuildChain(chain_len, genesisBits, 1775674812, T);

    // Propagate difficulty: each block from N+3 onward gets the computed nBits.
    for (int h = static_cast<int>(N + 3); h < chain_len; h++) {
        blocks[h].nBits = GetNextWorkRequired(&blocks[h - 1], nullptr, consensus);
    }

    // Difficulty must stabilise at genesisBits - 1 LSB and never drop further.
    const unsigned int expected_nbits = 0x1f0ffffeU;
    for (int h = static_cast<int>(N + 3); h < chain_len; h++) {
        BOOST_CHECK_EQUAL(blocks[h].nBits, expected_nbits);
    }
}

// ---------------------------------------------------------------------------
// Test 4: powLimit cap — very slow blocks must not produce a target above
//   powLimit.
//   spacing = 6T → every solvetime hits the internal 6T cap → uncapped result
//   would be ~6× powLimit → clamped to exactly powLimit.
//   Expected: 0x1f0fffffU == powLimit compact.
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
// Test 5: The 6T solvetime cap is symmetric — any spacing >= 6T yields the
//   same result as exactly 6T, because every solvetime is clamped to
//   min(6T, actual) before being used.
//   Expected for both 6T and 100T: 0x1f0fffffU.
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
//   spacing = T/2 → blocks arrive twice as fast → algorithm halves the target.
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

    // Target must be strictly below powLimit — difficulty increased.
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget < powLimit);
}

// ---------------------------------------------------------------------------
// Test 7: Mixed-spacing determinism — pure regression guard.
//   The LWMA window [3..578] (N=576 blocks, all carrying genesisBits) is split
//   into two halves by timestamp only:
//     blocks [3 .. 3+N/2-1]  : spacing 2T  (288 slow blocks)
//     blocks [3+N/2 .. 578]  : spacing T/2 (288 fast blocks)
//   Because LWMA weights recent blocks linearly higher, the fast second half
//   dominates and the result is between powLimit/2 and powLimit.
//   Expected: 0x1f0e0d51U  (verified by Python arith_uint256 simulation).
//
//   Any modification to loop weights, timestamp clamping, or accumulator
//   arithmetic will produce a different compact value and fail this test.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_mixed_solvetimes_determinism)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const int64_t T        = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // Build chain length N+3 = 579 (pindexLast = blocks[578]).
    // Blocks 0..2: spacing T  (anchor; only blocks[2].nTime matters as prev_ts).
    // Blocks 3..290 (first HALF=288): spacing 2T  — slow miners.
    // Blocks 291..578 (second HALF=288): spacing T/2 — fast miners.
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
        // Advance the timestamp for the next block.
        if      (i < 3)          ts += T;
        else if (i < 3 + HALF)   ts += 2 * T;
        else                     ts += T / 2;
    }

    // 0x1f0e0d51 verified independently by Python arith_uint256 simulation.
    const unsigned int expected_nbits = 0x1f0e0d51U;
    unsigned int result = GetNextWorkRequired(&blocks[chain_len - 1], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, expected_nbits);

    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);
    BOOST_CHECK(resultTarget > arith_uint256(0));
}

// ---------------------------------------------------------------------------
// Test 8: fPowNoRetargeting — regtest shortcut.
//   When fPowNoRetargeting is true (REGTEST), GetNextWorkRequired must return
//   pindexLast->nBits unchanged regardless of chain length or timestamps.
//   This is the first branch in GetNextWorkRequired and completely bypasses
//   LWMA-3, keeping difficulty fixed for local development and unit testing.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_no_retargeting)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const auto& consensus  = chainParams->GetConsensus();
    // Pre-condition: regtest must have fPowNoRetargeting enabled.
    BOOST_REQUIRE(consensus.fPowNoRetargeting);

    const int64_t N = consensus.lwmaAveragingWindow;
    const int64_t T = consensus.nPowTargetSpacing;

    // Use an arbitrary nBits value that is clearly not powLimit.
    const unsigned int someBits = 0x207fffffU;
    auto blocks = BuildChain(static_cast<int>(N + 3), someBits, 1775674812, T);

    unsigned int result = GetNextWorkRequired(&blocks[N + 2], nullptr, consensus);
    // Must return the parent's nBits without any LWMA calculation.
    BOOST_CHECK_EQUAL(result, someBits);
}

// ---------------------------------------------------------------------------
// Test 9: LWMA-3 runs on TESTNET and TESTNET4.
//   fPowAllowMinDifficultyBlocks is disabled on both testnets so real
//   difficulty adjustment runs exactly as on mainnet.
//   Verifies:
//     - both flags are in the correct state (no-retargeting off, min-diff off)
//     - GetNextWorkRequired returns a real LWMA result (not powLimit)
//     - result is a valid target at or below powLimit
//     - bootstrap path still works on testnets (height <= L returns genesis nBits)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_testnet_runs_lwma)
{
    auto check = [&](ChainType ct) {
        const auto chainParams = CreateChainParams(*m_node.args, ct);
        const auto& consensus  = chainParams->GetConsensus();

        // Pre-conditions: LWMA must be the active path on testnets.
        BOOST_REQUIRE(!consensus.fPowAllowMinDifficultyBlocks);
        BOOST_REQUIRE(!consensus.fPowNoRetargeting);

        const int64_t N        = consensus.lwmaAveragingWindow;
        const int64_t T        = consensus.nPowTargetSpacing;
        const unsigned int genesisBits  = chainParams->GenesisBlock().nBits;
        const unsigned int powLimitBits = UintToArith256(consensus.powLimit).GetCompact();
        const arith_uint256 powLimit    = UintToArith256(consensus.powLimit);

        const int lwma_height = static_cast<int>(N + 2);
        auto blocks = BuildChain(lwma_height + 1, genesisBits, 1762681892, T);

        // Past bootstrap threshold: LWMA runs and result differs from powLimit
        // by exactly 1 compact LSB (same truncation behaviour as mainnet).
        unsigned int result = GetNextWorkRequired(&blocks[lwma_height], nullptr, consensus);
        BOOST_CHECK(result != powLimitBits);

        // Result must be a valid target at or below powLimit.
        arith_uint256 resultTarget;
        resultTarget.SetCompact(result);
        BOOST_CHECK(resultTarget <= powLimit);
        BOOST_CHECK(resultTarget > arith_uint256(0));

        // Bootstrap path must still work on testnets:
        // height <= L = N+1 returns genesis nBits unchanged.
        const int L = static_cast<int>(N + 1);
        auto bootstrap_blocks = BuildChain(L + 1, genesisBits, 1762681892, T);
        unsigned int bootstrap_result = GetNextWorkRequired(&bootstrap_blocks[L], nullptr, consensus);
        BOOST_CHECK_EQUAL(bootstrap_result, genesisBits);
    };

    check(ChainType::TESTNET);
    check(ChainType::TESTNET4);
}

// ---------------------------------------------------------------------------
// Test 10: Duplicate timestamps — protection against negative or zero solvetimes.
//   When a block's timestamp is <= the running previousTimestamp, LWMA-3
//   forces it forward by 1 second:
//     thisTimestamp = (block->GetBlockTime() > previousTimestamp)
//                     ? block->GetBlockTime() : previousTimestamp + 1;
//   This test exercises that branch by giving every block the same nTime.
//   With all solvetimes forced to 1 second, the algorithm sees extremely fast
//   block production and must raise difficulty well above powLimit / 2.
//   The result must be a valid compact value (non-zero, <= powLimit).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_duplicate_timestamps)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N        = consensus.lwmaAveragingWindow; // 576
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const arith_uint256 powLimit   = UintToArith256(consensus.powLimit);

    // spacing = 0 → every block has the same nTime = t0.
    auto blocks = BuildChain(static_cast<int>(N + 3), genesisBits, 1775674812, 0);

    unsigned int result = GetNextWorkRequired(&blocks[N + 2], nullptr, consensus);
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);

    // Result must be a valid, positive target that does not exceed powLimit.
    BOOST_CHECK(resultTarget > arith_uint256(0));
    BOOST_CHECK(resultTarget <= powLimit);
    // With every solvetime = 1s the algorithm perceives massive hashrate;
    // target must be well below powLimit/2 (difficulty well above midpoint).
    BOOST_CHECK(resultTarget < UintToArith256(consensus.powLimit) / 2);
}

// ---------------------------------------------------------------------------
// Test 11: Monotonicity — higher hashrate must always produce a harder target.
//   At spacing T/3 (3× hashrate) the returned target must be strictly smaller
//   than at spacing T/2 (2× hashrate).  This validates the core property that
//   LWMA-3 responds correctly to increasing hashrate.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_monotone_difficulty)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus  = chainParams->GetConsensus();
    const int64_t N = consensus.lwmaAveragingWindow; // 576
    const int64_t T = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;
    const int lwma_height = static_cast<int>(N + 2);

    auto blocks_2x = BuildChain(lwma_height + 1, genesisBits, 1775674812, T / 2); // 150 s
    auto blocks_3x = BuildChain(lwma_height + 1, genesisBits, 1775674812, T / 3); // 100 s

    unsigned int result_2x = GetNextWorkRequired(&blocks_2x[lwma_height], nullptr, consensus);
    unsigned int result_3x = GetNextWorkRequired(&blocks_3x[lwma_height], nullptr, consensus);

    arith_uint256 target_2x, target_3x;
    target_2x.SetCompact(result_2x);
    target_3x.SetCompact(result_3x);

    // 3× hashrate → target must be strictly smaller (harder) than 2× hashrate.
    BOOST_CHECK(target_3x < target_2x);
}

// ---------------------------------------------------------------------------
// Existing proof-of-work validity tests — unchanged from upstream.
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
    hash_arith *= 2; // hash > nBits → must be rejected
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

// ---------------------------------------------------------------------------
// Chain-parameter sanity checks — run for every network type.
//
// In addition to the upstream checks (genesis hash, nBits validity), we verify
// the PoW routing mode for each chain so that any accidental change to
// chainparams.cpp that flips a difficulty flag is caught immediately.
//
//   Chain     | fPowNoRetargeting | fPowAllowMinDifficultyBlocks | LWMA runs?
//   ----------+-------------------+------------------------------+-----------
//   MAIN      | false             | false                        | yes
//   TESTNET   | false             | false                        | yes
//   TESTNET4  | false             | false                        | yes
//   SIGNET    | false             | false                        | yes
//   REGTEST   | true              | —                            | no (branch 1)
// ---------------------------------------------------------------------------
void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // Genesis block hash must match the value committed in chainparams.cpp.
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    /*
        // target timespan is an even multiple of spacing
        BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);
    */

    // Genesis nBits must be positive, must not overflow the compact format,
    // and must represent a target at or below powLimit.
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    /*
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    */

    // lwmaAveragingWindow must always be a positive value even if LWMA does
    // not run on this chain — prevents division-by-zero should routing change.
    BOOST_CHECK(consensus.lwmaAveragingWindow > 0);

    // Verify the expected PoW routing mode per chain type.
    // These checks catch accidental flag changes in chainparams.cpp.
    switch (chain_type) {
    case ChainType::MAIN:
        // Full LWMA-3 path: neither shortcut must be active.
        BOOST_CHECK(!consensus.fPowNoRetargeting);
        BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
        break;
    case ChainType::TESTNET:
    case ChainType::TESTNET4:
        // Full LWMA-3 path: same routing as mainnet.
        // fPowAllowMinDifficultyBlocks is disabled — real difficulty
        // adjustment runs on testnets instead of always returning powLimit.
        BOOST_CHECK(!consensus.fPowNoRetargeting);
        BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
        break;
    case ChainType::SIGNET:
        // Full LWMA-3 path: same routing as mainnet (no shortcuts).
        BOOST_CHECK(!consensus.fPowNoRetargeting);
        BOOST_CHECK(!consensus.fPowAllowMinDifficultyBlocks);
        break;
    case ChainType::REGTEST:
        // No-retargeting shortcut: nBits never changes, fastest for testing.
        BOOST_CHECK(consensus.fPowNoRetargeting);
        break;
    }
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
