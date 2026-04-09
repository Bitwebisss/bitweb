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
// Test 1 (replaces get_next_work_pow_limit):
// During bootstrap (height <= N+1) LWMA3 must return genesis nBits unchanged.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_bootstrap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // Bootstrap threshold L = N + 1 = 577.
    // Build a chain that covers [0 .. L], all blocks carry genesis nBits.
    const int L = static_cast<int>(N + 1); // 577
    auto blocks = BuildChain(L + 1, genesisBits, 1775674812, T);

    // At the boundary height L the bootstrap path is still taken.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[L], nullptr, consensus), genesisBits);

    // Heights well inside the bootstrap window also return genesis nBits.
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[1],     nullptr, consensus), genesisBits);
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&blocks[N / 2], nullptr, consensus), genesisBits);
}

// ---------------------------------------------------------------------------
// Test 2 (replaces get_next_work):
// With a perfectly stable hashrate (every solvetime == T) LWMA3 must return
// the same target it received as input (genesis target == powLimit).
//
// Math: sumWeightedSolvetimes = T * N*(N+1)/2 = k
//       avgTarget             = N * (target/N/k) = target/k
//       nextTarget            = (target/k) * k   ≈ target   → capped at powLimit
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_stable_hashrate)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits; // 0x1f0fffff

    // First height past bootstrap is N+2 = 578.
    // At this height the LWMA window covers blocks [2 .. 578] (exactly N blocks).
    const int height = static_cast<int>(N + 2); // 578
    auto blocks = BuildChain(height + 1, genesisBits, 1775674812, T);

    // With ideal spacing the next target must equal the genesis target.
    // Genesis target is already at powLimit so the result is powLimit compact.
    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);
    BOOST_CHECK_EQUAL(result, genesisBits);
}

// ---------------------------------------------------------------------------
// Test 3 (replaces get_next_work_lower_limit_actual):
// The computed target must never exceed powLimit even when every solvetime is
// at the 6T cap (6 * 300 = 1800 s).
//
// Math: sumWeightedSolvetimes = 6T * N*(N+1)/2 = 6k
//       nextTarget            = (target/k) * 6k = 6 * target > powLimit  → capped
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_powlimit_cap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits   = chainParams->GenesisBlock().nBits;
    const unsigned int powLimitBits  = UintToArith256(consensus.powLimit).GetCompact();
    const arith_uint256 powLimit     = UintToArith256(consensus.powLimit);

    // Spacing of exactly 6*T hits the cap on every block.
    const int height = static_cast<int>(N + 2);
    auto blocks = BuildChain(height + 1, genesisBits, 1775674812, 6 * T);

    unsigned int result = GetNextWorkRequired(&blocks[height], nullptr, consensus);

    // Result must never be above powLimit.
    arith_uint256 resultTarget;
    resultTarget.SetCompact(result);
    BOOST_CHECK(resultTarget <= powLimit);

    // Genesis target == powLimit for this coin, so with 6T cap the algorithm
    // would compute 6 * powLimit which is then capped back to powLimit.
    BOOST_CHECK_EQUAL(result, powLimitBits);
}

// ---------------------------------------------------------------------------
// Test 4 (replaces get_next_work_upper_limit_actual):
// The 6T solvetime cap must prevent difficulty from falling further when block
// timestamps exceed 6*T.  A chain with spacing 100*T must yield exactly the
// same next target as a chain with spacing 6*T because both are capped to 6*T
// internally.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(lwma3_6T_solvetime_cap)
{
    const auto chainParams   = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus    = chainParams->GetConsensus();
    const int64_t N          = consensus.lwmaAveragingWindow; // 576
    const int64_t T          = consensus.nPowTargetSpacing;   // 300
    const unsigned int genesisBits = chainParams->GenesisBlock().nBits;

    const int height = static_cast<int>(N + 2);

    // Chain A: spacing exactly at the cap boundary (6*T = 1800 s).
    auto blocks_6T   = BuildChain(height + 1, genesisBits, 1775674812, 6 * T);
    // Chain B: spacing far above the cap (100*T); must be clamped to 6*T.
    auto blocks_100T = BuildChain(height + 1, genesisBits, 1775674812, 100 * T);

    unsigned int result_6T   = GetNextWorkRequired(&blocks_6T[height],   nullptr, consensus);
    unsigned int result_100T = GetNextWorkRequired(&blocks_100T[height], nullptr, consensus);

    // Both chains experience the same internal solvetime after capping,
    // so the computed next target must be identical.
    BOOST_CHECK_EQUAL(result_6T, result_100T);
}

// ---------------------------------------------------------------------------
// Existing tests — NOT modified.
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
