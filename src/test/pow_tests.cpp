// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Bitweb Core developers
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
 
// ─── Helper: build a linked chain of N CBlockIndex blocks ────────────────────
// Returns a vector; blocks[0] = genesis, blocks.back() = tip.
// hr_fn(height) → relative hashrate multiplier (1.0 = normal).
// ts_fn(height, prev_ts) → timestamp override (nullptr = use T*j spacing).
static std::vector<CBlockIndex> BuildChain(
    const Consensus::Params& params,
    int                      n_blocks,
    std::function<double(int)>         hr_fn  = nullptr,
    std::function<int64_t(int,int64_t)> ts_fn = nullptr)
{
    std::vector<CBlockIndex> blocks(n_blocks);
 
    const int64_t T      = params.nPowTargetSpacing;
    const int64_t N      = params.lwmaAveragingWindow;
    const int64_t L      = N + 1;
 
    int64_t ts = 1775674812; // genesis timestamp
 
    blocks[0].nHeight    = 0;
    blocks[0].nTime      = ts;
    blocks[0].nBits      = 0x1f0fffff; // genesis nBits
    blocks[0].pprev      = nullptr;
    blocks[0].nChainWork = arith_uint256(0);
 
    for (int h = 1; h < n_blocks; ++h) {
        blocks[h].pprev      = &blocks[h - 1];
        blocks[h].nHeight    = h;
 
        // compute nBits via LWMA (or genesis during bootstrap)
        blocks[h].nBits = GetNextWorkRequired(&blocks[h - 1], nullptr, params);
 
        // timestamp
        if (ts_fn) {
            ts = ts_fn(h, ts);
        } else {
            double hr = hr_fn ? hr_fn(h) : 1.0;
            int64_t spacing = static_cast<int64_t>(T / hr);
            ts += std::max<int64_t>(1, spacing);
        }
        blocks[h].nTime = ts;
 
        blocks[h].nChainWork = blocks[h - 1].nChainWork + GetBlockProof(blocks[h - 1]);
    }
 
    return blocks;
}
 
// ─── Helper: arith_uint256 difficulty relative to genesis ────────────────────
static double RelDiff(unsigned int bits, unsigned int genesis_bits)
{
    arith_uint256 g, t;
    g.SetCompact(genesis_bits);
    t.SetCompact(bits);
    if (t == 0) return std::numeric_limits<double>::infinity();
    // difficulty = genesis_target / target  (higher = harder)
    // use double approximation
    return (double)g.GetLow64() / (double)t.GetLow64(); // rough but fine for tests
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 1: Regtest – always returns pindexLast->nBits (fPowNoRetargeting)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_regtest_no_retargeting)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::REGTEST);
    const Consensus::Params& params = chainParams->GetConsensus();
    BOOST_REQUIRE(params.fPowNoRetargeting);
 
    CBlockIndex tip;
    tip.nHeight = 1000;
    tip.nTime   = 1775674812 + 1000 * 300;
    tip.nBits   = 0x1e012345; // arbitrary
 
    unsigned int result = GetNextWorkRequired(&tip, nullptr, params);
    BOOST_CHECK_EQUAL(result, tip.nBits);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 2: Testnet – always returns powLimit (fPowAllowMinDifficultyBlocks)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_testnet_min_difficulty)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::TESTNET);
    const Consensus::Params& params = chainParams->GetConsensus();
    BOOST_REQUIRE(params.fPowAllowMinDifficultyBlocks);
 
    CBlockIndex tip;
    tip.nHeight = 5000;
    tip.nTime   = 1775674812 + 5000 * 300;
    tip.nBits   = 0x1c000001;
 
    unsigned int result   = GetNextWorkRequired(&tip, nullptr, params);
    unsigned int powlimit = UintToArith256(params.powLimit).GetCompact();
    BOOST_CHECK_EQUAL(result, powlimit);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 3: Bootstrap – first L=N+1 blocks always return genesis nBits
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_bootstrap_returns_genesis)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow; // 576
    const int64_t L = N + 1;                      // 577
 
    // Build just enough blocks to cover bootstrap + 2 LWMA blocks
    auto chain = BuildChain(params, static_cast<int>(L + 3));
 
    unsigned int genesis_bits = chain[0].nBits;
 
    // Every block from h=1 to h=L (inclusive) must return genesis nBits
    for (int h = 1; h <= static_cast<int>(L); ++h) {
        unsigned int got = GetNextWorkRequired(&chain[h], nullptr, params);
        BOOST_CHECK_MESSAGE(got == genesis_bits,
            "Bootstrap fail at h=" << h << ": got 0x" << std::hex << got
            << " expected 0x" << genesis_bits);
    }
 
    // h=L+1 is the first real LWMA block – must differ unless perfectly T-spaced
    // Just check it does not assert/crash and returns something <= powLimit
    unsigned int first_lwma = GetNextWorkRequired(&chain[L + 1], nullptr, params);
    arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 result;
    result.SetCompact(first_lwma);
    BOOST_CHECK(result <= pow_limit);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 4: Stable hashrate – avg solvetime must converge to T
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_stable_hashrate_convergence)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // Build chain with exactly T seconds between every block
    auto chain = BuildChain(params, static_cast<int>(L + N + 100),
        nullptr,
        [&](int h, int64_t prev_ts) { return prev_ts + T; });
 
    // After warmup (L + N blocks), all blocks should have genesis nBits
    // because perfect T spacing keeps difficulty at genesis level
    unsigned int genesis_bits = chain[0].nBits;
 
    for (int h = static_cast<int>(L + 1); h < static_cast<int>(chain.size()); ++h) {
        // Allow 1 compact step of precision loss
        unsigned int got = chain[h].nBits;
        unsigned int expected = genesis_bits;
        BOOST_CHECK_MESSAGE(got == expected || got == expected - 1 || got == expected + 1,
            "Stable T: h=" << h << " bits=0x" << std::hex << got
            << " expected ~0x" << expected);
    }
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 5: 6T cap – a single block with 100*T solvetime must not collapse diff
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_6T_cap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // Build stable chain past bootstrap
    auto chain = BuildChain(params, static_cast<int>(L + 50),
        nullptr,
        [&](int h, int64_t prev_ts) { return prev_ts + T; });
 
    unsigned int bits_before = chain.back().nBits;
 
    // Add one block with a huge timestamp gap (100*T)
    CBlockIndex huge;
    huge.pprev   = &chain.back();
    huge.nHeight = static_cast<int>(chain.size());
    huge.nTime   = chain.back().nTime + 100 * T;
    huge.nBits   = GetNextWorkRequired(&chain.back(), nullptr, params);
    chain.push_back(huge); // extend vector manually is OK for this test
 
    unsigned int bits_after = GetNextWorkRequired(&chain.back(), nullptr, params);
 
    // Difficulty should not drop more than 6x (because 6T cap limits each solvetime)
    // In practice with N=576 one block barely moves the needle
    arith_uint256 t_before, t_after;
    t_before.SetCompact(bits_before);
    t_after.SetCompact(bits_after);
 
    // target_after / target_before < 7 (less than 7x easier)
    BOOST_CHECK_MESSAGE(t_after < t_before * 7,
        "6T cap fail: difficulty dropped more than 7x from one block");
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 6: powLimit cap – when all solvetimes are maximum (6T), must cap
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_powlimit_cap)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // All blocks spaced 6*T apart → LWMA wants target above powLimit → must cap
    auto chain = BuildChain(params, static_cast<int>(L + 10),
        nullptr,
        [&](int h, int64_t prev_ts) { return prev_ts + 6 * T; });
 
    unsigned int result = GetNextWorkRequired(&chain.back(), nullptr, params);
    unsigned int powlimit_compact = UintToArith256(params.powLimit).GetCompact();
 
    BOOST_CHECK_EQUAL(result, powlimit_compact);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 7: Timestamp backward – LWMA must not go negative (previousTimestamp+1)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_backward_timestamp_safety)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // Build normal chain
    auto chain = BuildChain(params, static_cast<int>(L + 50),
        nullptr,
        [&](int h, int64_t prev_ts) { return prev_ts + T; });
 
    unsigned int bits_normal = GetNextWorkRequired(&chain.back(), nullptr, params);
 
    // Add 20 blocks all with timestamps going backwards (attacker)
    int64_t ts = chain.back().nTime;
    for (int i = 0; i < 20; ++i) {
        CBlockIndex b;
        b.pprev   = &chain.back();
        b.nHeight = chain.back().nHeight + 1;
        ts        = ts - 100; // 100s backwards each time
        b.nTime   = ts;
        b.nBits   = GetNextWorkRequired(&chain.back(), nullptr, params);
        chain.push_back(b);
    }
 
    unsigned int bits_after_attack = GetNextWorkRequired(&chain.back(), nullptr, params);
 
    // Difficulty must not have collapsed (ratio < 10x easier)
    arith_uint256 t_normal, t_after;
    t_normal.SetCompact(bits_normal);
    t_after.SetCompact(bits_after_attack);
 
    BOOST_CHECK_MESSAGE(t_after < t_normal * 10,
        "Backward timestamps caused difficulty collapse: "
        << std::hex << bits_after_attack << " vs " << bits_normal);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 8: Hashrate surge 10x → difficulty rises, no crash on return
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_hashrate_surge_10x)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // 200 stable blocks, then 200 blocks at T/10 (10x faster hashrate)
    int attack_start = static_cast<int>(L + 200);
    int attack_end   = attack_start + 200;
    int total        = attack_end + 50;
 
    int64_t ts = 1775674812;
    auto chain = BuildChain(params, total,
        nullptr,
        [&](int h, int64_t prev_ts) -> int64_t {
            if (h >= attack_start && h < attack_end)
                return prev_ts + T / 10; // 10x faster
            return prev_ts + T;
        });
 
    // During attack blocks should be faster
    int64_t st_attack = chain[attack_start + 10].nTime - chain[attack_start + 9].nTime;
    BOOST_CHECK_MESSAGE(st_attack <= T,
        "During 10x surge blocks should be at most T apart, got " << st_attack);
 
    // After attack, difficulty should be higher than before
    arith_uint256 t_pre, t_post;
    t_pre.SetCompact(chain[attack_start - 1].nBits);
    t_post.SetCompact(chain[attack_end].nBits);
    BOOST_CHECK_MESSAGE(t_post <= t_pre,
        "After 10x surge difficulty should be >= pre-surge difficulty");
 
    // Chain must still produce valid blocks (not stuck)
    arith_uint256 pow_limit = UintToArith256(params.powLimit);
    arith_uint256 t_final;
    t_final.SetCompact(chain.back().nBits);
    BOOST_CHECK(t_final <= pow_limit);
    BOOST_CHECK(t_final > 0);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 9: Hashrate crash 90% → chain continues, not stuck
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_hashrate_crash_90pct)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    int crash_at = static_cast<int>(L + 100);
    int total    = crash_at + static_cast<int>(N) + 50;
 
    auto chain = BuildChain(params, total,
        nullptr,
        [&](int h, int64_t prev_ts) -> int64_t {
            if (h >= crash_at)
                return prev_ts + T * 10; // 10x slower = 90% hashrate loss
            return prev_ts + T;
        });
 
    // After N blocks at 10x spacing, target should move toward powLimit
    arith_uint256 t_pre, t_post, pow_limit;
    t_pre.SetCompact(chain[crash_at - 1].nBits);
    t_post.SetCompact(chain.back().nBits);
    pow_limit = UintToArith256(params.powLimit);
 
    // Target must be larger (easier) after crash
    BOOST_CHECK_MESSAGE(t_post >= t_pre,
        "After hashrate crash target should have risen");
 
    // Must not exceed powLimit
    BOOST_CHECK(t_post <= pow_limit);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 10: All solvetime = 1s → difficulty multiplier ≈ T (max hardening)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_min_solvetime_max_difficulty)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    const int64_t N = params.lwmaAveragingWindow;
    const int64_t L = N + 1;
    const int64_t T = params.nPowTargetSpacing;
 
    // All blocks exactly 1s apart → maximum possible difficulty increase
    auto chain = BuildChain(params, static_cast<int>(L + N + 5),
        nullptr,
        [&](int h, int64_t prev_ts) { return prev_ts + 1; });
 
    unsigned int bits_last = chain.back().nBits;
    unsigned int genesis_bits = chain[0].nBits;
 
    arith_uint256 t_genesis, t_last;
    t_genesis.SetCompact(genesis_bits);
    t_last.SetCompact(bits_last);
 
    // Difficulty should be ≈ T times genesis difficulty
    // t_last ≈ t_genesis / T
    // So t_genesis / t_last ≈ T = 300
    // Allow ±10% tolerance
    arith_uint256 ratio = t_genesis / t_last;
    uint64_t ratio_approx = ratio.GetLow64();
    BOOST_CHECK_MESSAGE(ratio_approx > static_cast<uint64_t>(T * 0.9)
                     && ratio_approx < static_cast<uint64_t>(T * 1.1),
        "Min solvetime: diff multiplier=" << ratio_approx
        << " expected ~T=" << T);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 11: genesis nBits <= powLimit (sanity already in chainparams but explicit)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_genesis_bits_vs_powlimit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    arith_uint256 genesis_target, pow_limit;
    genesis_target.SetCompact(chainParams->GenesisBlock().nBits);
    pow_limit = UintToArith256(params.powLimit);
 
    BOOST_CHECK_MESSAGE(genesis_target <= pow_limit,
        "genesis target must be <= powLimit");
 
    // Also verify k = N*(N+1)*T/2 fits in int64
    int64_t N = params.lwmaAveragingWindow;
    int64_t T = params.nPowTargetSpacing;
    // N*(N+1) max = 576*577 = 332352, *300 = 99705600, /2 = 49852800 << INT64_MAX
    __int128 k_check = (__int128)N * (N + 1) * T / 2;
    BOOST_CHECK_MESSAGE(k_check < ((__int128)1 << 62),
        "k overflows int64_t: " << (int64_t)k_check);
}
 
// ─────────────────────────────────────────────────────────────────────────────
// TEST 12: PermittedDifficultyTransition always returns true (LWMA: no limits)
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(lwma_permitted_difficulty_transition)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const Consensus::Params& params = chainParams->GetConsensus();
 
    // Any transition is permitted in LWMA
    BOOST_CHECK(PermittedDifficultyTransition(params, 1000, 0x1f0fffff, 0x1f0fffff));
    BOOST_CHECK(PermittedDifficultyTransition(params, 1000, 0x1f0fffff, 0x1c000001));
    BOOST_CHECK(PermittedDifficultyTransition(params, 1000, 0x1c000001, 0x1f0fffff));
    BOOST_CHECK(PermittedDifficultyTransition(params, 1000, 0x1d00ffff, 0x1a00ffff));
}
 
// ─────────────────────────────────────────────────────────────────────────────
// Existing CheckProofOfWork tests (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
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
    hash_arith *= 2;
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
        blocks[i].pprev      = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight    = i;
        blocks[i].nTime      = 1775674812 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits      = 0x1f0fffff;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1])
                                 : arith_uint256(0);
    }
    for (int j = 0; j < 1000; j++) {
        CBlockIndex* p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex* p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex* p3 = &blocks[m_rng.randrange(10000)];
        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}
 
// ─────────────────────────────────────────────────────────────────────────────
// ChainParams sanity (kept, with LWMA-specific checks, BTC-specific commented)
// ─────────────────────────────────────────────────────────────────────────────
void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus   = chainParams->GetConsensus();
 
    // genesis hash is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());
 
    // genesis nBits: positive, no overflow, <= powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);
 
    // LWMA: lwmaAveragingWindow must be positive
    BOOST_CHECK_GT(consensus.lwmaAveragingWindow, 0);
 
    // LWMA: k = N*(N+1)*T/2 must not overflow int64
    {
        __int128 N = consensus.lwmaAveragingWindow;
        __int128 T = consensus.nPowTargetSpacing;
        __int128 k = N * (N + 1) * T / 2;
        BOOST_CHECK_MESSAGE(k > 0 && k < ((__int128)1 << 62),
            "k overflows int64_t for chain type " << static_cast<int>(chain_type));
    }
 
    /*
    // BTC-specific: target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);
 
    // BTC-specific: check max target * 4*nPowTargetTimespan doesn't overflow
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
    */
}
 
BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)    { sanity_check_chainparams(*m_node.args, ChainType::MAIN);     }
BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity) { sanity_check_chainparams(*m_node.args, ChainType::REGTEST);  }
BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity) { sanity_check_chainparams(*m_node.args, ChainType::TESTNET);  }
BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity){ sanity_check_chainparams(*m_node.args, ChainType::TESTNET4); }
BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)  { sanity_check_chainparams(*m_node.args, ChainType::SIGNET);   }
 
BOOST_AUTO_TEST_SUITE_END()