// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Bitweb Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

/* Bitweb Params */
#include <crypto/argon2d/argon2.h>
/* Bitweb Params */
#include <hash.h>
#include <streams.h>
#include <tinyformat.h>
#include <node/protocol_version.h>

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

/* Bitweb Params */
/*
 * Compute the Argon2id proof-of-work hash of this block header.
 *
 * The serialized 80-byte block header is used as both the password and
 * the salt input to argon2id_hash_raw. Using the header for both roles
 * keeps the construction simple and self-contained: the salt is fully
 * determined by the header itself, requiring no additional hash or
 * pre-processing step.
 *
 * CDataStream is used to produce the canonical little-endian serialization
 * of the block header. Direct struct casting is avoided as it depends on
 * ABI layout and is not safe across compilers.
 *
 * Parameters (consensus-critical, must not be changed):
 *   t (time cost)   = 3        -- number of passes over memory
 *   m (memory cost) = 1024 KiB -- fits in CPU L2 cache, penalises GPU
 *   p (parallelism) = 1        -- single-threaded per hash attempt
 */
uint256 CBlockHeader::GetArgon2idPoWHash() const
{
    static constexpr uint32_t ARGON2ID_TIME_COST   = 3;
    static constexpr uint32_t ARGON2ID_MEM_COST_KB = 1024;
    static constexpr uint32_t ARGON2ID_PARALLELISM = 1;
    static constexpr size_t   ARGON2ID_HASH_LEN    = 32;

    // Serialize the block header (80 bytes: version, hashPrevBlock,
    // hashMerkleRoot, nTime, nBits, nNonce).
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;

    // Compute Argon2id hash. The serialized header serves as both the
    // password and the salt. argon2id_hash_raw requires salt >= 8 bytes;
    // the 80-byte header satisfies this with ample margin.
    uint256 hash;
    const int rc = argon2id_hash_raw(
        ARGON2ID_TIME_COST,
        ARGON2ID_MEM_COST_KB,
        ARGON2ID_PARALLELISM,
        ss.data(), ss.size(),  /* password */
        ss.data(), ss.size(),  /* salt     */
        hash.begin(), ARGON2ID_HASH_LEN
    );

    // argon2id_hash_raw must not fail for well-formed parameters.
    // Any failure here indicates a programming error or memory exhaustion
    // and is treated as a fatal condition.
    assert(rc == ARGON2_OK);

    return hash;
}
/* Bitweb Params */

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
