#!/usr/bin/env python3
"""
Converts rpc_validateaddress.py test vectors to an arbitrary HRP.

Usage:
    cd test/functional
    python3 gen_validateaddress_vectors.py

Output: ready-to-paste INVALID_DATA and VALID_DATA blocks for rpc_validateaddress.py.

────────────────────────────────────────────────────────────────────────────────
HOW IT WORKS
────────────────────────────────────────────────────────────────────────────────
A bech32/bech32m address has three parts:
    <hrp> '1' <data+checksum>

The data+checksum section encodes:
    - witness version (1 character)
    - witness program (arbitrary bytes)
    - checksum (6 characters, computed from hrp)

When the HRP changes, only the checksum changes. The witness version and program
stay identical. So conversion is simply: decode(src_hrp) -> encode(dst_hrp).

Addresses with a "wrong" HRP (tc1...) test rejection due to HRP mismatch —
they do not need conversion and are kept as-is.

error_locations are character positions in the address string that the node
considers erroneous. They are determined by the node, not by us. For addresses
that carry error_locations we therefore construct the address such that the bad
character lands at exactly the required position:

    [41] — bad checksum: take a valid dst_hrp p2wpkh address, corrupt char at 41
    [40] — mixed case:   take an UPPERCASE dst_hrp p2wpkh address, lowercase char 40
    [59] — invalid char: take a valid dst_hrp p2tr address, inject 'b' at position 59
           ('b' is absent from the bech32 charset, so the node will report that position)
────────────────────────────────────────────────────────────────────────────────
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "test_framework"))
from segwit_addr import bech32_encode, bech32_decode, Encoding

# ── Configuration ────────────────────────────────────────────────────────────
DST_HRP = "bte"   # target HRP (your fork's mainnet human-readable part)
# ─────────────────────────────────────────────────────────────────────────────

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def reencode(addr: str, dst_hrp: str, force_upper: bool = False) -> str:
    """
    Decode a bech32/bech32m address with any HRP and re-encode it with dst_hrp.
    Witness version and program are preserved; only the checksum is recomputed.
    Returns None if the address cannot be decoded.
    """
    encoding, _hrp, data = bech32_decode(addr.lower())
    if encoding is None:
        return None
    result = bech32_encode(encoding, dst_hrp, data)
    return result.upper() if force_upper else result


def corrupt_at(addr: str, pos: int) -> str:
    """
    Replace the character at position pos with the first different character
    from the bech32 alphabet. Used to produce an address with a known-bad
    checksum at a specific position.
    """
    chars = list(addr)
    original = chars[pos]
    for c in BECH32_CHARSET:
        if c != original:
            chars[pos] = c
            break
    return "".join(chars)


def inject_invalid_char_at(addr: str, pos: int, char: str = "b") -> str:
    """
    Place a character that is not in the bech32 alphabet at position pos.
    'b' is absent from BECH32_CHARSET, so the node will report an error at
    exactly that position.
    """
    chars = list(addr)
    chars[pos] = char
    return "".join(chars)


def main():
    hrp = DST_HRP

    # ── Addresses with specific error_locations ───────────────────────────────

    # [41] "Invalid Bech32 checksum"
    # Valid p2wpkh address for dst_hrp, 43 characters long.
    # Corrupt the character at position 41; the node will locate the error there.
    valid_p2wpkh = reencode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", hrp)
    bad_checksum_41 = corrupt_at(valid_p2wpkh, 41)

    # [40] "Invalid character or mixed case"
    # Same p2wpkh address in UPPERCASE; lowercase the character at position 40.
    # The node treats mixed case as an error and reports the first lowercase character.
    valid_p2wpkh_uc = reencode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", hrp, force_upper=True)
    chars = list(valid_p2wpkh_uc)
    chars[40] = chars[40].lower()
    mixed_case_40 = "".join(chars)

    # [59] "Invalid Base 32 character"
    # Valid p2tr address for dst_hrp, 63 characters long.
    # Inject 'b' at position 59 — a character outside the bech32 alphabet.
    valid_p2tr = reencode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", hrp)
    bad_char_59 = inject_invalid_char_at(valid_p2tr, 59)

    # ── Print INVALID_DATA ────────────────────────────────────────────────────
    print("INVALID_DATA = [")
    print("    # BIP 173")

    rows = [
        # tc1 addresses test wrong HRP rejection; leave them unchanged.
        ("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# Invalid hrp"),

        (bad_checksum_41,
         "Invalid Bech32 checksum",
         "[41]", ""),

        (reencode("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", hrp, force_upper=True),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", ""),

        (reencode("bc1rw5uspcuh", hrp),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", "# Invalid program length"),

        (reencode("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", hrp),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", "# Invalid program length"),

        (reencode("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", hrp, force_upper=True),
         "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
         "[]", ""),

        # tc1 — wrong HRP + mixed case; leave unchanged.
        ("tc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Mixed case"),

        (mixed_case_40,
         "Invalid character or mixed case",
         "[40]", f"# {hrp}1, Mixed case, not in BIP 173 test vectors"),

        (reencode("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", hrp),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", "# Wrong padding"),

        # tc1 — wrong HRP; leave unchanged.
        ("tc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Non-zero padding in 8-to-5 conversion"),

        (reencode("bc1gmk9yu", hrp),
         "Empty Bech32 data section",
         "[]", ""),
    ]

    for addr, error, locs, comment in rows:
        cmt = f"  {comment}" if comment else ""
        if locs == "[]":
            print(f"    (")
            print(f"        \"{addr}\",")
            print(f"        \"{error}\",{cmt}")
            print(f"        [],")
            print(f"    ),")
        else:
            print(f"    (\"{addr}\", \"{error}\", {locs}),{cmt}")

    print("    # BIP 350")

    rows2 = [
        # tc1 — wrong HRP; leave unchanged.
        ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# Invalid human-readable part"),

        (reencode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", hrp),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", "# Invalid checksum (Bech32 instead of Bech32m)"),

        # tc1 — wrong HRP; leave unchanged.
        ("tc1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Invalid checksum (Bech32 instead of Bech32m)"),

        (reencode("BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", hrp, force_upper=True),
         "Version 1+ witness address must use Bech32m checksum",
         "[]", "# Invalid checksum (Bech32 instead of Bech32m)"),

        (reencode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", hrp),
         "Version 0 witness address must use Bech32 checksum",
         "[]", "# Invalid checksum (Bech32m instead of Bech32)"),

        # tc1 — wrong HRP; leave unchanged.
        ("tc1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Invalid checksum (Bech32m instead of Bech32)"),

        (bad_char_59,
         "Invalid Base 32 character",
         "[59]", "# Invalid character in checksum"),

        (reencode("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", hrp, force_upper=True),
         "Invalid Bech32 address witness version",
         "[]", ""),

        (reencode("bc1pw5dgrnzv", hrp),
         "Invalid Bech32 address program size (1 byte)",
         "[]", ""),

        (reencode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", hrp),
         "Invalid Bech32 address program size (41 bytes)",
         "[]", ""),

        (reencode("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", hrp, force_upper=True),
         "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
         "[]", ""),

        # tc1 — wrong HRP + mixed case; leave unchanged.
        ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Mixed case"),

        (reencode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", hrp),
         "Invalid padding in Bech32 data section",
         "[]", "# zero padding of more than 4 bits"),

        # tc1 — wrong HRP; leave unchanged.
        ("tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
         "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",
         "[]", "# tb1, Non-zero padding in 8-to-5 conversion"),

        (reencode("bc1gmk9yu", hrp),
         "Empty Bech32 data section",
         "[]", ""),
    ]

    for addr, error, locs, comment in rows2:
        cmt = f"  {comment}" if comment else ""
        if locs == "[]":
            print(f"    (")
            print(f"        \"{addr}\",")
            print(f"        \"{error}\",{cmt}")
            print(f"        [],")
            print(f"    ),")
        else:
            print(f"    (\"{addr}\", \"{error}\", {locs}),{cmt}")

    print("]")

    # ── Print VALID_DATA ──────────────────────────────────────────────────────
    print()
    print("VALID_DATA = [")
    print("    # BIP 350")

    valid = [
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
         "0014751e76e8199196d454941c45d1b3a323f1433bd6", True),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
         "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", False),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
         "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", False),
        ("BC1SW50QGDZ25J", "6002751e", True),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
         "5210751e76e8199196d454941c45d1b3a323", False),
        ("bc1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses5wp4dt",
         "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", False),
        ("bc1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses7epu4h",
         "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", False),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
         "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", False),
        ("bc1pfeessrawgf", "51024e73", False),
    ]

    for orig, spk, upper in valid:
        new = reencode(orig, hrp, force_upper=upper)
        print(f"    (")
        print(f"        \"{new}\",")
        print(f"        \"{spk}\",")
        print(f"    ),")

    print("]")


if __name__ == "__main__":
    main()
