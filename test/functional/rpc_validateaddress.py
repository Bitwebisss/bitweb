#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validateaddress for main chain"""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import assert_equal

INVALID_DATA = [
    # BIP 173
    (
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # Invalid hrp
        [],
    ),
    ("bte1qw508d6qejxtdg4y5r3zarvary0c5xw7kx8jnqe", "Invalid Bech32 checksum", [41]),
    (
        "BTE13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KE45VRX",
        "Version 1+ witness address must use Bech32m checksum",
        [],
    ),
    (
        "bte1rw5uc02kz",
        "Version 1+ witness address must use Bech32m checksum",  # Invalid program length
        [],
    ),
    (
        "bte10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5xdngxt",
        "Version 1+ witness address must use Bech32m checksum",  # Invalid program length
        [],
    ),
    (
        "BTE1QR508D6QEJXTDG4Y5R3ZARVARYV4ZWFSC",
        "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
        [],
    ),
    (
        "tc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Mixed case
        [],
    ),
    (
        "BTE1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KX8JnPE",
        "Invalid character or mixed case",  # bte1, Mixed case, not in BIP 173 test vectors
        [40],
    ),
    (
        "bte1zw508d6qejxtdg4y5r3zarvaryvq596up0",
        "Version 1+ witness address must use Bech32m checksum",  # Wrong padding
        [],
    ),
    (
        "tc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Non-zero padding in 8-to-5 conversion
        [],
    ),
    ("bte15zawvr", "Empty Bech32 data section", []),
    # BIP 350
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # Invalid human-readable part
        [],
    ),
    (
        "bte1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqmm4cx3",
        "Version 1+ witness address must use Bech32m checksum",  # Invalid checksum (Bech32 instead of Bech32m)
        [],
    ),
    (
        "tc1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Invalid checksum (Bech32 instead of Bech32m)
        [],
    ),
    (
        "BTE1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQCYLLWR",
        "Version 1+ witness address must use Bech32m checksum",  # Invalid checksum (Bech32 instead of Bech32m)
        [],
    ),
    (
        "bte1qw508d6qejxtdg4y5r3zarvary0c5xw7knmzlym",
        "Version 0 witness address must use Bech32 checksum",  # Invalid checksum (Bech32m instead of Bech32)
        [],
    ),
    (
        "tc1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Invalid checksum (Bech32m instead of Bech32)
        [],
    ),
    (
        "bte1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqw8b5rn",
        "Invalid Base 32 character",  # Invalid character in checksum
        [59],
    ),
    (
        "BTE130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQJNLKKL",
        "Invalid Bech32 address witness version",
        [],
    ),
    ("bte1pw5dqdpge", "Invalid Bech32 address program size (1 byte)", []),
    (
        "bte1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav255sfp7g",
        "Invalid Bech32 address program size (41 bytes)",
        [],
    ),
    (
        "BTE1QR508D6QEJXTDG4Y5R3ZARVARYV4ZWFSC",
        "Invalid Bech32 v0 address program size (16 bytes), per BIP141",
        [],
    ),
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Mixed case
        [],
    ),
    (
        "bte1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qpwe4yf",
        "Invalid padding in Bech32 data section",  # zero padding of more than 4 bits
        [],
    ),
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # tb1, Non-zero padding in 8-to-5 conversion
        [],
    ),
    ("bte15zawvr", "Empty Bech32 data section", []),
]
VALID_DATA = [
    # BIP 350
    (
        "BTE1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KX8JNPE",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    # (
    #   "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
    #   "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    # ),
    (
        "bte1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q5fcaad",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "bte1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k9qyker",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("BTE1SW50QCTVN20", "6002751e"),
    ("bte1zw508d6qejxtdg4y5r3zarvaryvdrq6df", "5210751e76e8199196d454941c45d1b3a323"),
    # (
    #   "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
    #   "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    # ),
    (
        "bte1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesclsnuh",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    # (
    #   "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
    #   "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    # ),
    (
        "bte1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesjgs6yt",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "bte1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqw895rn",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    # PayToAnchor(P2A)
    (
        "bte1pfeesq9nhk5",
        "51024e73",
    ),
]


class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]] * self.num_nodes

    def check_valid(self, addr, spk):
        info = self.nodes[0].validateaddress(addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["scriptPubKey"], spk)
        assert "error" not in info
        assert "error_locations" not in info

    def check_invalid(self, addr, error_str, error_locations):
        res = self.nodes[0].validateaddress(addr)
        assert_equal(res["isvalid"], False)
        assert_equal(res["error"], error_str)
        assert_equal(res["error_locations"], error_locations)

    def test_validateaddress(self):
        for (addr, error, locs) in INVALID_DATA:
            self.check_invalid(addr, error, locs)
        for (addr, spk) in VALID_DATA:
            self.check_valid(addr, spk)

    def run_test(self):
        self.test_validateaddress()


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
