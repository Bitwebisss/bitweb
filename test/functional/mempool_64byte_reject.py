class Mempool64ByteReject(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        tx_hex = (
            "0200000001deb98691723fa71260ffca6ea0a7bc0a63b0a8a366e1b585caad47fb269a2ce4"
            "01000000030251b201000000010000000000000000016a00000000"
        )

        res = self.nodes[0].testmempoolaccept([tx_hex])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "bad-txns-64byte")

if __name__ == "__main__":
    Mempool64ByteReject().main()
