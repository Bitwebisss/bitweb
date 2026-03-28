### TestGen ###

Utilities to generate test vectors for the data-driven Bitweb tests.

To use inside a scripted-diff (or just execute directly):

    ./gen_key_io_test_vectors.py valid 70 > ../../src/test/data/key_io_valid.json
    ./gen_key_io_test_vectors.py invalid 70 > ../../src/test/data/key_io_invalid.json


### gen_validateaddress_vectors.py ###
Regenerates INVALID_DATA and VALID_DATA test vectors in
test/functional/rpc_validateaddress.py for an arbitrary bech32 HRP.

    # Print generated blocks to stdout (inspect before applying):
    ./gen_validateaddress_vectors.py
    ./gen_validateaddress_vectors.py --hrp xbt

    # Patch rpc_validateaddress.py in-place (recommended):
    ./gen_validateaddress_vectors.py --apply
    ./gen_validateaddress_vectors.py --hrp xbt --apply

cmake -B build -DBUILD_DAEMON=ON -DBUILD_CLI=ON -DBUILD_TX=ON -DBUILD_TESTS=ON -DENABLE_WALLET=ON -DWITH_ZMQ=ON -DWITH_USDT=ON -DENABLE_EXTERNAL_SIGNER=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)

cd build
cp bin/bitweb-tx test/functional/data/util/bitweb-tx
python3 test/functional/data/util/regenerate_test_data.py