#!/bin/bash
cd ..
autoreconf -ivf
make clean
CXXFLAGS="-fsanitize=address" CFLAGS="-fsanitize=address" CC=afl-clang-fast CXX=afl-clang-fast++ ./configure
CFLAGS="-fsanitize=address" CC=afl-clang-fast CXX=afl-clang-fast++ make -j16
afl-clang-fast++ ./fuzz/fuzz_deserialize_cert.c -fsanitize=fuzzer -I ./include/ ./lib/.libs/libpkcs11-helper.a -lssl -lcrypto -o ./fuzz/fuzz_deserialize_cert -fsanitize=address
cd fuzz
