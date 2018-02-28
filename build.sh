#!/bin/sh

make clean
./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC -I/usr/local/Cellar/openssl@1.1/1.1.0f/include" LDFLAGS="/usr/local/Cellar/openssl@1.1/1.1.0f/lib/libcrypto.a" && make
