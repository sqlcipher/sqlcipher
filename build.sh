#!/bin/sh

make clean
echo "Environment $OSTYPE"

CMD='./configure --enable-tempstore=yes'
cflags="-DSQLITE_HAS_CODEC"

if [[ "$OSTYPE" == "darwin"* ]]; then
    cflags="$cflags -I/usr/local/Cellar/openssl@1.1/1.1.0f/include"
    ldflags="/usr/local/Cellar/openssl@1.1/1.1.0f/lib/libcrypto.a"
elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    ldflags="-lcrypto"
elif [[ "$OSTYPE" == "freebsd"* ]]; then
    ldflags="-lcrypto"
fi

#if [[ "$OSTYPE" == "linux-gnu" ]]; then
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC"'
#elif [[ "$OSTYPE" == "darwin"* ]]; then
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC -I/usr/local/Cellar/openssl@1.1/1.1.0f/include" LDFLAGS="/usr/local/Cellar/openssl@1.1/1.1.0f/lib/libcrypto.a"'
#elif [[ "$OSTYPE" == "cygwin" ]]; then # POSIX compatibility layer and Linux environment emulation for Windows
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC"'
#elif [[ "$OSTYPE" == "msys" ]]; then # Lightweight shell and GNU utilities compiled for Windows (part of MinGW)
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC"'
#elif [[ "$OSTYPE" == "win32" ]]; then
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC"'
#        # I'm not sure this can happen.
#elif [[ "$OSTYPE" == "freebsd"* ]]; then
#    CMD='./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC"'
#else
#    exit
#fi
echo "CFLAGS=$cflags LDFLAGS=$ldflags $CMD && make"
CFLAGS="$cflags" LDFLAGS="$ldflags" $CMD && make
