#!/bin/bash
#
# Before run this script install the following dependecies:
# sudo apt-get install build-essential git cmake lib32z1 lib32ncurses5 lib32bz2-1.0 libc6:i386 libgcc1:i386 gcc-4.6-base:i386 libstdc++5:i386 libstdc++6:i386
# sudo apt-get build-dep sqlite3 libsqlite3-dev # SQLCipher
#
# Donload the BB10 SDK from:
# http://developer.blackberry.com/native/download/linux/
# And install it in the same directory where this script is by running:
# $ chmod +x momentics*
# $ ./momentics*
# $ cd bbndk
# $ chmod +x sdkinstall
# $ ./sdkinstall --install 10.2.0.1155

DEV_DIR=$PWD
SQLCIPHER_VERSION=v3.1.0
SQLCIPHER_SRC_DIR="$DEV_DIR"/sqlcipher
BBSDK_DIR="$DEV_DIR"/bbndk
QNX_HOST="$BBSDK_DIR"/host_10_2_0_15/linux/x86


LOG() {
    echo -e "\033[1;32m$1\033[0m"
}

CHECK_ERROR() {
    if [ $? -ne 0 ] ; then
        returnCode=$?
        echo -e "\033[1;31m$1\033[0m"
        exit $returnCode
    fi
}


if [ ! -d "$SQLCIPHER_SRC_DIR" ] ; then
    LOG "[+] CLONING SQLCIPHER SOURCE CODE..."
    git clone https://github.com/sqlcipher/sqlcipher.git "$SQLCIPHER_SRC_DIR"
    cd "$SQLCIPHER_SRC_DIR"
    git checkout $SQLCIPHER_VERSION
else
    LOG "[+] USING EXISTING SQLCIPHER SOURCE CODE"
    cd "$SQLCIPHER_SRC_DIR"
fi

LOG "[+] SETTING BB10 CROSS-COMPILE ENVIRONMENT VARIABLES"
source "$BBSDK_DIR"/bbndk-env*.sh
export RANLIB="${QNX_HOST}/usr/bin/ntoarmv7-ranlib "
export PATH="$QNX_HOST/usr/bin":$PATH
export CPP="${QNX_HOST}/usr/bin/qcc -V4.6.3,gcc_ntoarmv7le -E "
export CC="${QNX_HOST}/usr/bin/qcc -V4.6.3,gcc_ntoarmv7le "
export LD="$QNX_HOST/usr/bin/ntoarmv7-ld"
export CPPFLAGS="-D__PLAYBOOK__ -D__QNXNTO__ "
export CFLAGS=" -g -fPIC -fstack-protector-strong "
export LDFLAGS="-L${BBSDK_DIR}/target_10_2_0_1155/qnx6/armle-v7/lib -lcrypto -lssl -lc -lscreen -lasound -lpps -lm -lpng14 -lbps -lEGL -lGLESv2 -Wl,-z,relro -Wl,-z,now -pie"

LOG "[+] SETTING SQLCIPHER ENVIRONMENT VARIABLES"
export CFLAGS="$CFLAGS -DSQLITE_HAS_CODEC"

LOG "[+] FIXING HAVE_MALLOC_USABLE_SIZE DEFINITION"
sed -e 's/\<malloc_usable_size\>//g' configure > configure.temp
mv configure.temp configure
chmod +x configure

LOG "[+] CONFIGURING SQLCIPHER..."
./configure --build=i686-pc-linux --host=arm-unknown-nto-qnx6.5.0eabi --enable-tempstore=yes
CHECK_ERROR "ERROR CONFIGURING SQLCIPHER"

LOG "[+] BUILDING SQLCIPHER..."
make -j4
CHECK_ERROR "ERROR BUILDING SQLCIPHER"

LOG "[+] COPYING SQLCIPHER LIBS TO "$DEV_DIR"/sqlcipher-libs..."
cp -r "$SQLCIPHER_SRC_DIR"/.libs "$DEV_DIR"/sqlcipher-libs
CHECK_ERROR "ERROR COPYING SQLCIPHER LIBS"

LOG "SQLCIPHER CORRECTLY BUILD :D"