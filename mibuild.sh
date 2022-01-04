#!/bin/bash

#ARCH=arm64
#ARCH=arm
#ARCH=mips
#ARCH=mipsle
for ARCH in arm64 arm mipsle
do
PWD=$(pwd)

if [ "$ARCH" = "arm" ];then
#armv7l
export CFLAGS="-I $PWD/opt/cross/arm-linux-musleabi/arm-linux-musleabi/include -Os -ffunction-sections -fdata-sections -march=armv7-a -mabi=aapcs-linux -D_GNU_SOURCE -D_BSD_SOURCE -fPIE"
export CXXFLAGS="-I $PWD/opt/cross/arm-linux-musleabi/arm-linux-musleabi/include"
export CC=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-gcc
export CXX=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-g++
export CORSS_PREFIX=$PWD/opt/cross/arm-linux-musleabi/bin/arm-linux-musleabi-
elif [ "$ARCH" = "arm64" ];then
#aarch64
export CFLAGS="-I $PWD/opt/cross/aarch64-linux-musl/aarch64-linux-musl/include -Os -ffunction-sections -fdata-sections -march=armv8-a -mabi=lp64 -D_GNU_SOURCE -D_BSD_SOURCE -fPIE"
export CXXFLAGS="-I $PWD/opt/cross/aarch64-linux-musl/aarch64-linux-musl/include"
export CC=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-gcc
export CXX=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/aarch64-linux-musl/bin/aarch64-linux-musl-
elif [ "$ARCH" = "mips" ];then
#mips
export CFLAGS="-I $PWD/opt/cross/mips-linux-musl/mips-linux-musl/include -Os -ffunction-sections -fdata-sections -mno-branch-likely -mtune=1004kc -D_GNU_SOURCE -D_BSD_SOURCE -fPIE -mips32r2"
export CXXFLAGS="-I $PWD/opt/cross/mips-linux-musl/mips-linux-musl/include"
export CC=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-gcc
export CXX=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/mips-linux-musl/bin/mips-linux-musl-
elif [ "$ARCH" = "mipsle" ];then
#mipsle
export CFLAGS="-I $PWD/opt/cross/mipsel-linux-musl/mipsel-linux-musl/include -Os -ffunction-sections -fdata-sections -D_GNU_SOURCE -D_BSD_SOURCE -fPIE -mips32r2"
export CXXFLAGS="-I $PWD/opt/cross/mipsel-linux-musl/mipsel-linux-musl/include"
export CC=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-gcc
export CXX=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-g++
export CORSS_PREFIX=$PWD/opt/cross/mipsel-linux-musl/bin/mipsel-linux-musl-
fi

BASE=`pwd`
SRC=$BASE/src
WGET="wget --prefer-family=IPv4"
DEST=$BASE/opt
LDFLAGS="-L$DEST/lib -Wl,--gc-sections"
CPPFLAGS="-I$DEST/include"
CXXFLAGS="$CXXFLAGS $CFLAGS"
MAKE="make"
mkdir -p bin/$ARCH
$CC -static mitool.c -o mitool_$ARCH
${CORSS_PREFIX}strip mitool_$ARCH
done
