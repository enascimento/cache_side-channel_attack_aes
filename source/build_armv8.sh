#!/bin/sh

export SCA_TARGET_ARCH=armv8
export SCA_CROSS_COMPILER=aarch64-linux-gnu-

rm -rf build
mkdir -p build/lib/
mkdir -p build/cache-attack/one-round-attack/real-security-daemon/
mkdir -p build/cache-attack/last-round-attack/real-security-daemon/

# build libraries
cd lib/openssl-1.0.2
./build.sh ${SCA_CROSS_COMPILER}
cp -f libcrypto.so.1.0.0 ../../build/lib/

cd ../libflush
make ARCH=${SCA_TARGET_ARCH}
cp -f build/${SCA_TARGET_ARCH}/release/libflush.a ../../build/lib/

cd ../one_round_attack
./build.sh ${SCA_CROSS_COMPILER}
cp -f libone_round_attack.a ../../build/lib/

cd ../last_round_attack
./build.sh ${SCA_CROSS_COMPILER}
cp -f liblast_round_attack.a ../../build/lib/

#cd ../cryptocore
#./build.sh
#cp -f build/libcryptocore.so ../../build/lib/

# build attacks
#cd ../../
#cd cache-attack/one-round-attack/ideal-security-daemon/
#./build.sh armv7l-tizen-linux-gnueabi-
#cp -f attacker ../../../build/cache-attack/one-round-attack/ideal-security-daemon/
#cp -f security_daemon ../../../build/cache-attack/one-round-attack/ideal-security-daemon/
#cp -f plain.txt ../../../build/cache-attack/one-round-attack/ideal-security-daemon/

# build security daemon for one-round-attack
cd ../../
cd cache-attack/one-round-attack/real-security-daemon
./build.sh ${SCA_CROSS_COMPILER}
cp -f attacker ../../../build/cache-attack/one-round-attack/real-security-daemon/
cp -f security_daemon ../../../build/cache-attack/one-round-attack/real-security-daemon/
cp -f plain.txt ../../../build/cache-attack/one-round-attack/real-security-daemon/

# build security daemon for last-round-attack
cd ../../last-round-attack/real-security-daemon
./build.sh ${SCA_CROSS_COMPILER}
cp -f attacker ../../../build/cache-attack/last-round-attack/real-security-daemon/
cp -f security_daemon ../../../build/cache-attack/last-round-attack/real-security-daemon/
cp -f plain.txt ../../../build/cache-attack/last-round-attack/real-security-daemon/

