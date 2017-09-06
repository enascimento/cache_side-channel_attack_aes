#!/bin/sh

rm -rf build

# clean libraries
cd lib/openssl-1.0.2
./clean.sh

cd ../libflush
rm -rf build/

cd ../one_round_attack
./clean.sh

cd ../last_round_attack
./clean.sh

cd ../cryptocore
./clean.sh

# clean attacks
cd ../../
cd cache-attack/one-round-attack/ideal-security-daemon
./clean.sh

cd ../real-security-daemon
./clean.sh

cd ../../last-round-attack/real-security-daemon
./clean.sh
cd ../../../

