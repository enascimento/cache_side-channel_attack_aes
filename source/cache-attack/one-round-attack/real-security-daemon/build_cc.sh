#!/bin/sh

# target => cryptocore
$1gcc -DTARGET_CRYPTO_CRYPTOCORE=1 -I./ -I../../../lib/cryptocore/include -L../../../lib/cryptocore/build -o security_daemon security_daemon.c -lcryptocore -lrt

$1gcc -DTARGET_CRYPTO_CRYPTOCORE=1 -I./ -I../../../lib/one_round_attack -I../../../lib/libflush -L../../../lib/one_round_attack -L../../../lib/libflush/build/armv7/release -o attacker attacker.c -lrt -lone_round_attack -lflush
