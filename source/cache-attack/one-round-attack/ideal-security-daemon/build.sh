#!/bin/sh

$1gcc -I./ -I../../../lib/openssl-0.9.8/include -L../../../lib/openssl-0.9.8 -o security_daemon security_daemon.c -lcrypto -lrt
$1gcc -I./ -o attacker attacker.c -lrt
