#!/bin/sh
export CRYPTO_RELEASE=secure-element
export CRYPTO_REPO_URL=git@github.com:Patater/mbed-crypto.git
curdir=`pwd`
cd mbed-os/features/mbedtls/mbed-crypto/importer
make
cd $curdir
