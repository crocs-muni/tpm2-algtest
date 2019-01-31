#!/bin/sh

DEV_TPM=/dev/tpm0

sudo docker image pull simonstruk/tpm2-algtest

if [ ! -d csv ]; then
    mkdir csv
fi

sudo docker run -it --init --device=${DEV_TPM}                              \
    -v "$(pwd)"/csv:/tpm2-algtest/build/csv:z simonstruk/tpm2-algtest
