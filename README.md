### TPM2_AlgTest

Tool for measuring TPM capabilities, generated primes etc.

Based on [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project.

#### How to use:
To test your TPM with `tpm2-algtest`, you need only to have `docker` and `python3`, download
the `run_image.py` script and run the following commands. Docker priviledges are needed:
* pull a docker image: `python3 -m, run_image pull`
* run quicktest: `python3 -m run_image quicktest`
* run keygen test: `python3 -m run_image keygen`
* run keygen all tests: `python3 -m run_image fulltest`
