### TPM2_AlgTest

It has been found out that implementation specifics of cryptographic smart cards can lead to serious vulnerabilities [1](https://en.wikipedia.org/wiki/ROCA_vulnerability). Since TPM chips are often manufactured by the same vendors, we have decided to create a tool that would help with collection of data from various TPMs that could be used for further analysis and discovery of similar bugs.

This project uses sources from [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project.

#### Want to help?
We are currently in the testing phase and will appreciate your help. If you have a TPM 2.0 chip (most of today's laptops do) and want to help us in the collection of data, please download the `run_image.py` script and run it using the following command (`docker` priviledges are required):
* `python3 -m run_image fulltest`

The script will pull and run a docker image with tools needed to do the measurement.

The main keygen test generates 1000 RSA key pairs on the TPM for each available keylength (usually only two: 1024 and 2048). Depending on speed of generation, this should last up to few hours while consuming minimum system resources (the computation usually happens on a separate chip). If you cannot afford to let it run for too long, consider appending option `-d <duration_s>` that limits the time spend per keylength in seconds, e.g. `python3 -m run_image fulltest -d 3600`.

Additionally, the test generates 1000 ECC key pairs for each available elliptic curve. These should be pretty swift.

After the tests are finished please send the generated zip file `out.zip` to `xstruk@fi.muni.cz` along with any additional information about the TPM model you might have.

**Important:** If during keygen test you don't see lines ending with `rc 0000`, but see some other number (return code), the key generation fails and it doesn't make sense to continue. Please contact me and send me the `out.zip` file anyway, the logs and TPM info there will still help us. A few erroneous return codes are ok.

If you run into any issues or feel that the computation is taking too long, please contact me on `xstruk@fi.muni.cz`.
