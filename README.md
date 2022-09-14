## TPM2_AlgTest

It has been found out that implementation specifics of cryptographic smart cards can lead to serious vulnerabilities [[1](https://en.wikipedia.org/wiki/ROCA_vulnerability)]. Since TPM chips are often manufactured by the same vendors, we have decided to create a tool that would help with collection of data from various TPMs that could be used for further analysis and discovery of similar bugs.

This project uses sources from [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project.

### Want to help?
We are currently in the testing phase and will appreciate your help. If you have a TPM 2.0 chip (most of today's laptops do) and want to help us in the collection of data, please download the [`run_algtest.py`](https://github.com/simon-struk/tpm2-algtest/releases/download/v1.0/run_algtest.py) script and run it using the following command.:
* `python3 -m run_algtest fulltest --docker`

**Important:** Please DO NOT suspend or hibernate the computer while running the algtest, it will affect the results! Locking the screen is ok.

You need to have installed [docker](https://www.docker.com/) (`sudo apt-get install docker.io` for ubuntu, `sudo dnf install docker` for fedora) and you need to have priviledges to use docker (either use `sudo` or add your user to `docker` group). If you get errors about docker daemon, you might need to start the docker service manually (`sudo systemctl start docker.service` or similar)
 
The script will pull and run a docker image with tools needed to do the measurement.

The main keygen test generates 1000 RSA key pairs on the TPM for each available keylength (usually only two: 1024 and 2048). Depending on speed of generation, this should last up to few hours (2-3 hours with current TPMs) while consuming minimum system resources (the computation usually happens on a separate chip). If you cannot afford to let it run for too long, consider appending option `-d <duration_s>` that limits the time spend per keylength in seconds, e.g. `python3 -m run_image fulltest --docker -d 3600`.

Additionally, the test generates 1000 ECC key pairs for each available elliptic curve. These should be pretty swift.

Lastly, there are performance tests for selected TPM operations. This should take 5-10 minutes.

**Important:** If during keygen test you don't see lines ending with `rc 0000`, but see some other number (return code), the key generation fails and it doesn't make sense to continue. Please contact me and send me the `out.zip` file anyway, the logs and TPM info there will still help us. A few erroneous return codes are ok.

### Troubleshooting
If the script crashes with this message:
```
subprocess.CalledProcessError: Command '['docker', 'run', '-it', '--init', '--device=/dev/tpm0', '--entrypoint=tpm2_getcap', 'simonstruk/tpm2-algtest:v1.0', '-c', 'algorithms']' returned non-zero exit status 1.
```
check if there is some output int `out/detail/Quicktest_algorithms.txt`. If it says 
```
ERROR:sys:src/tss2-sys/api/Tss2_Sys_Execute.c:80:Tss2_Sys_ExecuteFinish() Unsupported device. The device is a TPM 1.2 
ERROR: Failed to GetCapability: capability: 0x0, property: 0x1, TSS2_RC: 0x80001

ERROR: Unable to run tpm2_getcap
```
you have TPM 1.2 which is not compatible for this testing.

#### tpm2-abrmd
Only one process can access /dev/tpm0 directly at the same time. Some distributions (e.g. Fedora) use daemon `tpm2-abrmd` as a resource manager which already takes control of the device. In order to run this script you have to temporarily stop this daemon:
```
$ sudo systemctl stop tpm2-abrmd
```
When the script finishes, you can start it again:
```
$ sudo systemctl start tpm2-abrmd
```
