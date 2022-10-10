## TPM2_AlgTest

It has been found out that implementation specifics of cryptographic smart cards can lead to serious vulnerabilities [[1](https://en.wikipedia.org/wiki/ROCA_vulnerability)]. Since TPM chips are often manufactured by the same vendors, we have decided to create a tool that would help with collection of data from various TPMs that could be used for further analysis and discovery of similar bugs.

This project uses sources from [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project.

## Running the tool

Install [`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools).

Build `tpm2-algtest` tool:
```sh
$ git clone https://github.com/crocs-muni/tpm2-algtest.git
$ mkdir build
$ cd build
$ cmake .. && make
$ cd ..
```

Run `run_algtest.py`:
```sh
$ python run_algtest.py all
```

**Important:** Please DO NOT suspend or hibernate the computer while running the algtest, it will affect the results! Locking the screen is ok.

**Important:** If during keygen test you don't see lines ending with `rc 0000`, but see some other number (return code), the key generation fails and it doesn't make sense to continue. Please contact me and send me the `out.zip` file anyway, the logs and TPM info there will still help us. A few erroneous return codes are ok.

### Troubleshooting
If the script crashes with this message:
```
subprocess.CalledProcessError: Command '['sudo', 'tpm2_getcap', '-T', 'device', 'algorithms']' returned non-zero exit status 1.
```
check if there is some output in `out/detail/Capability_algorithms.txt`. If it says 
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
