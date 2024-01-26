# TPM2-AlgTest

It has been found out that implementation specifics of cryptographic smart cards can lead to serious vulnerabilities [[1](https://en.wikipedia.org/wiki/ROCA_vulnerability)]. Since TPM chips are often manufactured by the same vendors, we have decided to create a tool that would help with collection of data from various TPMs that could be used for further analysis and discovery of similar bugs.

This project uses sources from the [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) project.

## Running the tool

Install [`tpm2-tools`](https://github.com/tpm2-software/tpm2-tools) (version 5.0 or newer), `tss2-lib`, `openssl`, `dmidecode`:

```sh
# On Debian-based distros
sudo apt-get install tpm2-tools libtss2-dev openssl dmidecode
```

Build `tpm2-algtest` tool:
```sh
git clone https://github.com/crocs-muni/tpm2-algtest.git
mkdir build
cd build
cmake .. && make
cd ..
```

Install requirements (and optionally use venv):
```sh
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run `collect.py` with root privileges:
```sh
sudo python collect.py all
```

**Important:** Please DO NOT suspend or hibernate the computer while running the algtest, it will affect the results! Locking the screen is ok.

## Troubleshooting

Only one process can access /dev/tpm0 directly at the same time. Some distributions (e.g. Fedora) use daemon `tpm2-abrmd` as a resource manager which already takes control of the device. In order to run this script you have to temporarily stop this daemon:
```sh
sudo systemctl stop tpm2-abrmd
```
When the script finishes, you can start it again:
```sh
sudo systemctl start tpm2-abrmd
```
