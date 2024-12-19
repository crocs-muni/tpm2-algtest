# TPM2-AlgTest

The cryptographic hardware, including the security-certified one (Common Criteria, FIPS 140), was shown to contain serious vulnerabilities like [[1](https://en.wikipedia.org/wiki/ROCA_vulnerability)], [[2](https://minerva.crocs.fi.muni.cz/)] or [[3](https://tpm.fail)]. Since TPM chips are often manufactured by the same vendors as cryptographic smartcards, TPM2-AlgTest collects data from various TPMs that could be used for further analysis and discovery of similar bugs. The results from almost 80 TPM firmware revisions from 6 TPM vendors were published at [CHES'24](https://ches.iacr.org/2024/) conference, and existing and new vulnerabilities were found in several of them. 

![image](https://github.com/user-attachments/assets/d2930dc1-8964-41f1-b15c-597f703bad11)


If you like the tool, please consider citing our paper:
```
@inproceedings{2024-ches-tpmscan,
   title = {TPMScan: A wide-scale study of security-relevant properties of TPM 2.0 chips},
   year = {2024},
   author = {Svenda, Petr and Dufka, Antonin and Broz, Milan and Lacko, Roman and Jaros, Tomas and Zatovic, Daniel and Pospisil, Josef},
   booktitle = {IACR Transactions on Cryptographic Hardware and Embedded Systems},
   keywords = {TPM, common criteria, fips140, RSA, ECDSA},
   issn = {ISSN 2569-2925},
   pages = {714–734},
   volume={2024, No. 2}, 
   url={https://tches.iacr.org/index.php/TCHES/article/view/11444}, 
   DOI={10.46586/tches.v2024.i2.714-734}
}
```

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
