#!/usr/bin/env python3

import os
import subprocess
import zipfile

def main():
    os.makedirs('out', exist_ok=True)
    device = '/dev/tpm0'

    # TODO: maybe let user pull the image
    # TODO: use docker module
    #subprocess.run([
        #'docker', 'image', 'pull', 'simonstruk/tpm2-algtest:v0.1'
        #]).check_returncode()

    run_algtest = [ 'docker', 'run', '-it', '--init', '--device=' + device,
            '--volume=' + os.getcwd() + '/out:/tpm2-algtest/build/out:z',
            'simonstruk/tpm2-algtest:v0.1' ]

    for keylen in 1024, 2048:
        subprocess.run(run_algtest + [
            '-T', 'device',
            '-s', 'keygen',
            '-t', 'rsa',
            '-l', str(keylen),
            '-n', '3',
            '--exportkeys'
            ]).check_returncode()

    # TODO: flush context after use or error (option)

    zipf = zipfile.ZipFile('out.zip', 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir('out'):
        zipf.write('out/' + file)

if __name__ == '__main__':
    main()
