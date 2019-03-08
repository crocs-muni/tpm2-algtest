import os
import subprocess
import zipfile
import argparse

device = '/dev/tpm0'

def zip():
    zipf = zipfile.ZipFile('out.zip', 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir('out'):
        zipf.write('out/' + file)

def quicktest():
    os.makedirs('out', exist_ok=True)
    entrypoint = 'tpm2_getcap'
    image_args = '-c algorithms'
    run_image = ['docker', 'run', '-it', '--init', '--device=' + device,
            '--entrypoint=tpm2_getcap' , 'simonstruk/tpm2-algtest:v0.1']
    with open('out/Quicktest_algorithms.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'algorithms'], stdout=outfile).check_returncode()
    with open('out/Quicktest_commands.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'commands'], stdout=outfile).check_returncode()
    with open('out/Quicktest_properties-fixed.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'properties-fixed'], stdout=outfile).check_returncode()
    with open('out/Quicktest_properties-variable.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'properties-variable'], stdout=outfile).check_returncode()
    with open('out/Quicktest_ecc-curves.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'ecc-curves'], stdout=outfile).check_returncode()
    with open('out/Quicktest_handles-persistent.txt', 'w') as outfile:
        subprocess.run(run_image + ['-c', 'handles-persistent'], stdout=outfile).check_returncode()

def keygen():
    run_image = [ 'docker', 'run', '-it', '--init', '--device=' + device,
            '--volume=' + os.getcwd() + '/out:/tpm2-algtest/build/out:z',
            'simonstruk/tpm2-algtest:v0.1' ]
    os.makedirs('out', exist_ok=True)
    for keylen in 1024, 2048:
        subprocess.run(run_image + [
            '-T', 'device',
            '-s', 'keygen',
            '-t', 'rsa',
            '-l', str(keylen),
            '-n', '3',
            '--exportkeys'
            ]).check_returncode()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', metavar='command', type=str)
    args = parser.parse_args()

    if args.command == 'pull':
        subprocess.run([
            'docker', 'image', 'pull', 'simonstruk/tpm2-algtest:v0.1'
            ]).check_returncode()

    if args.command == 'quicktest':
        quicktest()
        zip()
    elif args.command == 'keygen':
        keygen()
        zip()
    elif args.command == 'fulltest':
        quicktest()
        keygen()
        zip()

    else:
        print('invalid command')

    # TODO: flush context after use or error (option)

if __name__ == '__main__':
    main()
