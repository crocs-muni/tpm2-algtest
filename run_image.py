import os
import subprocess
import zipfile
import argparse
import sys

device = '/dev/tpm0'
image_tag = 'v0.4'

def zip():
    zipf = zipfile.ZipFile('out.zip', 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir('out'):
        zipf.write('out/' + file)

def quicktest():
    run_image = ['docker', 'run', '-it', '--init', '--device=' + device,
            '--entrypoint=tpm2_getcap', 'simonstruk/tpm2-algtest:' + image_tag]
    print('Running quicktest...')
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

def keygen(args):
    run_image = [ 'docker', 'run', '-it', '--init', '--device=' + device,
            '--volume=' + os.getcwd() + '/out:/tpm2-algtest/build/out:z',
            'simonstruk/tpm2-algtest:' + image_tag, '-T', 'device', '-s', 'keygen' ]
    if args.num:
        run_image += [ '-n', str(args.num) ]
    if args.duration:
        run_image += [ '-d', str(args.duration) ]
    if args.keytype:
        run_image += [ '-t', args.keytype ]
    if args.keylen:
        run_image += [ '-l', str(args.keylen) ]
    if args.curveid:
        run_image += [ '-C', str(args.curveid) ]
    run_image += [ '--exportkeys' ]

    print('Running keygen test...')
    with open('out/keygen_log.txt', 'w') as logfile:
        proc = subprocess.Popen(run_image, stdout=subprocess.PIPE, universal_newlines=True)
        for line in proc.stdout:
            sys.stdout.write(line + '\r')
            logfile.write(line)
        proc.wait()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', metavar='command', type=str)
    parser.add_argument('-n', '--num', type=int, required=False)
    parser.add_argument('-d', '--duration', type=int, required=False)
    parser.add_argument('-t', '--keytype', type=str, required=False)
    parser.add_argument('-l', '--keylen', type=int, required=False)
    parser.add_argument('-C', '--curveid', type=int, required=False)
    args = parser.parse_args()

    if not os.path.exists(device):
        print(f'Device {device} not found')
        return

    if args.command == 'quicktest':
        os.makedirs('out', exist_ok=True)
        quicktest()
        zip()
    elif args.command == 'keygen':
        os.makedirs('out', exist_ok=True)
        keygen(args)
        zip()
    elif args.command == 'fulltest':
        os.makedirs('out', exist_ok=True)
        with open('out/docker_info.txt', 'w') as f:
            f.write('image ' + image_tag)
        quicktest()
        keygen(args)
        zip()
        print('The tests are finished. Thank you! Please send the generated file (out.zip) to xstruk@fi.muni.cz')
    else:
        print('invalid command')

if __name__ == '__main__':
    main()
