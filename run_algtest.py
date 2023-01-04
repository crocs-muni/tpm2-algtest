import os
import subprocess
import zipfile
import argparse
import sys
import glob
import csv
import datetime
import hashlib
import math
import re
import unicodedata
import binascii

from cryptography.hazmat.primitives.serialization import load_pem_public_key, PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

DEVICE = '/dev/tpm0'
IMAGE_TAG = 'v2.1'


def get_algtest(args):
    if args.use_system_algtest:
        return 'tpm2_algtest'
    else:
        return 'build/tpm2_algtest'


def set_status(args, status):
    if args.machine_readable_statuses:
        status = f"+++{status}+++"
    print(status)


def run_algtest(run_command, logfile):
    proc = subprocess.Popen(run_command, stdout=subprocess.PIPE, universal_newlines=True)
    for line in proc.stdout:
        sys.stdout.write(line + '\r')
        logfile.write(line)
    proc.wait()


def add_args(run_command, args):
    if args.num:
        run_command += ['-n', str(args.num)]
    if args.duration:
        run_command += ['-d', str(args.duration)]
    if args.keytype:
        run_command += ['-t', args.keytype]
    if args.keylen:
        run_command += ['-l', str(args.keylen)]
    if args.curveid:
        run_command += ['-C', str(args.curveid)]
    if args.command:
        run_command += ['-c', args.command]


def zip(outdir):
    zipf = zipfile.ZipFile(outdir + '.zip', 'w', zipfile.ZIP_DEFLATED)
    for root, _, files in os.walk(outdir):
        for file in files:
            zipf.write(os.path.join(root, file))


def remove_control_chars(string):
    return "".join(filter(lambda x: x == '\n' or unicodedata.category(x)[0] != "C", string))


def compute_rsa_privates(filename):
    def extended_euclidean(a, b):
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            q, b, a = b // a, a, b % a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0

    def mod_exp(base, exp, n):
        res = 1
        base %= n
        while exp > 0:
            if exp % 2 == 1:
                res *= base
                res %= n
            exp //= 2
            base *= base
            base %= n
        return res

    def compute_row(row):
        try:
            n = int(row['n'], 16)
            e = int(row['e'], 16)
            p = int(row['p'], 16)
        except:
            return False
        q = n // p
        totient = (p - 1) * (q - 1)
        _, d, _ = extended_euclidean(e, totient)
        d %= totient

        message = 12345678901234567890
        assert mod_exp(mod_exp(message, e, n), d, n) == message, \
            f"Something went wrong (row {row['id']})"

        row['q'] = '%X' % q
        row['d'] = '%X' % d
        return True

    rows = []
    with open(filename) as infile:
        reader = csv.DictReader(infile, delimiter=',')
        for row in reader:
            rows.append(row)

    failed = 0
    for row in rows:
        failed += 0 if compute_row(row) else 1

    if failed > 0:
        print(f"Computation of {failed} rows failed")

    with open(filename, 'w') as outfile:
        writer = csv.DictWriter(
                outfile, delimiter=',', fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def compute_nonce(filename):
    CURVE_ORDER = {
        "P256": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        "P384": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        "BN256": 0xfffffffffffcf0cd46e5f25eee71a49e0cdc65fb1299921af62d536cd10b500d
    }

    def extract_ecdsa_nonce(n, r, s, x, e):
        # https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        return (pow(s, -1, n) * (e + (r * x) % n) % n) % n

    def extract_ecschnorr_nonce(n, r, s, x, e):
        # https://trustedcomputinggroup.org/wp-content/uploads/TPM2.0-Library-Spec-v1.16-Errata_v1.5_09212016.pdf
        return (s - (r * x) % n) % n

    def extract_sm2_nonce(n, r, s, x, e):
        # https://crypto.stackexchange.com/questions/9918/reasons-for-chinese-sm2-digital-signature-algorithm
        return (s + (s * x) % n + (r * x) % n) % n

    def extract_ecdaa_nonce(n, r, s, x, e):
        # https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
        hasher = hashlib.sha256()
        hasher.update(int.to_bytes(r, byteorder="big", length=math.ceil(math.log2(n))))
        hasher.update(int.to_bytes(e, byteorder="big", length=math.ceil(math.log2(n))))
        h = int.from_bytes(hasher.digest(), byteorder="big")
        return (s - h * x) % n

    def compute_row(row):
        try:
            digest = int(row['digest'], 16)
            curve = {0x3: "P256", 0x4: "P384", 0x10: "BN256"}[int(row['curve'], 16)]
            algorithm = {0x18: "ECDSA", 0x1a: "ECDAA", 0x1b: "SM2", 0x1c: "ECSCHNORR"}[int(row['algorithm'], 16)]
            signature_r = int(row['signature_r'], 16)
            signature_s = int(row['signature_s'], 16)
            private_key = int(row['private_key'], 16)

            row['nonce'] = hex({
                "ECDSA": extract_ecdsa_nonce,
                "ECSCHNORR": extract_ecschnorr_nonce,
                "SM2": extract_sm2_nonce,
                "ECDAA": extract_ecdaa_nonce
            }[algorithm](CURVE_ORDER[curve], signature_r, signature_s, private_key, digest))[2:]

        except:
            return False
        return True

    rows = []
    with open(filename) as infile:
        reader = csv.DictReader(infile, delimiter=',')
        for row in reader:
            rows.append(row)

    failed = 0
    for row in rows:
        failed += 0 if compute_row(row) else 1

    if failed > 0:
        print(f"Computation of {failed} rows failed")

    with open(filename, 'w') as outfile:
        writer = csv.DictWriter(
                outfile, delimiter=',', fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def check_nonce_points(data_filename, log_filename):
    curve = data_filename.split(":")[1].split("_")[1][2:]

    log_nonce_points = {}
    with open(log_filename, "r") as f:
        log_lines = f.readlines()

    for i, line in enumerate(log_lines):
        if i + 1 >= len(log_lines):
            break
        next_line = log_lines[i + 1]

        if "Unexpected point output" in line and (match := re.search(f"Cryptoops ecc (\\d+): \\| scheme 001a \\| curve {curve}", next_line)):
            idx = int(match.groups()[0])

            point = line.split()[-1]
            if len(point) < 2 or point[:2] != "04":
                print("Could not extract a point from the log")
                continue

            coord_len = (len(point) - 2) // 2
            log_nonce_points[idx] = (point[2:2 + coord_len], point[2 + coord_len:])

    def compute_row(row):
        try:
            if row["nonce_point_x"] == "" or row["nonce_point_y"] == "":
                idx = int(row["id"])
                row["nonce_point_x"] = log_nonce_points[idx][0]
                row["nonce_point_y"] = log_nonce_points[idx][1]
        except:
            return False
        return True

    rows = []
    with open(data_filename) as infile:
        reader = csv.DictReader(infile, delimiter=',')
        for row in reader:
            rows.append(row)

    failed = 0
    for row in rows:
        failed += 0 if compute_row(row) else 1

    if failed > 0:
        print(f"Computation of {failed} rows failed")

    with open(data_filename, 'w') as outfile:
        writer = csv.DictWriter(
                outfile, delimiter=',', fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def get_tpm_id(detail_dir):
    def get_val(line):
        pos = line.find('0x')
        if pos == -1:
            return None
        val = line[line.find('0x') + 2:-1]
        return "0" * (8 - len(val)) + val

    manufacturer = ''
    vendor_str = ''
    fw = ''
    properties_path = os.path.join(detail_dir, 'Capability_properties-fixed.txt')
    if os.path.isfile(properties_path):
        with open(properties_path, 'r') as properties_file:
            lines = properties_file.readlines()

            fw1 = ''
            fw2 = ''
            for idx, line in enumerate(lines):
                val = get_val(lines[idx])
                if idx + 1 < len(lines):
                    val = val or get_val(lines[idx + 1])

                if line.startswith('TPM2_PT_MANUFACTURER'):
                    manufacturer = bytearray.fromhex(val).decode()
                elif line.startswith('TPM2_PT_FIRMWARE_VERSION_1'):
                    fw1 = val
                elif line.startswith('TPM2_PT_FIRMWARE_VERSION_2'):
                    fw2 = val
                elif line.startswith('TPM2_PT_VENDOR_STRING_'):
                    vendor_str += bytearray.fromhex(val).decode()

            fw = str(int(fw1[0:4], 16)) + '.' + str(int(fw1[4:8], 16)) + '.' + str(int(fw2[0:4], 16)) + '.' + str(int(fw2[4:8], 16))

    manufacturer = remove_control_chars(manufacturer)
    vendor_str = remove_control_chars(vendor_str)
    fw = remove_control_chars(fw)
    return manufacturer, vendor_str, fw


def get_system_id(detail_dir):
    uname = None
    manufacturer = None
    product_name = None
    version = None
    bios_version = None

    system_info = os.path.join(detail_dir, 'dmidecode_system_info.txt')
    if os.path.isfile(system_info):
        with open(system_info, 'r') as dmidecode_file:
            output = dmidecode_file.read().replace("\t", "").split("\n")
            try:
                manufacturer = output[0].split(":")[1][1:]
            except:
                pass

            try:
                product_name = output[1].split(":")[1][1:]
            except:
                pass

            try:
                version = output[2].split(":")[1][1:]
            except:
                pass

    system_info = os.path.join(detail_dir, 'dmidecode_bios_version.txt')
    if os.path.isfile(system_info):
        with open(system_info, 'r') as dmidecode_bios_file:
            bios_version = dmidecode_bios_file.readline()[:-1]

    system_info = os.path.join(detail_dir, 'uname_system_info.txt')
    if os.path.isfile(system_info):
        with open(system_info, 'r') as uname_file:
            uname = uname_file.readline()[:-1]
    return manufacturer, product_name, version, bios_version, uname


def get_image_tag(detail_dir):
    with open(os.path.join(detail_dir, 'image_tag.txt'), 'r') as f:
        image_tag = f.read()
    return image_tag


def get_anonymized_cert(cert_path):
    process = subprocess.run(['openssl', 'x509', '-in', cert_path, '-noout', '-text'], capture_output=True)
    process.check_returncode()
    data = process.stdout.decode().split("\n")
    anonymize_depth = None

    output = ""
    anonymized = 0
    for line in data:
        depth = 0
        for c in line:
            if c != ' ':
                break
            depth += 1

        if anonymize_depth is None and "Modulus" in line or "pub" in line or "Serial Number" in line or "Subject Alternative Name" in line or "Signature Value" in line:
            anonymized += 1
            anonymize_depth = depth
            output += line + "\n"
            continue

        if anonymize_depth and depth > anonymize_depth:
            output += "".join(map(lambda x: x if x in " :" else "X", line)) + "\n"
            continue

        output += line + "\n"
        anonymize_depth = None

    return output if anonymized >= 3 else ""


def get_anonymized_ecc(cert_path):
    process = subprocess.run(['openssl', 'x509', '-in', cert_path, '-noout', '-pubkey'], capture_output=True)
    process.check_returncode()
    data = process.stdout
    key = load_pem_public_key(data)
    assert isinstance(key, EllipticCurvePublicKey)
    point = binascii.hexlify(key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).decode()
    return f"Anonymized:\n  pub prefix: {point[:6]}\n  pub suffix: {point[-4:]}\n"


def get_anonymized_rsa(cert_path):
    process = subprocess.run(['openssl', 'x509', '-in', cert_path, '-noout', '-pubkey'], capture_output=True)
    process.check_returncode()
    data = process.stdout
    key = load_pem_public_key(data)
    assert isinstance(key, RSAPublicKey)
    n = key.public_numbers().n
    n = binascii.hexlify(int.to_bytes(n, length=(math.floor(math.log2(n)) // 8) + 1, byteorder="big")).decode()
    return f"Anonymized:\n  n prefix: {n[:4]}\n  n suffix: {n[-4:]}\n"


def system_info(args, detail_dir):
    with open(os.path.join(detail_dir, 'image_tag.txt'), 'w') as f:
        f.write(args.with_image_tag)
        print("Version tag:", args.with_image_tag)

    try:
        result = subprocess.run("sudo -n dmidecode -s bios-version", stdout=subprocess.PIPE, shell=True)
        with open(os.path.join(detail_dir, 'dmidecode_bios_version.txt'), 'w') as outfile:
            outfile.write(result.stdout.decode("ascii"))
        result = subprocess.run("sudo dmidecode -t system | grep -Ei '^\\s*(manufacturer|product name|version):'", stdout=subprocess.PIPE, shell=True)
        with open(os.path.join(detail_dir, 'dmidecode_system_info.txt'), 'w') as outfile:
            outfile.write(result.stdout.decode("ascii"))
        result = subprocess.run("uname -a", stdout=subprocess.PIPE, shell=True)
        with open(os.path.join(detail_dir, 'uname_system_info.txt'), 'w') as outfile:
            outfile.write(result.stdout.decode("ascii"))
    except:
        print("Could not obtain system information")


def capability_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    run_command = ['sudo', 'tpm2_getcap', '-T', 'device']

    with open(os.path.join(detail_dir, "Capability_pcrread.txt"), 'w') as outfile:
        subprocess.run(['tpm2_pcrread'], stdout=outfile)

    # Get anonymized endorsement certificates
    subprocess.run(['tpm2_getekcertificate', '-o', 'ek-rsa.cer', '-o', 'ek-ecc.cer'], stdout=subprocess.DEVNULL)
    try:
        anonymized_rsa = get_anonymized_rsa("ek-rsa.cer")
        anonymized_cert = get_anonymized_cert("ek-rsa.cer")
        with open(os.path.join(detail_dir, "Capability_ek-rsa.txt"), "w") as outfile:
            outfile.write(anonymized_rsa + anonymized_cert)
    except:
        print("Could not obtain RSA endorsement certificate")

    try:
        anonymized_ecc = get_anonymized_ecc("ek-ecc.cer")
        anonymized_cert = get_anonymized_cert("ek-ecc.cer")
        with open(os.path.join(detail_dir, "Capability_ek-ecc.txt"), "w") as outfile:
            outfile.write(anonymized_ecc + anonymized_cert)
    except:
        print("Could not obtain ECC endorsement certificate")
    subprocess.run(['rm', '-f', 'ek-rsa.cer', 'ek-ecc.cer'], stdout=subprocess.DEVNULL)

    with open(os.path.join(detail_dir, "Capability_pcrread.txt"), 'w') as outfile:
        subprocess.run(['tpm2_pcrread'], stdout=outfile).check_returncode()

    for command in ("algorithms", "commands", "properties-fixed", "properties-variable", "ecc-curves", "handles-persistent"):
        with open(os.path.join(detail_dir, f"Capability_{command}.txt"), 'w') as outfile:
            try:
                subprocess.run(run_command + ["-c", command], stdout=outfile, stderr=subprocess.DEVNULL).check_returncode()
            except:
                subprocess.run(run_command + [command], stdout=outfile).check_returncode()


def keygen_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    run_command = ['sudo', get_algtest(args), '--outdir=' + detail_dir, '-T', 'device', '-s', 'keygen']
    add_args(run_command, args)

    with open(os.path.join(detail_dir, 'keygen_log.txt'), 'w') as logfile:
        run_algtest(run_command, logfile)

    if not args.only_measure:
        set_status(args, 'Computing RSA private keys...')
        for filename in glob.glob(os.path.join(detail_dir, 'Keygen:RSA_*.csv')):
            print(filename)
            compute_rsa_privates(filename)


def perf_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    run_command = ['sudo', get_algtest(args), '--outdir=' + detail_dir, '-T', 'device', '-s', 'perf']
    add_args(run_command, args)

    with open(os.path.join(detail_dir, 'perf_log.txt'), 'w') as logfile:
        run_algtest(run_command, logfile)


def cryptoops_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    run_command = ['sudo', get_algtest(args), '--outdir=' + detail_dir, '-T', 'device', '-s', 'cryptoops']
    add_args(run_command, args)

    with open(os.path.join(detail_dir, 'cryptoops_log.txt'), 'w') as logfile:
        run_algtest(run_command, logfile)

    if not args.only_measure:
        print('Checking file consistency...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:ECC_*_0x001a.csv')):
            print(filename)
            check_nonce_points(filename, os.path.join(detail_dir, "cryptoops_log.txt"))

        set_status(args, 'Computing ECC nonces...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:ECC_*.csv')):
            print(filename)
            compute_nonce(filename)

        set_status(args, 'Computing RSA privates...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:RSA_*.csv')):
            print(filename)
            compute_rsa_privates(filename)


def rng_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    run_command = ['sudo', get_algtest(args), '--outdir=' + detail_dir, '-T', 'device', '-s', 'rng']
    add_args(run_command, args)

    with open(os.path.join(detail_dir, 'rng_log.txt'), 'w') as logfile:
        run_algtest(run_command, logfile)


def format_handler(args):
    detail_dir = os.path.join(args.outdir, 'detail')
    if len(os.listdir(detail_dir)) == 0:
        set_status(args, 'There is no output yet, need to run tests.')
        return

    if not args.only_measure:
        if args.include_legacy:
            create_legacy_result_files(args.outdir)

        create_result_files(args.outdir)

        set_status(args, 'Checking file consistency...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:ECC_*_0x001a.csv')):
            print(filename)
            check_nonce_points(filename, os.path.join(detail_dir, "cryptoops_log.txt"))

        set_status(args, 'Computing ECC nonces...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:ECC_*.csv')):
            print(filename)
            compute_nonce(filename)

        set_status(args, 'Computing RSA privates...')
        for filename in glob.glob(os.path.join(detail_dir, 'Cryptoops_Sign:RSA_*.csv')):
            print(filename)
            compute_rsa_privates(filename)


def all_handler(args):
    handlers_count = 5
    set_status(args, 'Running all tests...')
    system_info(args, os.path.join(args.outdir, 'detail'))
    set_status(args, f'Collecting basic TPM info (1/{handlers_count})...')
    capability_handler(args)
    default_num = args.num is None
    if default_num:
        args.num = 1000
    set_status(args, f'Running cryptoops test (2/{handlers_count})...')
    cryptoops_handler(args)
    if default_num:
        args.num = 16384
    set_status(args, f'Running RNG test (3/{handlers_count})...')
    rng_handler(args)
    if default_num:
        args.num = 1000
    set_status(args, f'Running performance test (4/{handlers_count})...')
    perf_handler(args)
    if default_num:
        args.num = 1000
    set_status(args, f'Running keygen test (5/{handlers_count})...')
    keygen_handler(args)
    if default_num:
        args.num = None
    if not args.only_measure:
        create_result_files(args.outdir)

        if args.include_legacy:
            create_legacy_result_files(args.outdir)


def extensive_handler(args):
    handlers_count = 5
    set_status(args, 'Running all tests with extensive setting...')
    system_info(args, os.path.join(args.outdir, 'detail'))
    set_status(args, f'Collecting basic TPM info (1/{handlers_count})...')
    capability_handler(args)
    default_num = args.num is None
    if default_num:
        args.num = 100000
    set_status(args, f'Running cryptoops test (2/{handlers_count})...')
    cryptoops_handler(args)
    if default_num:
        args.num = 524288
    set_status(args, f'Running RNG test (3/{handlers_count})...')
    rng_handler(args)
    if default_num:
        args.num = 1000
    set_status(args, f'Running performance test (4/{handlers_count})...')
    perf_handler(args)
    if default_num:
        args.num = 100000
    set_status(args, f'Running keygen test (5/{handlers_count})...')
    keygen_handler(args)
    if default_num:
        args.num = None
    if not args.only_measure:
        create_result_files(args.outdir)

        if args.include_legacy:
            create_legacy_result_files(args.outdir)


def write_header(file, detail_dir):
    image_tag = get_image_tag(detail_dir)
    manufacturer, vendor_str, fw = get_tpm_id(detail_dir)
    file.write(f'Execution date/time: {datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")}\n')
    file.write(f'Manufacturer: {manufacturer}\n')
    file.write(f'Vendor string: {vendor_str}\n')
    file.write(f'Firmware version: {fw}\n')
    file.write(f'Image tag: {image_tag}\n')
    file.write(f'TPM devices: {", ".join(glob.glob("/dev/tpm*"))}\n')
    try:
        system_manufacturer, product_name, system_version, bios_version, uname = get_system_id(detail_dir)
        file.write(f'Device manufacturer: {system_manufacturer}\n')
        file.write(f'Device name: {product_name}\n')
        file.write(f'Device version: {system_version}\n')
        file.write(f'BIOS version: {bios_version}\n')
        file.write(f'System information: {uname}\n')
    except:
        pass
    file.write('\n')


def compute_stats(infile):
    success, fail, sum_op, min_op, max_op, avg_op = 0, 0, 0, 10000000000, 0, 0
    error = None
    csv_input = csv.DictReader(infile, delimiter=',')

    for record in csv_input:
        if record["return_code"] != '0000':
            error = record["return_code"]
            fail += 1
            continue
        success += 1
        t = float(record["duration"])
        sum_op += t
        if t > max_op: max_op = t
        if t < min_op: min_op = t

    total = success + fail
    if success != 0:
        avg_op = (sum_op / success)
    else:
        min_op = 0

    return avg_op * 1000, min_op * 1000, max_op * 1000, total, success, fail, error # sec -> ms


def write_results_file(results_file, detail_dir):
    properties_path = os.path.join(detail_dir, 'Capability_properties-fixed.txt')
    if os.path.isfile(properties_path):
        results_file.write('\nCapability_properties-fixed:\n')
        with open(properties_path, 'r') as infile:
            properties = ""
            for line in infile:
                if line.startswith('  as UINT32:'):
                    continue
                if line.startswith('  as string:'):
                    line = line[line.find('"'):]
                    properties = properties[:-1] + '\t' + line
                else:
                    properties += "  " + line
            results_file.write(remove_control_chars(properties))

    algorithms_path = os.path.join(detail_dir, 'Capability_algorithms.txt')
    if os.path.isfile(algorithms_path):
        results_file.write('\nCapability_algorithms:\n')
        with open(algorithms_path, 'r') as infile:
            for line in infile:
                if line.startswith('  value:'):
                    line = line[line.find('0x'):]
                    results_file.write("- " + line)

    commands_path = os.path.join(detail_dir, 'Capability_commands.txt')
    if os.path.isfile(commands_path):
        results_file.write('\nCapability_commands:\n')
        with open(commands_path, 'r') as infile:
            for line in infile:
                if line.startswith('  commandIndex:'):
                    line = line[line.find('0x'):]
                    results_file.write("- " + line)

    curves_path = os.path.join(detail_dir, 'Capability_ecc-curves.txt')
    if os.path.isfile(curves_path):
        results_file.write('\nCapability_ecc-curves:\n')
        with open(curves_path, 'r') as infile:
            for line in infile:
                line = line[line.find('(') + 1:line.find(')')]
                results_file.write("  " + line + '\n')


def write_perf_file(perf_file, detail_dir):
    perf_csvs = glob.glob(os.path.join(detail_dir, 'Perf_*.csv'))
    perf_csvs.sort()
    prev_command, command = None, None
    for filepath in perf_csvs:
        filename = os.path.basename(filepath)
        params_idx = filename.find(':')
        suffix_idx = filename.find('.csv')
        prev_command, command = command, filename[5:suffix_idx if params_idx == -1 else params_idx]
        params = filename[params_idx+1:suffix_idx].split('_')

        if prev_command != command:
            perf_file.write('\nTPM2_' + command + ':\n')

        if command == 'GetRandom':
            perf_file.write('- data length (bytes): 32\n')
        elif command in ('Sign', 'VerifySignature', 'RSA_Encrypt', 'RSA_Decrypt'):
            perf_file.write(f'- key parameters: {params[0]} {params[1]}\n')
            perf_file.write(f'  scheme: {params[2]}\n')
        elif command == 'EncryptDecrypt':
            perf_file.write(f'- algorithm: {params[0]}\n')
            perf_file.write(f'  key length: {params[1]}\n')
            perf_file.write(f'  mode: {params[2]}\n')
            perf_file.write(f'  encrypt/decrypt?: {params[3]}\n')
            perf_file.write('  data length (bytes): 256\n')
        elif command == 'HMAC':
            perf_file.write('- hash algorithm: SHA-256\n')
            perf_file.write('  data length (bytes): 256\n')
        elif command == 'Hash':
            perf_file.write(f'- hash algorithm: {params[0]}\n')
            perf_file.write('  data length (bytes): 256\n')
        elif command == 'ZGen':
            perf_file.write(f'- key parameters: {params[0]}\n')
            perf_file.write(f'  scheme: {params[1]}\n')
        else:
            perf_file.write(f'- key parameters: {" ".join(params)}\n')

        with open(filepath, 'r') as infile:
            avg_op, min_op, max_op, total, success, fail, error = compute_stats(infile)
            perf_file.write('  operation stats (ms/op):\n')
            perf_file.write(f'    avg op: {avg_op:.2f}\n')
            perf_file.write(f'    min op: {min_op:.2f}\n')
            perf_file.write(f'    max op: {max_op:.2f}\n')
            perf_file.write('  operation info:\n')
            perf_file.write(f'    total iterations: {total}\n')
            perf_file.write(f'    successful: {success}\n')
            perf_file.write(f'    failed: {fail}\n')
            perf_file.write(f'    error: {"None" if not error else error}\n')


def create_result_files(outdir):
    detail_dir = os.path.join(outdir, 'detail')
    manufacturer, vendor_str, fw = get_tpm_id(detail_dir)

    with open(os.path.join(outdir, "results.yaml"), 'w') as results_file:
        write_header(results_file, detail_dir)
        write_results_file(results_file, detail_dir)

    with open(os.path.join(outdir, 'performance.yaml'), 'w') as perf_file:
        write_header(perf_file, detail_dir)
        write_perf_file(perf_file, detail_dir)


def write_legacy_header(file, detail_dir):
    image_tag = get_image_tag(detail_dir)
    manufacturer, vendor_str, fw = get_tpm_id(detail_dir)
    file.write(f'Execution date/time;{datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")}\n')
    file.write(f'Manufacturer;{manufacturer}\n')
    file.write(f'Vendor string;{vendor_str}\n')
    file.write(f'Firmware version;{fw}\n')
    file.write(f'Image tag;{image_tag}\n')
    file.write(f'TPM devices;{";".join(glob.glob("/dev/tpm*"))}\n')
    try:
        system_manufacturer, product_name, system_version, bios_version, uname = get_system_id(detail_dir)
        file.write(f'Device manufacturer;{system_manufacturer}\n')
        file.write(f'Device name;{product_name}\n')
        file.write(f'Device version;{system_version}\n')
        file.write(f'BIOS version;{bios_version}\n')
        file.write(f'System information;{uname}\n')
    except:
        pass
    file.write('\n')


def write_legacy_results_file(results_file, detail_dir):
    properties_path = os.path.join(detail_dir, 'Capability_properties-fixed.txt')
    if os.path.isfile(properties_path):
        results_file.write('\nCapability_properties-fixed\n')
        with open(properties_path, 'r') as infile:
            properties = ""
            for line in infile:
                if line.startswith('  as UINT32:'):
                    continue
                if line.startswith('  as string:'):
                    line = line[line.find('"'):]
                    properties = properties[:-1] + '\t' + line
                else:
                    properties += line.replace(':', ';')
            results_file.write(properties)

    algorithms_path = os.path.join(detail_dir, 'Capability_algorithms.txt')
    if os.path.isfile(algorithms_path):
        results_file.write('\nCapability_algorithms\n')
        with open(algorithms_path, 'r') as infile:
            for line in infile:
                if line.startswith('  value:'):
                    line = line[line.find('0x'):]
                    results_file.write(line)

    commands_path = os.path.join(detail_dir, 'Capability_commands.txt')
    if os.path.isfile(commands_path):
        results_file.write('\nCapability_commands\n')
        with open(commands_path, 'r') as infile:
            for line in infile:
                if line.startswith('  commandIndex:'):
                    line = line[line.find('0x'):]
                    results_file.write(line)

    curves_path = os.path.join(detail_dir, 'Capability_ecc-curves.txt')
    if os.path.isfile(curves_path):
        results_file.write('\nCapability_ecc-curves\n')
        with open(curves_path, 'r') as infile:
            for line in infile:
                line = line[line.find('(') + 1:line.find(')')]
                results_file.write(line + '\n')


def write_legacy_perf_file(perf_file, detail_dir):
    perf_csvs = glob.glob(os.path.join(detail_dir, 'Perf_*.csv'))
    perf_csvs.sort()
    command = ''
    for filepath in perf_csvs:
        filename = os.path.basename(filepath)
        params_idx = filename.find(':')
        suffix_idx = filename.find('.csv')
        new_command = filename[5:suffix_idx if params_idx == -1 else params_idx]
        params = filename[params_idx+1:suffix_idx].split('_')
        if new_command != command:
            command = new_command
            perf_file.write('TPM2_' + command + '\n\n')

        if command == 'GetRandom':
            perf_file.write('Data length (bytes):;32\n')
        elif command in ('Sign', 'VerifySignature', 'RSA_Encrypt', 'RSA_Decrypt'):
            perf_file.write(f'Key parameters:;{params[0]} {params[1]};Scheme:;{params[2]}\n')
        elif command == 'EncryptDecrypt':
            perf_file.write(f'Algorithm:;{params[0]};Key length:;{params[1]};Mode:;{params[2]};Encrypt/decrypt?:;{params[3]};Data length (bytes):;256\n')
        elif command == 'HMAC':
            perf_file.write('Hash algorithm:;SHA-256;Data length (bytes):;256\n')
        elif command == 'Hash':
            perf_file.write(f'Hash algorithm:;{params[0]};Data length (bytes):;256\n')
        elif command == 'ZGen':
            perf_file.write(f'Key parameters:;{params[0]};Scheme:;{params[1]}\n')
        else:
            perf_file.write(f'Key parameters:;{" ".join(params)}\n')

        with open(filepath, 'r') as infile:
            avg_op, min_op, max_op, total, success, fail, error = compute_stats(infile)
            perf_file.write(f'operation stats (ms/op):;avg op:;{avg_op:.2f};min op:;{min_op:.2f};max op:;{max_op:.2f}\n')
            perf_file.write(f'operation info:;total iterations:;{total};successful:;{success};failed:;{fail};error:;{"None" if not error else error}\n\n')


def create_legacy_result_files(outdir):
    detail_dir = os.path.join(outdir, 'detail')
    manufacturer, vendor_str, fw = get_tpm_id(detail_dir)
    file_name = manufacturer + '_' + vendor_str + '_' + fw + '.csv'

    os.makedirs(os.path.join(outdir, 'results'), exist_ok=True)
    with open(os.path.join(outdir, 'results', file_name), 'w') as results_file:
        write_legacy_header(results_file, detail_dir)
        write_legacy_results_file(results_file, detail_dir)

    os.makedirs(os.path.join(outdir, 'performance'), exist_ok=True)
    with open(os.path.join(outdir, 'performance', file_name), 'w') as perf_file:
        write_legacy_header(perf_file, detail_dir)
        write_legacy_perf_file(perf_file, detail_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('test', metavar='test', type=str)
    parser.add_argument('-n', '--num', type=int, required=False)
    parser.add_argument('-d', '--duration', type=int, required=False)
    parser.add_argument('-t', '--keytype', type=str, required=False)
    parser.add_argument('-l', '--keylen', type=int, required=False)
    parser.add_argument('-C', '--curveid', type=lambda x: int(x, 0), required=False)
    parser.add_argument('-c', '--command', type=str, required=False)
    parser.add_argument('-o', '--outdir', type=str, required=False, default='out')
    parser.add_argument('--with-image-tag', type=str, required=False, default=IMAGE_TAG)
    parser.add_argument('--only-measure', action='store_true', default=False)
    parser.add_argument('--include-legacy', action='store_true', default=False)
    parser.add_argument('--machine-readable-statuses', action='store_true', default=False)
    parser.add_argument('--use-system-algtest', action='store_true', default=False)
    args = parser.parse_args()

    if not os.path.exists(DEVICE):
        print(f'Device {DEVICE} not found')
        return

    print('IMPORTANT: Please do not suspend or hibernate the computer while testing the TPM!')

    COMMANDS = {
        "capability": capability_handler,
        "keygen": keygen_handler,
        "perf": perf_handler,
        "cryptoops": cryptoops_handler,
        "rng": rng_handler,
        "format": format_handler,
        "all": all_handler,
        "extensive": extensive_handler,
    }

    if args.test in COMMANDS:
        os.makedirs(os.path.join(args.outdir, 'detail'), exist_ok=True)
        COMMANDS[args.test](args)
        set_status(args, 'Compressing the results...')
        zip(args.outdir)
        set_status(args, 'The tests are finished.')
        print('Thank you! Please send us the generated file (' + args.outdir + '.zip).')
    else:
        print('Invalid test type, needs to be one of: ' + ', '.join(COMMANDS.keys()))


if __name__ == '__main__':
    main()
