import os
import sys

def get_val(line):
    return line[line.find("0x") + 2:-1]

def get_support_file_name(outdir):
    with open(os.path.join(outdir, 'Quicktest_properties-fixed.txt'), 'r') as properties_file:
        read_vendor_str = False
        manufacturer = ""
        vendor_str = ""
        fw1 = ""
        fw2 = ""
        for line in properties_file:
            if read_vendor_str:
                vendor_str += bytearray.fromhex(get_val(line)).decode()
                read_vendor_str = False
            elif line.startswith('TPM_PT_MANUFACTURER'):
                manufacturer = bytearray.fromhex(get_val(line)).decode()
            elif line.startswith('TPM_PT_FIRMWARE_VERSION_1'):
                fw1 = line[line.find("0x") + 2:-1]
            elif line.startswith('TPM_PT_FIRMWARE_VERSION_2'):
                fw2 = line[line.find("0x") + 2:-1]
            elif line.startswith('TPM_PT_VENDOR_STRING_'):
                read_vendor_str = True

        support_file_name = manufacturer + '_' + vendor_str + '%' + fw1 + '_' + fw2 + '.csv'
    return support_file_name.replace('\0', '')

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 prepare_result.py <outdir>")
        return

    outdir = sys.argv[1]
    support_file_name = get_support_file_name(outdir)

    with open(os.path.join(outdir, support_file_name), 'w') as support_file:
        support_file.write('Tested and provided by;\n')
        support_file.write('Execution date/time;\n') # TODO fill in date/time
        with open(os.path.join(outdir, 'docker_info.txt'), 'r') as infile:
            line = infile.read()
            docker_version = line[line.find(' v') + 2:]
            support_file.write('Image version; ' + docker_version + '\n')

        support_file.write('\nQuicktest_properties-fixed\n')
        with open(os.path.join(outdir, 'Quicktest_properties-fixed.txt'), 'r') as infile:
            properties = ""
            for line in infile:
                if line.startswith('  as UINT32:'):
                    continue
                if line.startswith('  as string:'):
                    line = line[line.find('"'):]
                    properties = properties[:-1] + '\t' + line
                else:
                    properties += line.replace(':', ';')

            support_file.write(properties)

        support_file.write('\nQuicktest_algorithms\n')
        with open(os.path.join(outdir, 'Quicktest_algorithms.txt'), 'r') as infile:
            for line in infile:
                if line.startswith('TPMA_ALGORITHM'):
                    line = line[line.find('0x'):]
                    line = line[:line.find(' ')]
                    support_file.write(line + '\n')

        support_file.write('\nQuicktest_commands\n')
        with open(os.path.join(outdir, 'Quicktest_commands.txt'), 'r') as infile:
            for line in infile:
                if line.startswith('  commandIndex:'):
                    line = line[line.find('0x'):]
                    support_file.write(line)

        support_file.write('\nQuicktest_ecc-curves\n')
        with open(os.path.join(outdir, 'Quicktest_ecc-curves.txt'), 'r') as infile:
            for line in infile:
                line = line[line.find('(') + 1:line.find(')')]
                support_file.write(line + '\n')

if __name__ == '__main__':
    main()

