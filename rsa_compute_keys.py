import sys
import csv

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
    except Exception:
        print(f"Cannot compute row {row['id']}")
        return
    q = n // p
    totient = (p - 1) * (q - 1)
    _, d, _ = extended_euclidean(e, totient)
    d %= totient

    message = 12345678901234567890
    assert mod_exp(mod_exp(message, e, n), d, n) == message, \
        f"something went wrong (row {row['id']})"

    row['q'] = '%X' % q
    row['d'] = '%X' % d

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 rsa_tester.py <csvfile>")
        return

    filename = sys.argv[1]
    rows = []
    with open(filename) as infile:
        reader = csv.DictReader(infile, delimiter=';')
        for row in reader:
            rows.append(row)

    for row in rows:
        compute_row(row)

    with open(filename, 'w') as outfile:
        writer = csv.DictWriter(
                outfile, delimiter=';', fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

if __name__ == '__main__':
    main()
