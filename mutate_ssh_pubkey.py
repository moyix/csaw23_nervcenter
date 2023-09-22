#!/usr/bin/env python3

import sys
import base64
import io
import argparse
import random

sys.path.append('/home/moyix/git/RsaCtfTool')
from lib.keys_wrapper import generate_keys_from_p_q_e_n

def parse_key(ssh_pubkey):
    keyline = ssh_pubkey.strip().split()
    keytpe_s, encoded_key, comment = keyline
    print(f"Key type: {keytpe_s}, comment: {comment} encoded_key len {len(encoded_key)}", file=sys.stderr)
    print(repr(encoded_key), file=sys.stderr)
    ssh_pubkey = io.BytesIO(base64.b64decode(encoded_key))

    # key type
    s_len = int.from_bytes(ssh_pubkey.read(4), byteorder='big')
    key_type = ssh_pubkey.read(s_len).decode('utf-8')
    assert key_type == 'ssh-rsa'

    # exponent
    s_len = int.from_bytes(ssh_pubkey.read(4), byteorder='big')
    exponent = int.from_bytes(ssh_pubkey.read(s_len), byteorder='big')

    # modulus
    s_len = int.from_bytes(ssh_pubkey.read(4), byteorder='big')
    modulus = int.from_bytes(ssh_pubkey.read(s_len), byteorder='big')

    return (key_type, exponent, modulus)

def main():
    parser = argparse.ArgumentParser(description='Parse SSH public key and generate k-bit variants')
    parser.add_argument('ssh_pubkey', help='SSH public key')
    parser.add_argument('-k', type=int, default=5, help='Key bits to mutate')
    parser.add_argument('--lsb', action='store_true', help='Mutate the least significant bits (default: mutate MSB)')
    parser.add_argument('-o', '--output_prefix', default='ssh_key_mut', help='Output file prefix')
    parser.add_argument('-r', '--random', action='store_true', help='Randomly flip k bits in the key')
    parser.add_argument('-n', '--no-mutate', action='store_true', help='Do not mutate the key, just print the key info')
    args = parser.parse_args()

    key_type, exponent, modulus = parse_key(open(args.ssh_pubkey).read())
    key_bits = modulus.bit_length()
    if args.no_mutate:
        print(f"{key_type} {key_bits}-bit key with public exponent {exponent}")
        print("N = ", end='')
        print(f"{modulus:#x}")
        return

    if not args.random:
        for mut in range(0, 2**args.k):
            mut_fmt = f"{{:0{args.k}b}}"
            mod_fmt = f"{{:0{key_bits}b}}"
            mut_bin = mut_fmt.format(mut)
            mod_bin = mod_fmt.format(modulus)
            hexdigits = key_bits // 4
            lsbstr = 'lsb' if args.lsb else 'msb'
            fname = f"{args.output_prefix}_{mut_bin}_{lsbstr}.pem"
            if args.lsb:
                mut_modulus = int(mod_bin[:-args.k] + mut_bin, 2)
            else:
                mut_modulus = int(mut_bin + mod_bin[args.k:], 2)
            print(f"[{mut_bin}] {mut_modulus:0{hexdigits}x}")
            try:
                pubkey, privkey = generate_keys_from_p_q_e_n(None, None, exponent, mut_modulus)
            except ValueError as e:
                print(f"Failed to generate PEM for mutation {mut:#x}: {e}, saving as plain", file=sys.stderr)
                with open(fname, 'w') as f:
                    print(exponent, mut_modulus, file=f)
                continue
            with open(fname, 'wb') as f:
                f.write(pubkey)
    else:
        mut = modulus
        which_bits = []
        for _ in range(args.k):
            which_bit = random.randint(0, key_bits - 1)
            mut = mut ^ (1 << which_bit)
            which_bits.append(which_bit)
        which_bits.sort()
        which_str = ','.join(map(str, which_bits))
        fname = f"{args.output_prefix}_flip_{which_str}.pem"
        try:
            pubkey, privkey = generate_keys_from_p_q_e_n(None, None, exponent, mut)
            with open(fname, 'w') as f:
                print(pubkey.decode(), file=f)
        except ValueError as e:
            print(f"Failed to generate key for mutation {mut:#x}: {e}, saving as plain", file=sys.stderr)
            with open(fname, 'w') as f:
                print(exponent, mut, file=f)

if __name__ == '__main__':
    main()