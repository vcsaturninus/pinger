#!/usr/bin/python3

import argparse
import asyncio
import logging
import struct
import socket
import sys
import signal

from datetime import datetime
from time import sleep

# TODO: implement udp behavior as well.
# TODO: make the client (for UDP, because it is non-reliable) implement
# statistics like RTT, delay, jitter, packet loss, delay variation etc
# which is very useful for verifying network behavior 'live' e.g. when
# applying iptables rules. Implement the stats for TCP as welll, but only the
# applicable ones e.g. delay, jitter, etc, but not packet loss.

MUST_STOP = False
BUFFSZ = 2**14

def signal_handler(sig, frame):
    global MUST_STOP
    MUST_STOP = True

def log(s, print_time=True):
    if print_time:
        now = datetime.now()
        time = now.strftime("%H:%M:%S.%f")
        s = f"[{time}] {s}"
    print(s)


logging.basicConfig(
        format='%(asctime)s.%(msecs)03d | %(message)s', level=logging.INFO,
                    datefmt = "%H:%M:%S")

signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description='UDP/TCP agent')

subparsers = parser.add_subparsers(help='commands', dest='cmd')
server_parser = subparsers.add_parser('server', help='Run as server')
client_parser = subparsers.add_parser('client', help='Run as client')
mutex = parser.add_mutually_exclusive_group()

mutex.add_argument('-t',
                     '--tcp',
                     action='store_true',
                     dest='use_tcp',
                     help='Use TCP'
                     )

mutex.add_argument('-u',
                     '--udp',
                     action='store_true',
                     dest='use_udp',
                     help='Use UDP'
                     )

client_parser.add_argument("-c",
                           "--count",
                           action='store',
                           default=10,
                           required=False,
                           dest='num_pings',
                           help='Number of pings to send to server'
                           )

client_parser.add_argument("-i",
                           "--interval",
                           action='store',
                           default=1000,
                           required=False,
                           dest='ping_interval',
                           help='Ping interval in milliseconds'
                           )

client_parser.add_argument("-a",
                           "--server-address",
                           action='store',
                           default='localhost',
                           required=False,
                           dest='server_address',
                           help='IP address of the server'
                           )

client_parser.add_argument('-p',
                           "--server-port",
                           action='store',
                           default='54321',
                           required=False,
                           dest='server_port',
                           help='Port the server is listening on'
                           )

client_parser.add_argument('-s',
                           "--stats",
                           action='store',
                           default=10,
                           required=False,
                           dest='stats_interval_ms',
                           help="""Whether to calculate and display stats (delay, pktloss, jitter etc).""")


server_parser.add_argument('-p',
                           "--port",
                           action='store',
                           default=54321,
                           dest='port',
                           required=False,
                           help='Port to listen on'
                           )

args = parser.parse_args()

if not (args.use_udp or args.use_tcp):
    print("Must specify layer-4 protocol to use (udp: -u | tcp: -t)")
    sys.exit(1)

#print("args is ", args)
#print("")

def run_client(l4proto, server_address, server_port, num_pings, ping_interval):
    socktype = None
    if l4proto == 'tcp':
        socktype = socket.SOCK_STREAM
    elif l4proto == 'udp':
        socktype = socket.SOCK_DGRAM
    else:
        logging.error("Invalid layer 4 protocol specified: %s", l4proto)
        sys.exit(1)

    s = socket.socket(socket.AF_INET, socktype)
    logging.info(f'Connecting to server ({args.server_address}:{args.server_port},{l4proto})')

    try:
        s.connect((server_address, server_port))
    except:
        logging.error("Failed to conneect.")
        sys.exit(1)

    ## Send the data
    message = 'BEAT'
    encoding='ascii'
    payload = message.encode(encoding)
    global MUST_STOP

    for i in range(num_pings + 1):
        if MUST_STOP: break
        logging.info('Sending data: %s', payload)
        s.sendall(message.encode())

        # Receive a response
        response_payload = s.recv(BUFFSZ)
        response = response_payload.decode(encoding)
        logging.info(" *** Recv (%s bytes): %s",
                     len(response_payload), response_payload)
        sleep(ping_interval / 1000)

    logging.info('closing socket')
    s.close()

# self-rearming callback
def check_stop_flag(loop):
    global MUST_STOP
    if MUST_STOP:
        logging.warning("Stopping...")
        loop.stop()
        return

    delay_ms = 10 * 1/1000
    loop.call_later(delay_ms, check_stop_flag, loop)

# TODO: stats should be a map populated in the client
def print_udp_stats(stats):
    pass

def print_tcp_stats(stats):
    pass

def read_from_socket(sock, client_socks):
    response_payload = sock.recv(BUFFSZ)
    logging.info(" *** Recv (%s bytes from %s): %s", len(response_payload), response_payload, sock.getpeername())

    # only tcp has a per-client 'connection' socket that we can close.
    if (len(response_payload) == 0) and socket.SOCK_STREAM:
        logging.warning("Closing connection to %s", sock.getpeername())
        sock.close()
        for i in client_socks:
            if sock == i:
                client_socks.remove(sock)
        return

    # echo back to the server; NOTE: we simplistically assume the client socket
    # is always immediately writable once we've read from it. For our basic test
    # client/server setup this is True.
    sock.sendall(response_payload)

def accept_tcp_connection(fd, client_socks, loop):
    sock, _ = fd.accept()
    print("socket is ", sock)
    client_socks.append(sock)
    loop.add_reader(sock, read_from_socket, sock, client_socks)

def run_server(server_address, server_port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.info(f'Starting server on {server_address}:{server_port})')
    try:
        server_sock.bind((server_address, server_port))
        server_sock.listen()
    except:
        logging.error("Failed to bind/listen.")
        sys.exit(1)

    client_socks = []
    loop = asyncio.new_event_loop()
    loop.add_reader(server_sock, accept_tcp_connection, server_sock, client_socks, loop)
    delay_ms = 10 * 1/1000
    loop.call_later(delay_ms, check_stop_flag, loop)

    loop.run_forever()

    for sock in client_socks: sock.close()
    server_sock.close()

def main():
    l4proto = None
    if args.use_tcp: l4proto = 'tcp'
    elif args.use_udp: l4proto = 'udp'
    else: raise ValueError

    if args.cmd == 'server':
        #address = ('localhost', int(args.port))
        address = ('0.0.0.0', int(args.port))
        run_server(*address)
    elif args.cmd == 'client':
        run_client(l4proto, args.server_address, int(args.server_port),
                   int(args.num_pings),
                   int(args.ping_interval))

if __name__ == '__main__':
    main()

