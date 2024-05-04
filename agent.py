#!/usr/bin/python3

import argparse
import asyncio
import logging
import struct
import socket
import sys
import signal
import statistics

from datetime import datetime

# TODO: put a checksum in the message as well to ensure no corruption: this
# would make it possibe to check corruption effects on the network.
# TODO: implement udp behavior as well.
# TODO: make the client (for UDP, because it is non-reliable) implement
# statistics like RTT, delay, jitter, packet loss, delay variation etc
# which is very useful for verifying network behavior 'live' e.g. when
# applying iptables rules. Implement the stats for TCP as welll, but only the
# applicable ones e.g. delay, jitter, etc, but not packet loss.

# TODO: use ntohs etc -- convert between network and host byte order.
#
# TODO: client hangs tryinng to send even when blocking; and tehrefore it does
# not check sigint flag and does not exit when asked.
#
# TODO: do not use sendall, use send and receive and construct the buffers
# piecemeal
#
# NOTE: must have separate reader and writer for tcp server as well, given
# multiple clients can connect to it.

MUST_STOP = False
BUFFSZ = 2**14
TIMEOUT_THRESH = 10 # seconds
MS_PER_SEC = 1000

def signal_handler(*_):
    global MUST_STOP
    MUST_STOP = True

def log(s, print_time=True):
    if print_time:
        now = datetime.now()
        time = now.strftime("%H:%M:%S.%f")
        s = f"[{time}] {s}"
    print(s)

def timedelta_to_fractional_seconds(time):
    usecs_per_sec = 1e6
    return time.seconds + time.microseconds / usecs_per_sec

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

client_parser.add_argument('--pin-display',
                           action='store_true',
                           default=False,
                           required=False,
                           help="""Pin the report at the top of the screen always.
                           NOTE: a subsequent report in this case overwrites the
                           previous one"""
                           )


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

if not (args.cmd):
    print("Must specify operational mode: (client | server )")
    sys.exit(1)

#print("args is ", args)
#print("")
 
class packet:
    # a packet is simply a uint32_t sequence number right now.
    fixedsz = len(struct.pack("!I", 0))

    def __init__(self, sequence_number=0):
        self.seqn = sequence_number

    def tobytes(self):
        """Convert to a bytearray in network byte order."""
        return struct.pack("!I", self.seqn)

    def frombytes(self, bytestring):
        """Initialize from bytearray in network byte order."""
        s = struct.unpack("!I", bytestring)
        self.seqn = s[0]
        return self

class NetStats:
    """A struct to hold stats necessary for generating a report describing the
    network quality / live state of the connection between client and server.
    NOTE this is a superset of the characteristics of all protocols used. For
    example, clearly for TCP (since it is a reliable protocol) pkts_reordered,
    pkts_lost, fraction_lost etc will always be 0 (hence it does not make sense
    to show them in any report).
    """
    def __init__(self):
        self.pkts_sent = 0
        self.pkts_received = 0
        self.pkts_answered = 0
        self.pkts_lost = 0
        self.pkts_reordered = 0
        self.duplicates = 0
        self.fraction_lost = 0
        self.rtt = 0
        self.owtt = 0
        self.jitter = 0
        # TODO: calculate others: delay variance, jitter standard deviation etc

class IoState:
    """A struct to contain all the state data kept on unacknowledged packets.
    """
    def __init__(self):
        # as-yet unacknowledged packets; The length of the list has an upper
        # bound that determined the number of unacknowledged packets that are
        # waited for at any given time. If the list is about to grow bigger than
        # this upper threshold, we stop sending and wait for responses.
        self.unackd = dict()
        self.max_num_unackd = 50
        self.received = set()
        self.rxbuf = None
        self.txbuf = None
        self.last_sequence_sent = 0
        self.last_sequence_received = 0
        self.last_send_time = None
        self.max_num_rtts = 10
        self.rtts = []

def generate_report(iostate, stats):
    stats.rtt = statistics.mean(iostate.rtts)
    stats.owtt = stats.rtt / 2
    if len(iostate.rtts) >= 2:
        stats.jitter = iostate.rtts[-1] - iostate.rtts[-2]

    print("\n\n")
    print("=========== iostate ================")
    print(" unackd: ", iostate.unackd)
    print(" received: ", iostate.received)
    print(" last_sequence_sent: ", iostate.last_sequence_sent)
    print(" last_sequence_received: ", iostate.last_sequence_received)
    print(" last_send_time: ", iostate.last_send_time)
    print(" rtts: ", iostate.rtts)
    print("")

    print("=========== stats ================")
    print("pkts_sent: ", stats.pkts_sent)
    print("pkts_received: ", stats.pkts_received)
    print("pkts_answered: ", stats.pkts_answered)
    print("pkts_lost: ", stats.pkts_lost)
    print("pkts_reordered: ", stats.pkts_reordered)
    print("duplicates: ", stats.duplicates)
    print("fraction_lost: ", stats.fraction_lost)
    print("rtt: ", stats.rtt)
    print("owtt: ", stats.owtt)
    print("jitter: ", stats.jitter)
    print("\n\n")

def read_from_socket(sock, iostate, stats):
    """Read a packet from the socket, in part or, if possible, in full.
    Assumes sock is readable when this function is called.
    """
    bytes_to_read = packet.fixedsz
    if iostate.rxbuf == None:
        iostate.rxbuf = b''

    # how many bytes needed until we can form a complete message
    bytes_to_read = packet.fixedsz - len(iostate.rxbuf)
    bytes_ = sock.recv(bytes_to_read)

    if len(bytes_) == 0:
        logging.info(" *** Recv %s bytes, closing socket.", len(bytes_))
        sock.close()
        return

    iostate.rxbuf = iostate.rxbuf + bytes_

    # if we have a full packet
    if len(iostate.rxbuf) == packet.fixedsz:
        pkt = packet()
        pkt.frombytes(iostate.rxbuf)
        logging.info(" *** Recv %s bytes, seq=%s",
                     len(iostate.rxbuf), pkt.seqn)

        iostate.rxbuf = None
        receipt_time = datetime.now()
        rtt = None

        stats.pkts_received += 1
        # TODO: make this a list so we can bound it in size to a max len

        # if a duplicate (sequence we have seen before, whether in a lost
        # packet, delayed packet, or correctly ackd packet)
        if pkt.seqn in iostate.received:
            stats.duplicates += 1

        iostate.received.add(pkt.seqn)

        # if there is an outstanding message waiting for an ack.
        unackd = iostate.unackd.keys()
        if pkt.seqn in unackd:
            rtt =  receipt_time - iostate.unackd[pkt.seqn]
            rtt = timedelta_to_fractional_seconds(rtt)
            iostate.unackd.pop(pkt.seqn)
            if rtt > TIMEOUT_THRESH:
                # received, but too late; count as a lost packet
                stats.pkts_lost += 1
            else:
                stats.pkts_answered += 1
                if pkt.seqn != (iostate.last_sequence_received+1):
                    stats.pkts_reordered += 1
                iostate.last_sequence_received = pkt.seqn
                iostate.rtts.append(rtt)
                if len(iostate.rtts) > iostate.max_num_rtts:
                    # discard n oldest entries
                    n = len(iostate.rtts) - iostate.max_num_rtts
                    iostate.rtts = iostate.rtts[n:]
        else:
            logging.error("Packet received with sequence %s that that fits no "
                          "category", pkt.seqn)
        generate_report(iostate, stats)
    else:
        print("else!!!")

def write_to_socket(sock, iostate, stats, scheduler,
                    *scheduler_args):
    """Writes packet (in part or in whole if possible) to the socket.
    Assumes sock is writable when this function is called."""
    print("in write to socket!!!")

    # to schedule the next write as appropriate
    args_for_this = (sock, iostate, stats)
    this = write_to_socket

    # stage a new outgoing packet if needed
    if iostate.txbuf == None:
        iostate.txbuf = packet(iostate.last_sequence_sent+1).tobytes()

    bytes_sent = sock.send(iostate.txbuf)
    if bytes_sent < len(iostate.txbuf):
        print("not sent all, returning")
        # truncate buffer to remaning bytes to be sent
        iostate.txbuf = iostate.txbuf[bytes_sent:]
    else:
        print("SENT BYTES: ", iostate.txbuf)

        # else all bytes sent
        iostate.txbuf = None
        sendoff_time = datetime.now()
        iostate.last_sequence_sent += 1
        stats.pkts_sent += 1
        iostate.unackd[iostate.last_sequence_sent] = sendoff_time
        iostate.last_send_time = sendoff_time

    #print("Calling scheduler with args:\n"
    #      "scheduler_args:", *scheduler_args,
    #      "this: ", this,
    #      "args_for_this: ", *args_for_this)
          
    scheduler(*scheduler_args, this, *args_for_this)

def schedule_next_write(sock, loop, iostate, ping_interval, writer, *writer_args):
    # INVARIANT: when we enter this function, sock is *not* monitored for
    # being writable.
    loop.remove_writer(sock)

    print("\n\n")
    #print("called schedule_next_write with args: "
    #      "\nsocket = ", sock,
    #      "\nloop = ", loop,
    #      "\niostate = ", iostate,
    #      "\nping interval = ", ping_interval,
    #      "\nwriter callback = ", writer,
    #      "\nwriter_args = ", *writer_args)
    #print("type of sock = ", type(sock), " type of loop = ", type(loop))
    print("\n\n")
    
    this = schedule_next_write
    args_for_this = (sock, loop, iostate, ping_interval)
    
    if len(iostate.unackd) == 0 or iostate.txbuf != None:
        print("adding writer immediately")
        loop.add_writer(sock, writer, *writer_args, this, *args_for_this)
        return

    last_send_time = iostate.last_send_time
    delta = datetime.now() - last_send_time
    gap = timedelta_to_fractional_seconds(delta)
    if gap >= ping_interval:
        print("time for next ping")
        loop.add_writer(sock, writer, *writer_args, this, *args_for_this)
        return

    print("waiting until next deadline: ", ping_interval - gap)
    loop.call_later(ping_interval - gap, this, *args_for_this, writer, *writer_args)
        

# TODO: this requires a more complex loop, like epoll, so we can send and
# receive without bllocking waiting for a receipt every time we send; i.e.
# the packet may be completely lost so we would wait indefinitely. Only read
# from the socket when it is readable! -- just use asyncio and:
#
# add_reader -- read from socket whenever readable
# add_timer to write to socket on interval: note udp socket is always writable
# so we don't need to check for that condition; that is only for tcp socket.
# for tcp, add_writer: write to socket when writable.
def run_client(l4proto, server_address, server_port, num_pings, ping_interval):
    ping_interval = ping_interval / MS_PER_SEC

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
    else:
        logging.info(f"Connected to server.")

    ## Send the data
    global MUST_STOP
    stats = NetStats()
    iostate = IoState()

    loop = asyncio.new_event_loop()
    loop.add_reader(s, read_from_socket, s, iostate, stats)
    write_to_socket_args = (s, iostate, stats)
    loop.call_later(1, schedule_next_write, s, loop, iostate, ping_interval,
                    write_to_socket, *write_to_socket_args)
    # daniell

    delay_ms = 10 * 1/1000
    loop.call_later(delay_ms, check_stop_flag, loop)
    loop.call_later(1000, generate_report, iostate, stats)

    loop.run_forever()

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

def read_from_tcp_socket(loop, sock, client_socks):
    response_payload = sock.recv(BUFFSZ)
    pkt = packet()
    if len(response_payload) > 0:
        pkt.frombytes(response_payload)
        logging.info(" *** %s bytes from %s: seq=%s", len(response_payload),
                     sock.getpeername(), pkt.seqn)
    else:
        logging.info(" *** %s bytes from %s", len(response_payload), sock.getpeername())

    if (len(response_payload) == 0):
        logging.warning("Closing connection to %s", sock.getpeername())
        sock.close()
        loop.remove_reader(sock)
        while sock in client_socks:
            print('removing from list')
            client_socks.remove(sock)
        return

    # echo back to the server; NOTE: we simplistically assume the client socket
    # is always immediately writable once we've read from it. For our basic test
    # client/server setup this is True.
    sock.sendall(response_payload)


def send_all_udp(sock, peer_address, payload):
    bytes_to_send = len(payload)
    while bytes_to_send > 0:
        bytes_sent = sock.sendto(payload, peer_address)
        bytes_to_send -= bytes_sent

def read_from_udp_socket(sock):
    response_payload, peer = sock.recvfrom(BUFFSZ)
    pkt = packet()
    pkt.frombytes(response_payload)
    logging.info(" *** %s bytes from %s: seq=%s", len(response_payload),
                 f'{peer[0]}:{peer[1]}', pkt.seqn)

    # echo back to the server; NOTE: we simplistically assume the client socket
    # is always immediately writable once we've read from it. For our basic test
    # client/server setup this is True.
    send_all_udp(sock, peer, response_payload)

def accept_tcp_connection(fd, client_socks, loop):
    sock, _ = fd.accept()
    logging.info("Connection from %s", sock.getpeername())
    client_socks.append(sock)
    args_for_reader = [loop, sock, client_socks]
    loop.add_reader(sock, read_from_tcp_socket, *args_for_reader)

def run_server(server_address, server_port, l4proto):
    socktype = None
    if l4proto == 'tcp':
        socktype = socket.SOCK_STREAM
    elif l4proto == 'udp':
        socktype = socket.SOCK_DGRAM
    else:
        logging.error("Invalid layer 4 protocol specified: %s", l4proto)
        sys.exit(1)

    server_sock = socket.socket(socket.AF_INET, socktype)
    logging.info(f'Starting server on {server_address}:{server_port},{l4proto})')
    try:
        server_sock.bind((server_address, server_port))
        if socktype == socket.SOCK_STREAM:
            server_sock.listen()
    except:
        logging.error("Failed to bind/listen.")
        sys.exit(1)

    client_socks = []  # only used for TCP

    loop = asyncio.new_event_loop()
    if socktype == socket.SOCK_STREAM:
        loop.add_reader(server_sock, accept_tcp_connection, server_sock, client_socks, loop)
    elif socktype == socket.SOCK_DGRAM:
        loop.add_reader(server_sock, read_from_udp_socket, server_sock)

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
        run_server(*address, l4proto)
    elif args.cmd == 'client':
        run_client(l4proto, args.server_address, int(args.server_port),
                   int(args.num_pings),
                   int(args.ping_interval))

if __name__ == '__main__':
    main()

