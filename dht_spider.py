import socket

from hashlib import sha1
from random import randint
from struct import unpack
from socket import inet_ntoa
from bisect import bisect_left
from threading import Timer
from bencode import bencode, bdecode, BTFailure
from functools import cmp_to_key
import traceback


BOOTSTRAP_NODES = [
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881)
]
TID_LENGTH = 4
KRPC_TIMEOUT = 10
REBORN_TIME = 5 * 60
K = 8
DEFAULT_NODE_ID = "I am a 2B"
DEFAULT_NODE_PORT = 6881


class BucketFull(Exception):
    pass


class KRPC(object):
    def __init__(self):
        self.types = {
            'r': self.response_received,
            'q': self.query_received
        }
        self.actions = {
            'ping': self.ping_received,
            'find_node': self.find_node_received,
            'get_peers': self.get_peers_received,
            'announce_peer': self.announce_peer_received
        }

        if not hasattr(self, 'port'):
            self.port = DEFAULT_NODE_PORT

        # For IPv4, use AF_INET
        # For UDP, use SOCK_DGRAM
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('0.0.0.0', self.port))

    def find_node_handler(self, msg):
        pass

    def response_received(self, msg, address):
        self.find_node_handler(msg)

    def query_received(self, msg, address):
        try:
            self.actions[msg['q']](msg, address)
        except KeyError:
            traceback.print_exc()
        except Exception as ex:
            print(f"Failed handling query request for {address}: {ex}")

    def send_krpc(self, msg, address):
        try:
            self.socket.sendto(bencode(msg), address)
        except OSError:
            traceback.print_exc()

    def ping_received(self, msg, address):
        pass

    def find_node_received(self, msg, address):
        pass

    def get_peers_received(self, msg, address):
        pass

    def announce_peer_received(self, msg, address):
        pass


class Client(KRPC):
    def __init__(self, table):
        self.table = table

        timer(KRPC_TIMEOUT, self.timeout)
        timer(REBORN_TIME, self.reborn)
        super(Client, self).__init__()

    def find_node(self, address, nid=None):
        nid = self.get_neighbor(nid) if nid else self.table.nid
        tid = entropy(TID_LENGTH)

        msg = {
            't': tid,
            'y': 'q',
            'q': 'find_node',
            'a': {
                'id': nid,
                'target': random_id()
            }
        }
        self.send_krpc(msg, address)

    def find_node_handler(self, msg):
        try:
            nodes = decode_nodes(msg['r']['nodes'])
            for node in nodes:
                (nid, ip, port) = node
                if len(nid) != 20:
                    continue
                if nid == self.table.nid:
                    continue
                self.find_node((ip, port), nid)
        except KeyError:
            traceback.print_exc()

    def join_dht(self):
        for address in BOOTSTRAP_NODES:
            self.find_node(address)

    def timeout(self):
        if len(self.table.buckets) < 2:
            self.join_dht()
        timer(KRPC_TIMEOUT, self.timeout)

    def reborn(self):
        self.table.nid = random_id()
        self.table.buckets = [KBucket(0, 2**160)]
        timer(REBORN_TIME, self.reborn)

    def start(self):
        self.join_dht()

        while True:
            (data, address) = self.socket.recvfrom(65536)
            try:
                msg = bdecode(data, decoder=my_decoder)
                self.types[msg['y']](msg, address)
            except KeyError:
                traceback.print_exc()
            except BTFailure:
                print("Error decoding bencode from", address)

    def get_neighbor(self, target: str | bytes) -> bytes:
        if type(target) is str:
            target = bytes.fromhex(target)
        return target[:10] + random_id()[10:]


class Server(Client):
    def __init__(self, master, table, port):
        self.table = table
        self.master = master
        self.port = port
        super(Server, self).__init__(table)

    def ping_received(self, msg, address):
        try:
            nid = msg['a']['id']
            msg = {
                't': msg['t'],
                'y': 'r',
                'r': {
                    'id': self.get_neighbor(nid)
                }
            }
            self.send_krpc(msg, address)
            self.find_node(address, nid)
        except KeyError:
            traceback.print_exc()

    def find_node_received(self, msg, address):
        try:
            target = msg['a']['target']
            neighbors = self.table.get_neighbors(target)

            nid = msg['a']['id']
            msg = {
                't': msg['t'],
                'y': 'r',
                'r': {
                    'id': self.get_neighbor(target),
                    'nodes': encode_nodes(neighbors)
                }
            }
            self.table.append(KNode(nid, *address))
            self.send_krpc(msg, address)
            self.find_node(address, nid)
        except KeyError:
            traceback.print_exc()

    def get_peers_received(self, msg, address):
        try:
            info_hash = msg['a']['info_hash']
            neighbors = self.table.get_neighbors(info_hash)

            nid = msg['a']['id']
            msg = {
                't': msg['t'],
                'y': 'r',
                'r': {
                    'id': self.get_neighbor(info_hash),
                    'nodes': encode_nodes(neighbors)
                }
            }
            self.table.append(KNode(nid, *address))
            self.send_krpc(msg, address)
            self.master.log(info_hash)
            self.find_node(address, nid)
        except KeyError:
            traceback.print_exc()

    def announce_peer_received(self, msg, address):
        try:
            info_hash = msg['a']['info_hash']

            nid = msg['a']['id']
            msg = {
                't': msg['t'],
                'y': 'r',
                'r': {
                    'id': self.get_neighbor(info_hash)
                }
            }

            self.table.append(KNode(nid, *address))
            self.send_krpc(msg, address)
            self.master.log(info_hash)
            self.find_node(address, nid)
        except KeyError:
            traceback.print_exc()


class KTable(object):
    def __init__(self, nid):
        self.nid = nid
        self.buckets = [ KBucket(0, 2**160) ]

    def append(self, node):
        index = self.bucket_index(node.nid)
        bucket = self.buckets[index]
        try:
            bucket.append(node)
        except IndexError:
            return
        except BucketFull:
            if not bucket.in_range(self.nid):
                return
            self.split_bucket(index)
            self.append(node)
        print(f"New node was discovered: nid={node.nid}, ip={node.ip}, port={node.port}")

    def get_neighbors(self, target):
        nodes = []
        if len(self.buckets) == 0:
            return nodes
        if len(target) != 20:
            return nodes

        index = self.bucket_index(target)
        try:
            nodes = self.buckets[index].nodes
            min = index - 1
            max = index + 1

            while len(nodes) < K and ((min >= 0) or max < len(self.buckets)):
                if min >= 0:
                    nodes.extend(self.buckets[min].nodes)

                if max < len(self.buckets):
                    nodes.extend(self.buckets[max].nodes)

                min -= 1
                max += 1

            num = intify(target)
            nodes.sort(key=cmp_to_key(lambda a, b: cmp(num ^ intify(a.nid), num ^ intify(b.nid))))
            return nodes[:K]
        except IndexError:
            return nodes

    def bucket_index(self, target):
        return bisect_left(self.buckets, intify(target))

    def split_bucket(self, index):
        old = self.buckets[index]
        point = old.max - (old.max - old.min) / 2
        new = KBucket(point, old.max)
        old.max = point
        self.buckets.insert(index + 1, new)
        for node in old.nodes[:]:
            if new.in_range(node.nid):
                new.append(node)
                old.remove(node)

    def __iter__(self):
        yield from self.buckets


class KBucket(object):
    __slots__ = ('min', 'max', 'nodes')

    def __init__(self, min, max):
        self.min = min
        self.max = max
        self.nodes = []

    def append(self, node):
        if node in self:
            self.remove(node)
            self.nodes.append(node)
        else:
            if len(self) < K:
                self.nodes.append(node)
            else:
                raise BucketFull()

    def remove(self, node):
        self.nodes.remove(node)

    def in_range(self, target):
        return self.min <= intify(target) < self.max

    def __len__(self):
        return len(self.nodes)

    def __contains__(self, node):
        return node in self.nodes

    def __iter__(self):
        yield from self.nodes

    def __lt__(self, target):
        return self.max <= target


class KNode(object):
    __slots__ = ('nid', 'ip', 'port')

    def __init__(self, nid, ip, port):
        self.nid = nid
        self.ip = ip
        self.port = port

    def __eq__(self, other):
        return self.nid == other.nid


class Master(object):
    def __init__(self, f):
        self.f = f
        self.hash_arr = []

    def log(self, info_hash):
        nhash = info_hash.hex()
        if nhash not in self.hash_arr:
            print("Received torrent hash:", nhash)
            self.hash_arr.append(nhash)
            self.f.write(nhash + '\n')
            self.f.flush()


def entropy(byte_len):
    s = ""
    for i in range(byte_len):
        s += chr(randint(0, 255))
    return s.encode('utf-8')


def random_id():
    hash = sha1()
    hash.update(entropy(20))
    return hash.digest()


def generate_node_id() -> bytes:
    hash = sha1()
    hash.update(DEFAULT_NODE_ID.encode('utf-8'))
    return hash.digest()


def decode_nodes(nodes):
    n = []
    length = len(nodes)

    if (length % 26) != 0:
        return n

    for i in range(0, length, 26):
        nid = nodes[i:i+20]
        ip = inet_ntoa(nodes[i+20:i+24])
        port = unpack('!H', nodes[i+24:i+26])[0]
        n.append((nid, ip, port))

    return n


def encode_nodes(nodes):
    strings = []
    for node in nodes:
        s = "%s%s%s" % (node.nid, node.ip, node.port)
        strings.append(s)

    return "".join(strings)


def intify(hstr):
    if type(hstr) is bytes:
        hstr = hstr.hex()
    return int(hstr, 16)


def timer(t, f):
    Timer(t, f).start()


def cmp(a, b):
    if a < b:
        return -1
    elif a == b:
        return 0
    else:
        return 1


def my_decoder(field_type, value):
    if field_type == 'key':
        return str(value, 'ascii')
    elif field_type == 'value':
        try:
            return str(value, 'utf-8')
        except UnicodeDecodeError:
            return value
    else:
        raise Exception("'field_type' can pass only 'key' and 'value' values")


def main():
    print("Start DHT spider")
    f = open('hash.txt', 'a+')
    m = Master(f)
    s = Server(m, KTable(generate_node_id()), DEFAULT_NODE_PORT)

    try:
        s.start()
    except KeyboardInterrupt:
        s.socket.close()
        f.close()


if __name__ == '__main__':
    main()
