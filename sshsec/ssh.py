import struct
import random
import base64
import hashlib
from io import BytesIO


def rand_bytes(n):
    r = bytearray(n)
    for i in range(n):
        r[i] = random.getrandbits(8)
    return bytes(r)


class SSHPropType(object):
    count = 0

    class PropInstance(object):
        def __init__(self, count, cls):
            self.count = count
            self.cls = cls

        def __cmp__(self, that):
            return cmp(self.count, that.count)

    @property
    def uint32(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_uint32)

    @property
    def byte(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_byte)

    @property
    def byte16(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_byte16)

    @property
    def string(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_string)

    @property
    def nameslist(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_nameslist)

    @property
    def mpint(self):
        SSHPropType.count += 1
        return SSHPropType.PropInstance(
            SSHPropType.count, SSHPropType.cl_mpint)

    class primitive(object):
        @classmethod
        def load(cls, io):
            b = io.read(cls.struct.size)
            return cls(cls.struct.unpack(b)[0])

        def pack(self):
            return type(self).struct.pack(self)

    class cl_uint32(int, primitive):
        struct = struct.Struct('>I')

    class cl_byte(int, primitive):
        struct = struct.Struct('>B')

    class cl_byte16(bytes, primitive):
        struct = struct.Struct('>16s')

    class cl_nameslist(list):
        struct = struct.Struct('>L')
        @classmethod
        def load(cls, io):
            length, = cls.struct.unpack(io.read(4))
            return cls(io.read(length).decode('ascii').split(','))

        def pack(self):
            l = (','.join(self)).encode('ascii')
            return self.struct.pack(len(l)) + l

    class cl_mpint(int):
        struct = struct.Struct('>L')
        @classmethod
        def load(cls, io):
            length, = cls.struct.unpack(io.read(4))
            return cls(int.from_bytes(io.read(length), 'big', signed=True))

        def pack(self):
            length = (self.bit_length() + 9) // 8
            return self.struct.pack(length) + self.to_bytes(length, 'big',
                signed=True)

    class cl_string(bytes):
        struct = struct.Struct('>L')
        @classmethod
        def load(cls, io):
            length, = cls.struct.unpack(io.read(4))
            return cls(io.read(length))

        def pack(self):
            return self.struct.pack(len(self)) + self

SSHProp = SSHPropType()


class SSHMeta(type):
    def __init__(cls, name, bases, dict):
        msg_type = dict.pop('msg_type', None)
        if msg_type:
            SSHPacket.MSG_TYPES[msg_type] = cls
        properties = {}
        for k, v in list(dict.items()):
            if isinstance(v, SSHPropType.PropInstance):
                properties[k] = v
                del dict[k]
        properties = sorted(properties.items(), key=lambda x:x[1].count)
        super(SSHMeta, cls).__init__(name, bases, dict)
        cls.properties = [(k, v.cls) for k,v in properties]


class SSHPacket(metaclass=SSHMeta):
    MSG_TYPES = {}
    HEADER = struct.Struct('>LB')

    def __init__(self, *data):
        for (k, v), x in zip(self.properties, data):
            setattr(self, k, v(x))

    @staticmethod
    def load_raw(io, mac_length=0):
        H = SSHPacket.HEADER
        packet_length, padding_length = H.unpack(io.read(H.size))
        data    = io.read(packet_length - padding_length - 1)
        padding = io.read(padding_length)
        mac     = io.read(mac_length)

        io = BytesIO(data)
        msg_type = SSHProp.cl_byte.load(io)
        return msg_type, io

    @staticmethod
    def load(io, mac_length=0):
        msg_type, io = SSHPacket.load_raw(io, mac_length=mac_length)
        obj = SSHPacket.MSG_TYPES[msg_type]()
        for k, v in obj.properties:
            setattr(obj, k, v.load(io))
        if io.read():
            raise ValueError('packet was not fully read')
        return obj

    def pack(self, mac=b''):
        data = [SSHPropType.cl_byte(self.msg_type).pack()]
        data += [v(getattr(self, k)).pack() for k,v in self.properties]
        data = b''.join(data)
        H = SSHPacket.HEADER
        # total message must be multiple of 8 bytes
        total_length = H.size + len(data) + len(mac)
        padding_length = 4 + 8 - ((total_length + 4) % 8)
        padding = rand_bytes(padding_length)
        packet_length = 1 + len(data) + padding_length
        header = H.pack(packet_length, padding_length)
        return b''.join([header, data, padding, mac])

    def to_json(self):
        r = {}
        for k, v in self.properties:
            r[k] = getattr(self, k)
        return r

    DISCONNECT                  = 1
    IGNORE                      = 2
    UNIMPLEMENTED               = 3
    DEBUG                       = 4
    SERVICE_REQUEST             = 5
    SERVICE_ACCEPT              = 6
    KEXINIT                     = 20
    NEWKEYS                     = 21
    USERAUTH_REQUEST            = 50
    USERAUTH_FAILURE            = 51
    USERAUTH_SUCCESS            = 52
    USERAUTH_BANNER             = 53
    GLOBAL_REQUEST              = 80
    REQUEST_SUCCESS             = 81
    REQUEST_FAILURE             = 82
    CHANNEL_OPEN                = 90
    CHANNEL_OPEN_CONFIRMATION   = 91
    CHANNEL_OPEN_FAILURE        = 92
    CHANNEL_WINDOW_ADJUST       = 93
    CHANNEL_DATA                = 94
    CHANNEL_EXTENDED_DATA       = 95
    CHANNEL_EOF                 = 96
    CHANNEL_CLOSE               = 97
    CHANNEL_REQUEST             = 98
    CHANNEL_SUCCESS             = 99
    CHANNEL_FAILURE             = 100

    KEX_DH_INIT = 30
    KEX_DH_REPLY = 31

    KEX_DH_GEX_REQUEST     = 34
    KEX_DH_GEX_GROUP       = 31
    KEX_DH_GEX_INIT        = 32
    KEX_DH_GEX_REPLY       = 33


class SSHDisconnect(SSHPacket):
    msg_type = SSHPacket.DISCONNECT
    reason_code     = SSHProp.uint32
    description     = SSHProp.string
    language        = SSHProp.string

class SSHKexInit(SSHPacket):
    msg_type = SSHPacket.KEXINIT
    cookie                                  = SSHProp.byte16
    kex_algorithms                          = SSHProp.nameslist
    server_host_key_algorithms              = SSHProp.nameslist
    encryption_algorithms_client_to_server  = SSHProp.nameslist
    encryption_algorithms_server_to_client  = SSHProp.nameslist
    mac_algorithms_client_to_server         = SSHProp.nameslist
    mac_algorithms_server_to_client         = SSHProp.nameslist
    compression_algorithms_client_to_server = SSHProp.nameslist
    compression_algorithms_server_to_client = SSHProp.nameslist
    languages_client_to_server              = SSHProp.nameslist
    languages_server_to_client              = SSHProp.nameslist
    first_kex_packet_follows                = SSHProp.byte
    reserved                                = SSHProp.uint32

class SSHKexDhInit(SSHPacket):
    msg_type =  SSHPacket.KEX_DH_INIT
    e = SSHProp.mpint

class SSHKexDhGexRequest(SSHPacket):
    msg_type = SSHPacket.KEX_DH_GEX_REQUEST
    min = SSHProp.uint32
    n   = SSHProp.uint32
    max = SSHProp.uint32

class SSHKexDhGexGroup(SSHPacket):
    msg_type = SSHPacket.KEX_DH_GEX_GROUP
    p = SSHProp.mpint
    g = SSHProp.mpint

# same as non-GEX packet
class SSHKexDhGexInit(SSHPacket):
    msg_type = SSHPacket.KEX_DH_GEX_INIT
    e = SSHProp.mpint

class SSHKexDhGexReply(SSHPacket):
    msg_type = SSHPacket.KEX_DH_GEX_REPLY
    host_key    = SSHProp.string
    f           = SSHProp.mpint
    H           = SSHProp.string

class SSHNewKeys(SSHPacket):
    msg_type = SSHPacket.NEWKEYS


def parse_key_ascii(s):
    b = base64.b64decode(s)
    return parse_key_bytes(b)

def parse_key_bytes(b):
    io = BytesIO(b)

    txt = base64.b64encode(b).decode('ascii')
    alg = SSHPropType.cl_string.load(io).decode('ascii')

    key = {
        'algorithm': alg,
        'ascii': txt,
        'fingerprint': (('%c%c:' * 16) % tuple(
            hashlib.md5(b).hexdigest()))[:-1],
    }

    if alg == 'ssh-ed25519':
        key['n'] = SSHPropType.cl_mpint.load(io)
    elif alg == 'ecdsa-sha2-nistp521':
        key['name'] = SSHPropType.cl_string.load(io).decode('ascii')
        key['n'] = SSHPropType.cl_mpint.load(io)
    elif alg == 'ecdsa-sha2-nistp256':
        key['name'] = SSHPropType.cl_string.load(io).decode('ascii')
        key['n'] = SSHPropType.cl_mpint.load(io)
    elif alg == 'ssh-rsa':
        key['e'] = SSHPropType.cl_mpint.load(io)
        key['n'] = SSHPropType.cl_mpint.load(io)
    elif alg == 'ssh-dss':
        key['p'] = SSHPropType.cl_mpint.load(io)
        key['q'] = SSHPropType.cl_mpint.load(io)
        key['g'] = SSHPropType.cl_mpint.load(io)
        key['y'] = SSHPropType.cl_mpint.load(io)
    else:
        raise ValueError(alg)
    s = io.read()
    if s:
        raise ValueError('extra data: %r' % s)
    return key


def test():
    assert SSHPropType.cl_byte(10) == 10
    assert SSHPropType.cl_byte.load(BytesIO(b'\x0a')) == 10
    assert SSHPropType.cl_byte(10).pack() == b'\x0a'

def test2():
    p = SSHKexDhGexReply(b'foo', 1234, b'bar')
    assert p.host_key == b'foo'
    assert type(p.host_key) == SSHPropType.cl_string
    assert len(p.pack()) == 32
    assert p.pack()[:26] == (
        # length
        b'\x00\x00\x00\x1c'
        # padding
        b'\x06'
        # data
            # type
            b'\x21'
            # string
            b'\x00\x00\x00\x03'
                b'foo'
            # mpint
            b'\x00\x00\x00\x02'
                b'\x04\xd2'
            # string
            b'\x00\x00\x00\x03'
                b'bar'
    )
    q = SSHKexDhGexReply.load(BytesIO(p.pack()))
    assert q.host_key == b'foo'
    assert q.f == 1234
    assert q.H == b'bar'

    p = SSHDhGexRequest(1024, 2048, 8192)
    print(p.properties)
    print(p.pack())
    assert len(p.pack()) == 24
    assert p.min == 1024
    assert p.n == 2048
    assert p.max == 8192
