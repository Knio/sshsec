#!/usr/bin/python3

# http://www.openssh.com/specs.html
# http://www.openssh.com/txt/rfc4253.txt
# https://www.ietf.org/rfc/rfc4419.txt

import socket
import base64
import copy
import random
from io import BytesIO


from . import ssh

class SSHSocket(object):
    def __init__(self, addr):
        self.socket = None
        self.open(addr)

    def open(self, addr):
        if self.socket:
            self.close()
        self.socket = socket.socket()
        self.socket.settimeout(4)
        self.socket.connect(addr)

    def close(self):
        self.socket.close()
        self.socket = None

    def send(self, data):
        while data:
            data = data[self.socket.send(data):]

    def read(self, n):
        r = []
        i = 0
        while n:
            s = self.socket.recv(n)
            if not s:
                raise EOFError
            n -= len(s)
            r.append(s)
        return b''.join(r)

    def send_line(self, line):
        self.send(line.encode('ascii'))
        self.send(b'\r\n')

    def read_line(self):
        # server will wait at newline
        r = b''
        while b'\r\n' not in r:
            if len(r) > 1024:
                raise ValueError
            s = self.socket.recv(1024)
            if not s:
                raise EOFError
            r += s
        return r

    def next(self):
        return ssh.SSHPacket.load(self)

def scan(addr):
    result = {}

    s = SSHSocket(addr)
    result['ip'] = s.socket.getpeername()[0]
    result['ident'] = s.read_line().decode('ascii').strip()
    s.send_line('SSH-2.0-sshsec.zkpq.ca')

    kexinit = s.next()
    supported = kexinit.to_json()
    supported.pop('first_kex_packet_follows')
    supported.pop('reserved')
    supported.pop('cookie')
    result['supported'] = supported

    def reopen():
        s.open(addr)
        s.read_line()
        s.send_line('SSH-2.0-sshsec.zkpq.ca')
        kexinit = s.next()

    def read_host_key(b):
        return base64.b64encode(b).decode('ascii')

        io = BytesIO(b)
        alg = ssh.SSHPropType.cl_string.load(io).decode('ascii')
        key = {}
        if alg == 'ssh-ed25519':
            key['g'] = ssh.SSHPropType.cl_mpint.load(io)
        elif alg == 'ecdsa-sha2-nistp256':
            key['name'] = ssh.SSHPropType.cl_string.load(io).decode('ascii')
            key['g'] = ssh.SSHPropType.cl_mpint.load(io)
        elif alg == 'ssh-rsa':
            key['e'] = ssh.SSHPropType.cl_mpint.load(io)
            key['g'] = ssh.SSHPropType.cl_mpint.load(io)
        elif alg == 'ssh-dss':
            key['e'] = ssh.SSHPropType.cl_mpint.load(io)
            key['g'] = ssh.SSHPropType.cl_mpint.load(io)
            key['r'] = ssh.SSHPropType.cl_mpint.load(io)
            key['s'] = ssh.SSHPropType.cl_mpint.load(io)
        else:
            raise ValueError(alg)
        r = io.read()
        assert not r, (alg, r)
        return alg, key

    result['host_keys'] = {}
    result['gex'] = {}

    kex = [kex for kex in (
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group-exchange-sha1')
        if kex in kexinit.kex_algorithms][0]

    # TODO add 768: server should EOF if it's good
    want_gex_size = [1024, 2048, 4096, 8192]
    want_keys = list(kexinit.server_host_key_algorithms)


    while want_keys or want_gex_size:
        if want_gex_size:
            gex_size = want_gex_size.pop()

        if want_keys:
            host_key_alg = want_keys.pop()

        ki = copy.deepcopy(kexinit)
        ki.kex_algorithms = [kex]
        ki.server_host_key_algorithms = [host_key_alg]

        s.send(ki.pack())
        s.send(ssh.SSHDhGexRequest(gex_size, gex_size, gex_size).pack())

        gex = s.next()
        result['gex']['%d' % gex_size] = gex.to_json()

        s.send(ssh.SSHDhGexInit(random.getrandbits(gex.p.bit_length()-1))
                .pack())

        rep = s.next()
        result['host_keys'][host_key_alg] = read_host_key(rep.host_key)

        packet = s.next()
        if isinstance(packet, ssh.SSHNewKeys):
            reopen()
            continue

        else:
            raise Exception(packet)

    s.close()
    return result


def test():
    assert SSHPacket.byte(1).dump() == b'\1'
    assert SSHPacket.uint32(1).dump() == b'\0\0\0\1'
    assert SSHPacket.nameslist(['a', 'b']).dump() == b'\0\0\0\3a,b'
    assert SSHPacket.byte16(b'a'*16).dump() == b'a'*16
    assert SSHPacket.mpint(-1).dump() == b'\0\0\0\1\xff'

    assert SSHPacket.byte.parse(BytesIO(b'\1')) == 1
    assert SSHPacket.uint32.parse(BytesIO(b'\0\0\1\1')) == 257
    assert SSHPacket.nameslist.parse(BytesIO(b'\0\0\0\3a,b')) == ['a','b']
    assert SSHPacket.byte16.parse(BytesIO(b'a'*16)).dump() == b'a'*16
    assert SSHPacket.mpint.parse(BytesIO(b'\0\0\0\1\xff')) == -1
    assert SSHPacket.mpint.parse(BytesIO(b'\0\0\0\2\xff\xff')) == -1

    d = SSHPacket([
        SSHPacket.byte(10),
        SSHPacket.uint32(1)
    ]).dump()
    assert len(d) == 16
    assert d[:4+1+5] == \
        b'\0\0\0\x0c' + \
        b'\x06' + \
        b'\x0a\0\0\0\1'

    p = SSHPacket.parse(BytesIO(d))
    assert p == (b'\x0a\0\0\0\1', b'')

    p = SSHPacket.parse(BytesIO(d), [
        SSHPacket.byte,
        SSHPacket.uint32,
    ])
    assert p == ([10, 1], b'')

