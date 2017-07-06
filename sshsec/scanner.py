#!/usr/bin/python3

# http://www.openssh.com/specs.html

# SSH Transport Layer Protocol
# http://www.openssh.com/txt/rfc4253.txt

# Diffie-Hellman Group Exchange
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
        while not r.endswith(b'\n'):
            if len(r) > 1024:
                raise ValueError
            s = self.read(1)
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
    ident = s.read_line().decode('ascii').strip()
    if not ident.startswith('SSH-2.0-'):
        raise ValueError('Not an SSH 2.0 server (server said: %r)' % ident)
    result['ident'] = ident
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

    result['host_keys'] = {}
    result['gex'] = {}

    kex = 'diffie-hellman-group-exchange-sha256'
    if kex not in kexinit.kex_algorithms:
        kex = 'diffie-hellman-group-exchange-sha1'
    if kex not in kexinit.kex_algorithms:
        kex = 'diffie-hellman-group14-sha1'
    if kex not in kexinit.kex_algorithms:
        kex = 'diffie-hellman-group1-sha1'
    if kex not in kexinit.kex_algorithms:
        kex = kexinit.kex_algorithms[0]

    # TODO add 768: server should EOF if it's good
    want_gex_size = [768]
    if kex.startswith('diffie-hellman-group-exchange-'):
        want_gex_size += [1024, 2048, 4096, 8192]
    want_keys = list(kexinit.server_host_key_algorithms)

    def query(gex_size, host_key_alg):
        r = {
            'host_keys': {},
            'gex': {},
        }
        ki = copy.deepcopy(kexinit)
        ki.kex_algorithms = [kex]
        ki.server_host_key_algorithms = [host_key_alg]

        s.send(ki.pack())

        if kex.startswith('diffie-hellman-group-exchange-'):
            # GEX
            s.send(ssh.SSHKexDhGexRequest(
                    gex_size, gex_size, gex_size).pack())
            # expecting GEX_GROUP
            # server will EOF if it's too small
            try:
                gex = s.next()
                r['gex']['%d' % gex_size] = gex.to_json()
                s.send(ssh.SSHKexDhGexInit(
                        random.getrandbits(gex.p.bit_length()-1)).pack())

                gex_reply = s.next()
                key = ssh.parse_key_bytes(gex_reply.host_key)
                r['host_keys'][key['algorithm']] = key

            except EOFError:
                r['gex']['%d' % gex_size] = 'EOF'
                return r

        else:
            if kex == 'diffie-hellman-group1-sha1':
                s.send(ssh.SSHKexDhInit(random.getrandbits(1024)).pack())

            elif kex == 'diffie-hellman-group14-sha1':
                s.send(ssh.SSHKexDhInit(random.getrandbits(2048)).pack())

            else:
                raise Exception('unknown kex: %s' % kex)

            msg_type, io = ssh.SSHPacket.load_raw(s)
            if msg_type != ssh.SSHPacket.KEX_DH_REPLY:
                raise ValueError('invalid packet: %d %r'
                        % (msg_type, io.read()))
            reply = ssh.SSHKexDhGexReply()
            for k, v in ssh.SSHKexDhGexReply.properties:
                setattr(reply, k, v.load(io))
            key = ssh.parse_key_bytes(reply.host_key)
            r['host_keys'][key['algorithm']] = key

        packet = s.next()
        if isinstance(packet, ssh.SSHNewKeys):
            pass
        else:
            raise ValueError('invalid packet: %r %r'
                    % (type(packet), packet.to_json()))

        return r

    while want_keys or want_gex_size:
        if want_gex_size:
            gex_size = want_gex_size.pop()

        if want_keys:
            host_key_alg = want_keys.pop()

        try:
            r = query(gex_size, host_key_alg)
            for k, v in r.items():
                result[k].update(v)
        except:
            import traceback
            traceback.print_exc()
            pass

        if want_keys or want_gex_size:
            reopen()

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

