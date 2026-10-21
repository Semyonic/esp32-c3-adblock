#!/usr/bin/env python3
"""Correctness checks for the adblocker's DNS engine (stdlib only).

Compares the device's answers against a reference resolver and exercises the
paths a fast path tends to break: record types it must pass through untouched,
NXDOMAIN, EDNS, replies larger than 512 bytes, 0x20 case echo, TTLs counting
down out of the cache, and parent-domain blocking.

usage: dnscheck.py [device_ip] [reference_ip]
"""
import random, socket, string, struct, sys, time

TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA', 65: 'HTTPS'}
fails = []


def build(name, qtype=1, edns=0, rid=None):
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    ar = 1 if edns else 0
    m = struct.pack('>HHHHHH', rid if rid is not None else random.getrandbits(16),
                    0x0120, 1, 0, 0, ar) + q + struct.pack('>HH', qtype, 1)
    if edns:
        m += b'\0' + struct.pack('>HHIH', 41, edns, 0, 0)
    return m


def ask(server, name, qtype=1, edns=0, timeout=4):
    pkt = build(name, qtype, edns)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        try:
            while True:
                r = s.recv(4096)
                if r[:2] == pkt[:2]:
                    return r, pkt
        except socket.timeout:
            return None, pkt


def skip_name(p, i):
    while i < len(p):
        l = p[i]
        if l == 0:
            return i + 1
        if l & 0xC0:
            return i + 2
        i += 1 + l
    return i


def records(p):
    """[(type, ttl, rdata)] across all sections."""
    qd, an, ns, ar = struct.unpack('>HHHH', p[4:12])
    i = 12
    for _ in range(qd):
        i = skip_name(p, i) + 4
    out = []
    for _ in range(an + ns + ar):
        i = skip_name(p, i)
        if i + 10 > len(p):
            break
        t, _c, ttl, rl = struct.unpack('>HHIH', p[i:i + 10])
        out.append((t, ttl, p[i + 10:i + 10 + rl]))
        i += 10 + rl
    return out


def check(label, ok, detail=''):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{(' — ' + detail) if detail else ''}")
    if not ok:
        fails.append(label)


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.240'
    ref = sys.argv[2] if len(sys.argv) > 2 else '9.9.9.9'

    print('record types pass through unchanged')
    for qt, nm in TYPES.items():
        name = {2: 'google.com', 5: 'www.github.com', 15: 'gmail.com'}.get(qt, 'example.com')
        a, _ = ask(dev, name, qt)
        b, _ = ask(ref, name, qt)
        if a is None or b is None:
            check(f'{nm} {name}', False, 'no reply'); continue
        ra = sorted(r[2] for r in records(a) if r[0] == qt)
        rb = sorted(r[2] for r in records(b) if r[0] == qt)
        same_rcode = (a[3] & 15) == (b[3] & 15)
        # rdata that contains a domain name (NS, CNAME, MX) carries compression
        # pointers whose offsets depend on the packet it arrived in, so comparing
        # those bytes across two responses is meaningless — count them instead.
        same = ra == rb if qt in (1, 16, 28) else len(ra) == len(rb)
        check(f'{nm:5s} {name}', same_rcode and same,
              f'device {len(ra)} rr, reference {len(rb)} rr, rcode {a[3] & 15}/{b[3] & 15}')

    print('error and edge responses')
    # .invalid is guaranteed not to exist (RFC 6761). A random name under a real
    # domain is not: example.com answers NODATA, so asserting rcode 3 there would
    # be testing the zone, not the device.
    nx = 'nx-' + ''.join(random.choices(string.ascii_lowercase, k=10)) + '.invalid'
    a, _ = ask(dev, nx)
    b, _ = ask(ref, nx)
    check('NXDOMAIN returned as NXDOMAIN', a is not None and (a[3] & 15) == 3,
          f'rcode {a[3] & 15 if a else "none"}')
    nd = 'nd-' + ''.join(random.choices(string.ascii_lowercase, k=10)) + '.example.com'
    a, _ = ask(dev, nd)
    b, _ = ask(ref, nd)
    check('nonexistent name matches the reference rcode',
          a is not None and b is not None and (a[3] & 15) == (b[3] & 15),
          f'rcode {a[3] & 15 if a else "none"}/{b[3] & 15 if b else "none"}')
    a, _ = ask(dev, 'example.com', 1, edns=1232)
    check('EDNS0 query answered', a is not None and (a[3] & 15) == 0)
    a, _ = ask(dev, 'dnssec-failed.org', 1)
    check('served-fail domain still answered', a is not None)

    big = ask(dev, 'ns1.google.com', 16, edns=4096)[0]
    ref_big = ask(ref, 'ns1.google.com', 16, edns=4096)[0]
    if big and ref_big:
        check('reply over 512 B relayed whole', len(big) == len(ref_big),
              f'{len(big)} B vs {len(ref_big)} B')

    print('cache behaviour')
    name = 'www.wikipedia.org'
    first, _ = ask(dev, name)
    time.sleep(3)
    second, _ = ask(dev, name)
    if first and second:
        t1 = min((r[1] for r in records(first) if r[0] != 41), default=0)
        t2 = min((r[1] for r in records(second) if r[0] != 41), default=0)
        check('TTL counts down on a cache hit', t2 < t1, f'{t1}s then {t2}s')
    rid = random.getrandbits(16)
    pkt = build('eXaMpLe.CoM', 1, rid=rid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(pkt, (dev, 53))
        try:
            r = s.recv(4096)
            check('question echoed byte for byte (0x20)', r[12:len(pkt)] == pkt[12:],
                  r[13:24].decode('ascii', 'replace'))
            check('transaction id preserved', r[:2] == pkt[:2])
        except socket.timeout:
            check('question echoed byte for byte (0x20)', False, 'no reply')

    print('filtering')
    a, _ = ask(dev, 'googlesyndication.com')
    check('listed domain sinkholed', a is not None and any(r[2] == b'\0\0\0\0' for r in records(a) if r[0] == 1))
    a, _ = ask(dev, 'deep.sub.googlesyndication.com')
    check('subdomain of a listed domain sinkholed',
          a is not None and any(r[2] == b'\0\0\0\0' for r in records(a) if r[0] == 1))
    a, _ = ask(dev, 'googlesyndication.com', 28)
    check('AAAA for a listed domain is NODATA, not 0.0.0.0',
          a is not None and (a[3] & 15) == 0 and struct.unpack('>H', a[6:8])[0] == 0)
    a, _ = ask(dev, 'wikipedia.org')
    check('unlisted domain resolves normally',
          a is not None and any(r[2] != b'\0\0\0\0' for r in records(a) if r[0] == 1))

    print(f"\n{'all checks passed' if not fails else str(len(fails)) + ' FAILED: ' + ', '.join(fails)}")
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
