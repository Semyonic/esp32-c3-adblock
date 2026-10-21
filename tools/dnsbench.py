#!/usr/bin/env python3
"""DNS latency benchmark for the adblocker (stdlib only).

Compares the device against a direct upstream on the paths that matter:
  blocked  - a name in the blocklist (answered locally)
  repeat   - the same allowed name over and over (answer-cache hits)
  unique   - fresh random subdomains (always a cache miss -> upstream)
  burst    - N unique queries sent at once (concurrency / head-of-line)

usage: dnsbench.py [device_ip] [upstream_ip] [-n COUNT]
"""
import random, socket, string, struct, sys, time
from concurrent.futures import ThreadPoolExecutor

BLOCKED, REPEAT = "googlesyndication.com", "github.com"


def query(name: str) -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0) + qname + b"\0\1\0\1"


def ask(server: str, name: str, timeout: float = 3.0):
    """Round-trip time in ms, or None if lost/timed out."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        pkt = query(name)
        t0 = time.perf_counter()
        s.sendto(pkt, (server, 53))
        try:
            while True:
                r = s.recv(1500)
                if r[:2] == pkt[:2]:
                    return (time.perf_counter() - t0) * 1000
        except socket.timeout:
            return None


def unique_name() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=12)) + ".example.com"


def report(label: str, rtts):
    ok = sorted(x for x in rtts if x is not None)
    lost = len(rtts) - len(ok)
    if not ok:
        print(f"{label:22s} all {lost} lost"); return
    pct = lambda p: ok[min(len(ok) - 1, int(len(ok) * p))]
    print(f"{label:22s} n={len(ok):3d} lost={lost:2d}  p50={pct(.5):7.1f}  p90={pct(.9):7.1f}  "
          f"p99={pct(.99):7.1f}  max={ok[-1]:7.1f} ms")


def main():
    argv = sys.argv[1:]
    n = 40
    if "-n" in argv:
        i = argv.index("-n"); n = int(argv[i + 1]); del argv[i:i + 2]
    dev = argv[0] if argv else "192.168.1.240"
    up = argv[1] if len(argv) > 1 else "9.9.9.9"

    ask(dev, REPEAT)                                   # warm the repeat name
    report("blocked", [ask(dev, BLOCKED) for _ in range(n)])
    report("repeat (cache hit)", [ask(dev, REPEAT) for _ in range(n)])
    report("unique via device", [ask(dev, unique_name()) for _ in range(n)])
    report(f"unique direct {up}", [ask(up, unique_name()) for _ in range(n)])
    with ThreadPoolExecutor(32) as ex:                 # 32 in flight at once
        report("burst x32 via device", list(ex.map(lambda _: ask(dev, unique_name()), range(32))))


if __name__ == "__main__":
    main()
