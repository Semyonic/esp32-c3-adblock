# Verification record

What was actually run against hardware, and what it produced. Reproduce any line
with `tools/dnscheck.py` (correctness) or `tools/dnsbench.py` (latency, soak).

Device: ESP32-S3R8 (Waveshare 1.47 class), 16 MB flash, 8 MB octal PSRAM,
206,567-domain blocklist built on-device from `hagezi/adblock/pro.txt`, DoT to
dns.quad9.net. Reference resolver for every comparison: 9.9.9.9 direct.

## Correctness — 20/20

`tools/dnscheck.py`, passing on both the PSRAM build and the no-PSRAM build:

- A, NS, CNAME, MX, TXT, AAAA and HTTPS answers match the reference
- NXDOMAIN stays NXDOMAIN; a nonexistent name under a wildcard zone matches the
  reference's NODATA instead
- EDNS0 queries answered; a 1.2 kB reply relayed whole and untruncated
- The question is echoed byte for byte (0x20 encoding) and the transaction id kept
- TTLs count down on a cache hit
- A listed domain and its subdomains are sinkholed; AAAA for them is NODATA, not
  0.0.0.0; unlisted domains resolve normally
- Survives 16 crafted malformed packets (empty, lying qdcount, label past the end,
  label length 64, no terminator, compression pointer in the question, pointer
  loop, name over 255 bytes, EDNS claiming 4000 bytes, response bit on a query,
  random payloads) plus 300 random packets, and still answers and still filters

## Latency

| | this device | 9.9.9.9 direct |
|---|---|---|
| Blocked name | 7.3 ms | — |
| Repeat name (answer cache) | 6.5 ms | 64 ms |
| New name (cache miss, over TLS) | 71.6 ms | 63.8 ms |
| 32 queries at once | 0 lost | 0 lost |

## Loss, measured against the device's own counters

Counters are cumulative from boot, so the clearest reading is one device lifetime.
From a fresh boot, then 180 s of mixed load:

| | at boot (20 queries) | after 22,880 more |
|---|---|---|
| Replies lwIP refused to send | 1 | **1** — did not recur |
| Queries lwIP refused to send | 0 | **0** |
| Internal loss (shed or timed out) | 0 | **0** |
| Replies with no hand-off slot | 0 | **0** |
| Client-visible loss | — | **0** |

The counter is split by direction because the two cases differ: a refused query
is resent 350 ms later, a refused reply is not.

About that single refused reply: it was seen twice, both times early in the
session on builds that predate the queue-fallback and lookup-memo fixes, and
once it had appeared it stayed at exactly 1 across the following 22,880 queries
— never a load effect. On the shipping build it has not recurred. Three fresh
boots, each loaded from the instant the device first answered, served 3,320,
2,080 and 2,080 queries with every counter at zero and nothing in the log.

So the cause is not established, and this file does not guess at one. An earlier
draft blamed ARP resolution; that was withdrawn after testing failed to support
it (and the reasoning was weak to begin with — the device learns a client's MAC
from the very packet it is replying to). `sendRaw()` now prints the lwIP error
code and whether the buffer allocation failed, so a recurrence will report what
it is. No client ever saw a loss from it in any run.

Earlier in the same session a 180 s window at 85 q/s showed the device counting
all 15,360 queries this machine sent, with internal loss, send failures and
dropped replies all at 0; the 2 the client missed were replies lost on the WiFi
return path. Five idle minutes of household traffic (172 queries): 0 lost.
Longer runs: 30,720 queries over 4 min, 38,440 over 5 min, 45,600 over 5 min —
internal loss 0 in every one.

Where a nonzero internal count does appear over a long mixed lifetime (10 in
38,814), it tracks queries from the other hosts on the LAN whose upstream never
answered inside 1.5 s; the reference resolver drops a comparable share when
queried directly.

## Capacity — the ceiling is the radio

Self-paced load, N queries in flight:

| in flight | achieved | client loss | device received | firmware internal loss |
|---|---|---|---|---|
| 8 | 69 q/s | 0 | 3,228 | 0 |
| 16 | 102 q/s | 0 | 4,661 | 0 |
| 32 | 116 q/s | 1 | 5,313 | 0 |
| 64 | 87 q/s | 304 | 3,872 | 0 |

At 64 in flight the firmware still loses nothing: it only ever received 3,872 of
the 4,160 sent, so the rest died in the WiFi receive path, whose buffer counts
live in the prebuilt IDF libraries. A household asks a few names a second.

**Load-testing note.** Drive load from a bounded pool that waits for each answer.
A thread per query arrives in clumps and hits that ceiling — one sweep reported
10,049 "losses" at 140 q/s. Blaming the test machine was wrong: the same harness
delivered 8,400 queries to a public resolver losslessly. Compare client-sent
against the device's received count before concluding anything.

## DoT link

Close-reason logging says who hung up. Over a 10-minute run at ~140 q/s, all 24
closes were the resolver's and none were initiated here. Against query rate,
2 minutes each: 5 q/s → 0 closes, 20 → 2, 60 → 4, 90 → 7, none of them losing a
query. Reconnecting costs ~1.6 s (software ECDSA P-384) and queries take the
plaintext path meanwhile.

Encryption was checked by counting: 25 of 25 and 20 of 20 cache misses left the
box inside TLS, with no plaintext fallback while the link was up.

## Targets

| env | chip | builds | RAM | hardware run |
|---|---|---|---|---|
| s3 | ESP32-S3 | yes | 39.3% | yes — everything above |
| c3 | ESP32-C3 | yes | 27.0% | code path only, see below |
| esp32dev | ESP32 | yes | 30.3% | code path only, see below |

The C3 and classic ESP32 boards were not available. What was done instead: the
S3 was flashed with `BOARD_HAS_PSRAM` undefined and the single-core branch
selected, which is the code those targets run — file-mode blocklist from flash,
smaller tables, unpinned DoT task. That build passed 20/20 correctness, lost
nothing in a 32-query burst, and soaked 18,600 queries with the firmware's
internal loss counter at 0.

Exercising that path is what found the one defect those boards would have hit:
the DoT task was pinned to core 1, which does not exist on a single-core chip,
and FreeRTOS asserts on it (the assertion text is in the shipped `libfreertos.a`
and assertions are compiled in), so a C3 would have boot-looped. Task placement
now keys off `configNUMBER_OF_CORES`, falls to the call that is valid everywhere
if that macro is ever invisible, and is checked per target by `static_assert` —
so a regression breaks the build in CI rather than the board.

To finish the job on real silicon:

```bash
pio run -e c3 -t upload            # or -e esp32dev
python3 tools/dnscheck.py <device-ip>
python3 tools/dnsbench.py <device-ip> --soak 300
```
