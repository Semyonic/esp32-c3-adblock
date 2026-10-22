// dns.h — DNS sinkhole engine. Runs in its own high-priority FreeRTOS task on
// raw lwIP sockets, so the web UI, OTA and blocklist downloads never stall it.
//
// Hot path per query: parse -> ban/blocklist check (PSRAM binary search) ->
// answer cache (PSRAM, TTL-aware) -> else async forward with retry to a second
// upstream. Nothing in the task allocates, takes a long lock, or touches String.
#pragma once
#include <Arduino.h>

// Upstream resolver, shared with the device's own hostname lookups (see WiFi.config
// in main.cpp). dns.cpp forwards here when DoT is unavailable; dot.cpp holds the
// encrypted link to the same operator.
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9: malware filtering, no logging
#endif
#ifndef UPSTREAM2_IP
#define UPSTREAM2_IP 149, 112, 112, 112           // Quad9 secondary
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif

void     dnsInit();                          // call first in setup(): allocs, decides PSRAM vs file mode
void     dnsStart(uint16_t port = 53);       // after WiFi is up: opens sockets, starts the task
uint64_t dnsHash(const char* s, size_t n);   // 40-bit FNV-1a, same as tools/build_blocklist.py

// Validates (size, sort order) and swaps the list in atomically; on failure the
// old list keeps serving. In file mode (no PSRAM) the file stays open for lookups.
bool     dnsLoadBlocklist(const char* path);
void     dnsUnloadBlocklist();               // file mode only: close before the file is replaced
uint32_t dnsBlocklistCount();
bool     dnsUsesPsram();

// Build a list straight from upstream TEXT sources (hosts / AdGuard syntax),
// hashing and sorting in PSRAM as the bytes stream in — no prebuilt .bin to host,
// no multi-MB temp file on flash. PSRAM only; returns false on a board without it.
bool     dnsTextBegin();
void     dnsTextFeed(const uint8_t* data, int n);
bool     dnsTextCommit();                    // sorts, dedupes, publishes; false = nothing usable
bool     dnsSaveBlocklist(const char* path); // persist the live list so a reboot keeps it
void     dnsTextAbort();
uint32_t dnsTextCount();                     // domains accepted so far

void     dnsSetCustom(const uint64_t* hashes, int n);
void     dnsSetBanned(const uint32_t* ips, int n);
void     dnsSetBlocking(bool on);

// The last few names that were sinkholed, so the dashboard can show what is
// being blocked and not just how much. A fixed ring written in the DNS path:
// no allocation, one memcpy per blocked query.
struct DnsHit { char name[48]; uint32_t ip; uint32_t age; };   // age = seconds ago
int  dnsRecent(DnsHit* out, int max);                          // newest first, returns count
uint32_t dnsHitSeq();                                          // total ever recorded, only grows

struct DnsEvent { uint32_t ip; uint8_t blocked; };
bool     dnsPollEvent(DnsEvent* e);          // drain from loop(): per-client counters

struct DnsStats {
  uint32_t blocked, allowed, cacheHits, upstreamLost, prefetches;
  // upstreamLost is the sum of these two, which mean different things: a query
  // the resolver never answered (it may have been nonsense in the first place),
  // and one this device turned away because its own table was full.
  uint32_t lostTimeout, lostShed;
  uint32_t dotQueries, dotHandshakes, dotHsMs;   // queries sent encrypted; TLS link cost
  uint32_t dotDropped;                           // replies that found no free hand-off slot
  uint32_t txFailedReply, txFailedQuery;         // packets lwIP would not send, by direction
  int32_t  txErrReply, txErrQuery;               // why: 1 = no buffer, else lwIP err_t
  bool dotUp;
};
DnsStats dnsStats();
