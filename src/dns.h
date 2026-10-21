// dns.h — DNS sinkhole engine. Runs in its own high-priority FreeRTOS task on
// raw lwIP sockets, so the web UI, OTA and blocklist downloads never stall it.
//
// Hot path per query: parse -> ban/blocklist check (PSRAM binary search) ->
// answer cache (PSRAM, TTL-aware) -> else async forward with retry to a second
// upstream. Nothing in the task allocates, takes a long lock, or touches String.
#pragma once
#include <Arduino.h>

void     dnsInit();                          // call first in setup(): allocs, decides PSRAM vs file mode
void     dnsStart(uint16_t port = 53);       // after WiFi is up: opens sockets, starts the task
uint64_t dnsHash(const char* s, size_t n);   // 40-bit FNV-1a, same as tools/build_blocklist.py

// Validates (size, sort order) and swaps the list in atomically; on failure the
// old list keeps serving. In file mode (no PSRAM) the file stays open for lookups.
bool     dnsLoadBlocklist(const char* path);
void     dnsUnloadBlocklist();               // file mode only: close before the file is replaced
uint32_t dnsBlocklistCount();
bool     dnsUsesPsram();

void     dnsSetCustom(const uint64_t* hashes, int n);
void     dnsSetBanned(const uint32_t* ips, int n);
void     dnsSetBlocking(bool on);

struct DnsEvent { uint32_t ip; uint8_t blocked; };
bool     dnsPollEvent(DnsEvent* e);          // drain from loop(): per-client counters

struct DnsStats {
  uint32_t blocked, allowed, cacheHits, upstreamLost, prefetches;
  uint32_t dotQueries, dotHandshakes, dotHsMs;   // queries sent encrypted; TLS link cost
  bool dotUp;
};
DnsStats dnsStats();
