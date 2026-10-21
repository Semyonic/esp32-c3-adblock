// dns.cpp — see dns.h. Everything below the "lwIP thread" marker runs only inside
// lwIP's tcpip thread (raw UDP callbacks + lwIP timers); the setters above it are
// the only cross-thread entry points.
//
// Why raw UDP and not sockets: a socket queues each datagram in a 6-slot recvmbox
// (CONFIG_LWIP_UDP_RECVMBOX_SIZE, fixed in the prebuilt libs) until a task wakes,
// and a 32-query burst lost 14-28 packets there. The raw callback handles each
// datagram the moment lwIP parses it — no queue, no task switch, no extra copy.
#include "dns.h"
#include "dot.h"
#include <LittleFS.h>
#include "lwip/udp.h"
#include "lwip/tcpip.h"
#include "lwip/timeouts.h"
#include <esp_timer.h>
#include <esp_random.h>
#include <esp_heap_caps.h>
#include <algorithm>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const uint32_t RETRY_MS = 350;             // > upstream p99 (~160 ms) -> resend to the other one
static const uint32_t GIVEUP_MS = 1500;           // stubs retry by ~1-2 s; frees the port for queued misses

static inline uint32_t nowMs() { return (uint32_t)(esp_timer_get_time() / 1000); }
static inline uint32_t nowS()  { return (uint32_t)(esp_timer_get_time() / 1000000); }

uint64_t dnsHash(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpack5(const uint8_t* b) {
  return (uint64_t)b[0] | (uint64_t)b[1] << 8 | (uint64_t)b[2] << 16 | (uint64_t)b[3] << 24 | (uint64_t)b[4] << 32;
}

// ---------- blocklist ----------
// PSRAM mode: the whole sorted hash array lives in PSRAM; a swap publishes a new
// object through one pointer store, so lookups never lock.
// File mode (C3 / classic ESP32, no PSRAM): the original LittleFS file + 4096-entry
// RAM index, guarded by a mutex because the file handle is shared with the loader.
struct Blocklist { uint8_t* data; uint32_t n; };
static Blocklist* volatile blMem = nullptr;
static Blocklist* retired = nullptr;           // see publish()
static bool usePsram = false;

// Swap in a new list with a single pointer store, so a lookup in the lwIP thread
// either sees the old list or the new one, never a half-built state. The displaced
// list is freed at the *next* swap rather than after a delay: a lookup that was
// already walking it finishes in microseconds, and swaps are minutes apart, so
// this needs no timing assumption to be safe.
static void publish(Blocklist* nb) {
  Blocklist* old = blMem;
  blMem = nb;
  if (retired) { heap_caps_free(retired->data); delete retired; }
  retired = old;
}

static const int IDX = 4096, MAX_RANGE = 256;
static File blFile;
static uint32_t blFileN = 0;
static uint8_t (*blIdx)[HASH_BYTES] = nullptr;
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];
static SemaphoreHandle_t blFileMux;

static bool memContains(const Blocklist* b, uint64_t h) {
  uint32_t lo = 0, hi = b->n;
  while (lo < hi) {
    uint32_t mid = (lo + hi) >> 1;
    uint64_t v = unpack5(b->data + (size_t)mid * HASH_BYTES);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid; else return true;
  }
  return false;
}

static bool fileContains(uint64_t h) {
  bool hit = false;
  xSemaphoreTake(blFileMux, portMAX_DELAY);
  uint32_t n = blFileN;
  if (n && blIdx && h >= unpack5(blIdx[0]) && h <= unpack5(blIdx[IDX - 1])) {
    int lo = 0, hi = IDX - 2, seg = 0;
    while (lo <= hi && !hit) {
      int mid = (lo + hi) >> 1; uint64_t v = unpack5(blIdx[mid]);
      if (v < h) { seg = mid; lo = mid + 1; } else if (v > h) hi = mid - 1; else hit = true;
    }
    if (!hit) {
      uint32_t s = (uint64_t)seg * (n - 1) / (IDX - 1), e = (uint64_t)(seg + 1) * (n - 1) / (IDX - 1);
      uint32_t cnt = e - s + 1; if (cnt > (uint32_t)MAX_RANGE) cnt = MAX_RANGE;
      blFile.seek(s * HASH_BYTES);
      cnt = blFile.read(rangeBuf, cnt * HASH_BYTES) / HASH_BYTES;
      for (uint32_t i = 0; i < cnt; i++) { uint64_t v = unpack5(rangeBuf + i * HASH_BYTES); if (v >= h) { hit = v == h; break; } }
    }
  }
  xSemaphoreGive(blFileMux);
  return hit;
}

static inline bool blContains(uint64_t h) {
  if (!usePsram) return fileContains(h);
  const Blocklist* b = blMem;
  return b && memContains(b, h);
}

static bool sortedRun(const uint8_t* p, uint32_t n, uint64_t* prev) {
  for (uint32_t i = 0; i < n; i++) { uint64_t v = unpack5(p + i * HASH_BYTES); if (v < *prev) return false; *prev = v; }
  return true;
}

bool dnsLoadBlocklist(const char* path) {
  File f = LittleFS.open(path, "r"); if (!f) return false;
  size_t sz = f.size();
  if (sz == 0 || sz % HASH_BYTES) { f.close(); return false; }
  uint32_t n = sz / HASH_BYTES;
  uint64_t prev = 0;
  if (usePsram) {
    uint8_t* d = (uint8_t*)heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);
    if (!d) { f.close(); return false; }
    size_t got = 0;
    while (got < sz) { int r = f.read(d + got, sz - got > 8192 ? 8192 : sz - got); if (r <= 0) break; got += r; }
    f.close();
    // A text list (or truncated download) is rejected here instead of going live.
    if (got != sz || !sortedRun(d, n, &prev)) { heap_caps_free(d); return false; }
    publish(new Blocklist{d, n});
    return true;
  }
  uint8_t chunk[256 * HASH_BYTES];
  for (uint32_t done = 0; done < n; ) {
    uint32_t k = n - done > 256 ? 256 : n - done;
    if (f.read(chunk, k * HASH_BYTES) != (int)(k * HASH_BYTES) || !sortedRun(chunk, k, &prev)) { f.close(); return false; }
    done += k;
  }
  xSemaphoreTake(blFileMux, portMAX_DELAY);
  if (blFile) blFile.close();
  blFile = f; blFileN = n;
  if (!blIdx) blIdx = (uint8_t(*)[HASH_BYTES])malloc(IDX * HASH_BYTES);
  for (int i = 0; blIdx && i < IDX; i++) {
    blFile.seek((uint32_t)((uint64_t)i * (n - 1) / (IDX - 1)) * HASH_BYTES);
    blFile.read(blIdx[i], HASH_BYTES);
  }
  xSemaphoreGive(blFileMux);
  return true;
}

// ---------- build from text sources (PSRAM) ----------
// One allocation sized from free PSRAM, filled with 64-bit hashes as lines arrive,
// then sorted, deduped and packed to 5 bytes *in place* (5n < 8n, so the write
// pointer never catches the read pointer) before being published.
static uint64_t* bld = nullptr;
static uint32_t bldN = 0, bldCap = 0;
static char bldLine[300];
static int bldLen = 0;
static bool bldOver = false;

bool dnsTextBegin() {
  if (!usePsram) return false;
  dnsTextAbort();
  // Size from the largest free block, not total free: the live list and the answer
  // cache fragment PSRAM, so "5 MB free" can still refuse a 4.7 MB allocation.
  size_t big = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
  uint32_t cap = big > 768 * 1024 ? (big - 256 * 1024) / sizeof(uint64_t) : 0;
  if (cap > 900000) cap = 900000;              // 900k domains is far past any public list
  if (cap < 20000) return false;
  bld = (uint64_t*)heap_caps_malloc((size_t)cap * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
  while (!bld && cap > 20000) {                // lost a race for the block: ask for less
    cap /= 2;
    bld = (uint64_t*)heap_caps_malloc((size_t)cap * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
  }
  if (!bld) return false;
  bldCap = cap; bldN = 0; bldLen = 0; bldOver = false;
  return true;
}
void dnsTextAbort() {
  if (bld) heap_caps_free(bld);
  bld = nullptr; bldN = bldCap = 0; bldLen = 0;
}
uint32_t dnsTextCount() { return bldN; }

// hosts ("0.0.0.0 ads.example"), AdGuard ("||ads.example^"), or a bare domain.
// Allow rules (@@), regex (/.../) and anything with a wildcard or odd character
// are skipped — the engine matches a domain and its parents, nothing else.
static void bldLineDone() {
  char* s = bldLine; s[bldLen] = 0;
  while (*s == ' ' || *s == '\t') s++;
  if (!*s || *s == '#' || *s == '!' || *s == '[' || *s == '/') return;
  if (s[0] == '@' && s[1] == '@') return;
  if (s[0] == '|' && s[1] == '|') s += 2;
  else {
    char* sp = strpbrk(s, " \t");              // hosts format: strip the IP column
    if (sp) {
      bool ip = strncmp(s, "0.0.0.0", 7) == 0 || strncmp(s, "127.0.0.1", 9) == 0 ||
                strncmp(s, "::", 2) == 0 || strncmp(s, "::1", 3) == 0;
      if (!ip) return;
      s = sp; while (*s == ' ' || *s == '\t') s++;
    }
  }
  char* e = s;                                  // cut at the first terminator
  while (*e && *e != '^' && *e != '$' && *e != ' ' && *e != '\t' && *e != '#') e++;
  *e = 0;
  if (e > s && e[-1] == '.') *--e = 0;
  size_t n = e - s;
  if (n < 4 || n > 253) return;
  bool dot = false;
  for (char* p = s; *p; p++) {
    char c = *p | 0x20;                         // lowercase in place
    if (c >= 'a' && c <= 'z') { *p = c; continue; }
    if ((*p >= '0' && *p <= '9') || *p == '-' || *p == '_') continue;
    if (*p == '.') { dot = true; continue; }
    return;                                     // wildcard, slash, colon...
  }
  if (!dot || strcmp(s, "localhost") == 0) return;
  if (n > 4 && memcmp(s, "www.", 4) == 0) { s += 4; n -= 4; }
  if (bldN < bldCap) bld[bldN++] = dnsHash(s, n);
  else bldOver = true;
}

void dnsTextFeed(const uint8_t* data, int n) {
  if (!bld) return;
  for (int i = 0; i < n; i++) {
    char c = (char)data[i];
    if (c == '\n' || c == '\r') { if (bldLen) bldLineDone(); bldLen = 0; }
    else if (bldLen < (int)sizeof(bldLine) - 1) bldLine[bldLen++] = c;
    else bldLen = sizeof(bldLine);              // overlong line: drop the rest of it
  }
}

bool dnsTextCommit() {
  if (!bld) return false;
  if (bldLen && bldLen < (int)sizeof(bldLine)) bldLineDone();
  if (bldN < 1000) { dnsTextAbort(); return false; }     // clearly not a blocklist
  std::sort(bld, bld + bldN);
  uint8_t* out = (uint8_t*)bld;                 // pack in place: 5 bytes per entry
  uint32_t kept = 0; uint64_t prev = UINT64_MAX;
  for (uint32_t i = 0; i < bldN; i++) {
    uint64_t v = bld[i];
    if (v == prev) continue;
    prev = v;
    for (int k = 0; k < HASH_BYTES; k++) out[kept * HASH_BYTES + k] = (uint8_t)(v >> (8 * k));
    kept++;
  }
  uint8_t* shrunk = (uint8_t*)heap_caps_realloc(bld, (size_t)kept * HASH_BYTES, MALLOC_CAP_SPIRAM);
  if (shrunk) out = shrunk;                     // shrink is best-effort
  publish(new Blocklist{out, kept});
  bld = nullptr; bldN = bldCap = 0; bldLen = 0;
  if (bldOver) Serial.println("[list] capacity reached: list truncated");
  return true;
}

// Write the live PSRAM list to flash via a temp file, so a crash mid-write leaves
// the previous list intact. Called after a text rebuild; ~1 MB, a second or two.
bool dnsSaveBlocklist(const char* path) {
  const Blocklist* b = blMem;
  if (!usePsram || !b || !b->n) return false;
  const char* tmp = "/blocklist.tmp";
  File f = LittleFS.open(tmp, "w");
  if (!f) return false;
  size_t total = (size_t)b->n * HASH_BYTES, done = 0;
  while (done < total) {
    size_t chunk = total - done > 4096 ? 4096 : total - done;
    if (f.write(b->data + done, chunk) != chunk) { f.close(); LittleFS.remove(tmp); return false; }
    done += chunk;
    vTaskDelay(1);                               // flash writes stall the CPU; yield between them
  }
  f.close();
  LittleFS.remove(path);
  return LittleFS.rename(tmp, path);
}

void dnsUnloadBlocklist() {
  if (usePsram) return;
  xSemaphoreTake(blFileMux, portMAX_DELAY);
  if (blFile) blFile.close();
  blFileN = 0;
  xSemaphoreGive(blFileMux);
}

uint32_t dnsBlocklistCount() {
  if (!usePsram) return blFileN;
  const Blocklist* b = blMem; return b ? b->n : 0;
}
bool dnsUsesPsram() { return usePsram; }

// ---------- custom domains, bans, pause (set from loop, read by the task) ----------
static portMUX_TYPE listMux = portMUX_INITIALIZER_UNLOCKED;
static const int MAX_CUSTOM = 200, MAX_BAN = 32;
static uint64_t customH[MAX_CUSTOM]; static int nCustom = 0;
static uint32_t bannedIp[MAX_BAN];   static int nBanned = 0;
static volatile bool blocking = true;

void dnsSetCustom(const uint64_t* h, int n) {
  if (n > MAX_CUSTOM) n = MAX_CUSTOM;
  portENTER_CRITICAL(&listMux); memcpy(customH, h, n * sizeof(uint64_t)); nCustom = n; portEXIT_CRITICAL(&listMux);
}
void dnsSetBanned(const uint32_t* ip, int n) {
  if (n > MAX_BAN) n = MAX_BAN;
  portENTER_CRITICAL(&listMux); memcpy(bannedIp, ip, n * sizeof(uint32_t)); nBanned = n; portEXIT_CRITICAL(&listMux);
}
void dnsSetBlocking(bool on) { blocking = on; }

static bool isCustom(uint64_t h) {
  bool hit = false;
  portENTER_CRITICAL(&listMux);
  for (int i = 0; i < nCustom && !hit; i++) hit = customH[i] == h;
  portEXIT_CRITICAL(&listMux);
  return hit;
}
static bool isBanned(uint32_t ip) {
  bool hit = false;
  portENTER_CRITICAL(&listMux);
  for (int i = 0; i < nBanned && !hit; i++) hit = bannedIp[i] == ip;
  portEXIT_CRITICAL(&listMux);
  return hit;
}

// ---------- stats ----------
static volatile uint32_t stBlocked = 0, stAllowed = 0, stHits = 0, stLost = 0, stPrefetch = 0, stDot = 0;
static QueueHandle_t evq;
bool dnsPollEvent(DnsEvent* e) { return evq && xQueueReceive(evq, e, 0) == pdTRUE; }
DnsStats dnsStats() {
  DotStats d = dotStats();
  return { stBlocked, stAllowed, stHits, stLost, stPrefetch, stDot, d.handshakes, d.hsMs, d.up };
}

// ---------- answer cache ----------
// 4-way set-associative, keyed by (name, qtype, qclass, EDNS). Stored replies keep
// their original TTLs; a hit rewrites them down by the entry's age. Entries close
// to expiry are refreshed in the background so hot names never miss.
static const int WAYS = 4;
struct CacheEnt {
  uint64_t key;              // 0 = empty
  uint32_t stored, ttl;      // seconds
  uint16_t len; uint8_t prefetching, pad;
  uint8_t data[492];         // 512-byte slot; bigger replies just aren't cached
};
static CacheEnt* cache = nullptr;
static uint32_t cacheSets = 0;

void dnsInit() {
  usePsram = psramFound();
  blFileMux = xSemaphoreCreateMutex();
  evq = xQueueCreate(256, sizeof(DnsEvent));
  uint32_t entries = usePsram ? 4096 : 32;   // 2 MB in PSRAM; 16 KB on the C3
  cache = (CacheEnt*)heap_caps_calloc(entries, sizeof(CacheEnt), usePsram ? MALLOC_CAP_SPIRAM : MALLOC_CAP_8BIT);
  cacheSets = cache ? entries / WAYS : 0;
}

// ======================= lwIP thread =======================
static udp_pcb* srvPcb = nullptr;
static ip_addr_t upAddr[2];
static bool timerArmed = false;
static uint8_t rx[1536], ux[1536], tx[1536];

static void sendRaw(udp_pcb* pcb, const uint8_t* d, int len, const ip_addr_t* to, uint16_t port) {
  pbuf* pb = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM); if (!pb) return;
  memcpy(pb->payload, d, len);
  udp_sendto(pcb, pb, to, port);
  pbuf_free(pb);
}

static uint64_t cacheKey(const char* name, int n, uint16_t qtype, uint16_t qclass, bool edns) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (int i = 0; i < n; i++) { h ^= (uint8_t)name[i]; h *= 0x100000001b3ULL; }
  h ^= ((uint64_t)qtype << 32) ^ ((uint64_t)qclass << 48) ^ (edns ? 0x9E3779B97F4A7C15ULL : 0);
  return h ? h : 1;
}

static int skipName(const uint8_t* p, int len, int i) {
  while (i < len) {
    uint8_t l = p[i];
    if (l == 0) return i + 1;
    if ((l & 0xC0) == 0xC0) return i + 2 <= len ? i + 2 : -1;
    if (l & 0xC0) return -1;
    i += 1 + l;
  }
  return -1;
}
// Min TTL over all RRs except OPT; with age > 0 also lowers every TTL by age.
static bool walkTtl(uint8_t* p, int len, uint32_t age, uint32_t* minTtl) {
  if (len < 12) return false;
  int qd = p[4] << 8 | p[5];
  int rr = (p[6] << 8 | p[7]) + (p[8] << 8 | p[9]) + (p[10] << 8 | p[11]);
  int i = 12;
  for (int k = 0; k < qd; k++) { i = skipName(p, len, i); if (i < 0 || i + 4 > len) return false; i += 4; }
  uint32_t mn = UINT32_MAX;
  for (int k = 0; k < rr; k++) {
    i = skipName(p, len, i); if (i < 0 || i + 10 > len) return false;
    uint16_t type = p[i] << 8 | p[i + 1], rdlen = p[i + 8] << 8 | p[i + 9];
    if (type != 41) {
      uint32_t t = (uint32_t)p[i + 4] << 24 | (uint32_t)p[i + 5] << 16 | (uint32_t)p[i + 6] << 8 | p[i + 7];
      if (t < mn) mn = t;
      if (age) { t = t > age ? t - age : 0; p[i + 4] = t >> 24; p[i + 5] = t >> 16; p[i + 6] = t >> 8; p[i + 7] = t; }
    }
    i += 10 + rdlen; if (i > len) return false;
  }
  if (minTtl) *minTtl = mn;
  return true;
}

static void cacheStore(uint64_t key, uint8_t* p, int len) {
  if (!key || !cacheSets || len < 12 || len > (int)sizeof(CacheEnt::data)) return;
  if (p[2] & 0x02) return;                                 // truncated
  uint8_t rcode = p[3] & 0x0F; if (rcode != 0 && rcode != 3) return;
  uint32_t ttl;
  if (!walkTtl(p, len, 0, &ttl) || ttl == 0 || ttl == UINT32_MAX) return;
  if ((rcode == 3 || (p[6] | p[7]) == 0) && ttl > 300) ttl = 300;   // negative answers: short
  if (ttl > 86400) ttl = 86400;
  CacheEnt* set = cache + (key & (cacheSets - 1)) * WAYS;
  uint32_t now = nowS();
  CacheEnt* v = nullptr;
  for (int w = 0; w < WAYS && !v; w++) if (set[w].key == key) v = &set[w];
  for (int w = 0; w < WAYS && !v; w++) if (!set[w].ttl || now >= set[w].stored + set[w].ttl) v = &set[w];
  if (!v) { v = set; for (int w = 1; w < WAYS; w++) if (set[w].stored + set[w].ttl < v->stored + v->ttl) v = &set[w]; }
  v->key = key; v->stored = now; v->ttl = ttl; v->len = len; v->prefetching = 0;
  memcpy(v->data, p, len);
}

static CacheEnt* cacheFind(uint64_t key, const uint8_t* q, int qend) {
  if (!cacheSets) return nullptr;
  CacheEnt* set = cache + (key & (cacheSets - 1)) * WAYS;
  uint32_t now = nowS();
  for (int w = 0; w < WAYS; w++) {
    CacheEnt* e = &set[w];
    if (e->key != key || !e->ttl || now >= e->stored + e->ttl || e->len < qend) continue;
    bool same = true;                                       // guard against a 64-bit key collision
    for (int i = 12; i < qend && same; i++) same = tolower(e->data[i]) == tolower(q[i]);
    if (same) return e;
  }
  return nullptr;
}

// ---------- pending upstream queries ----------
// Each in-flight upstream query owns one of UP_PORTS source ports. Measured on
// this network: N concurrent queries from one source port get exactly 1 reply
// (the path to the resolver collapses them), so a shared port lost most of any
// burst. Per-query ports are also the standard defence against cache poisoning.
// lwIP has 16 UDP PCBs in total (DHCP, mDNS, OTA... hold ~6), hence 8 ports; a
// miss beyond that waits in the queue for the next free port instead of dropping.
static const int MAX_PEND = 64, PEND_Q = 512, UP_PORTS = 8;
static const int8_t PORT_WAIT = -1, PORT_DOT = -2;
struct Pending {
  uint64_t key;
  uint32_t cip, sentMs;          // sentMs = queue time until dispatched, then send time
  uint16_t cport, cid, wid, qlen, qend;                    // cport 0 = prefetch (no client)
  int8_t port;                   // PORT_WAIT: queued for a UDP port; PORT_DOT: in flight over TLS
  uint8_t gen;                   // bumped on reuse, so a late DoT reply can't land in a new query
  uint8_t tries; bool used;
  uint8_t q[PEND_Q];
};
static Pending pend[MAX_PEND];
static udp_pcb* upPcb[UP_PORTS];
static Pending* portOwner[UP_PORTS];

static void expireTick(void*);
static void armTimer() { if (!timerArmed) { timerArmed = true; sys_timeout(50, expireTick, nullptr); } }

static void dispatch(Pending* p, int port) {
  portOwner[port] = p; p->port = port; p->tries = 1; p->sentMs = nowMs();
  p->wid = (uint16_t)esp_random(); p->q[0] = p->wid >> 8; p->q[1] = p->wid;
  sendRaw(upPcb[port], p->q, p->qlen, &upAddr[0], UPSTREAM_PORT);
}
static void release(Pending* p) {              // free the slot; its port goes to the oldest waiter
  int port = p->port; p->used = false; p->port = PORT_WAIT; p->gen++;
  if (port < 0) return;
  portOwner[port] = nullptr;
  Pending* w = nullptr;
  for (int i = 0; i < MAX_PEND; i++)
    if (pend[i].used && pend[i].port == PORT_WAIT && (!w || (int32_t)(pend[i].sentMs - w->sentMs) < 0)) w = &pend[i];
  if (w) dispatch(w, port);
}

// A reply that came back over TLS, handed to us by the DoT task.
void dotDeliver(uint16_t slot, uint16_t gen, const uint8_t* reply, int len) {
  if (slot >= MAX_PEND || len < 12) return;
  Pending* p = &pend[slot];
  if (!p->used || p->port != PORT_DOT || p->gen != (uint8_t)gen) return;   // slot already reused
  if (len < p->qend || memcmp(reply + 12, p->q + 12, p->qend - 12) != 0) return;
  memcpy(ux, reply, len);
  cacheStore(p->key, ux, len);
  if (p->cport) {
    ux[0] = p->cid >> 8; ux[1] = p->cid;
    ip_addr_t c = IPADDR4_INIT(p->cip);
    sendRaw(srvPcb, ux, len, &c, p->cport);
  }
  release(p);
}

// cip is in network order; cport 0 = prefetch (no client to answer)
static void forward(const uint8_t* q, int qlen, int qend, uint64_t key, uint32_t cip, uint16_t cport) {
  if (qlen > PEND_Q) { stLost++; return; }                 // no real stub sends a >512 B query
  Pending* p = nullptr;
  for (int i = 0; i < MAX_PEND && !p; i++) if (!pend[i].used) p = &pend[i];
  if (!p) { stLost++; return; }                            // 64 already queued: shed load
  p->used = true; p->port = PORT_WAIT; p->key = key; p->sentMs = nowMs();
  p->cip = cip; p->cport = cport; p->cid = q[0] << 8 | q[1]; p->qlen = qlen; p->qend = qend;
  memcpy(p->q, q, qlen);
  // Encrypted first: only fall back to plaintext UDP when DoT is actually down, so
  // a healthy box never puts a name on the wire in the clear.
  uint16_t slot = p - pend;
  if (dotReady() && dotSubmit(slot, p->gen, p->q, qlen)) { p->port = PORT_DOT; p->tries = 1; stDot++; }
  else for (int i = 0; i < UP_PORTS; i++) if (upPcb[i] && !portOwner[i]) { dispatch(p, i); break; }
  armTimer();
}

static void onUpstream(int n, const ip_addr_t* from, uint16_t port, int slot) {
  Pending* p = portOwner[slot];
  if (!p || n < 12 || port != UPSTREAM_PORT || !IP_IS_V4(from)) return;
  if (!ip_addr_cmp(from, &upAddr[0]) && !ip_addr_cmp(from, &upAddr[1])) return;
  if ((ux[0] << 8 | ux[1]) != p->wid) return;
  if (n < p->qend || memcmp(ux + 12, p->q + 12, p->qend - 12) != 0) return;   // late dup / spoof
  cacheStore(p->key, ux, n);
  if (p->cport) {
    ux[0] = p->cid >> 8; ux[1] = p->cid;
    ip_addr_t c = IPADDR4_INIT(p->cip);
    sendRaw(srvPcb, ux, n, &c, p->cport);
  }
  release(p);
}

// Single plain question -> lowercase name; returns name length, or -1 (forward raw).
static int parseQuestion(const uint8_t* p, int len, char* out, uint16_t* qtype, uint16_t* qclass, int* qend) {
  if (len < 17 || (p[4] << 8 | p[5]) != 1) return -1;
  int i = 12, o = 0;
  while (i < len) {
    uint8_t l = p[i++];
    if (l == 0) break;
    if (l & 0xC0 || o + l + 1 >= 250 || i + l > len) return -1;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(p[i++]);
  }
  if (i + 4 > len || o == 0) return -1;
  out[o] = 0;
  *qtype = p[i] << 8 | p[i + 1]; *qclass = p[i + 2] << 8 | p[i + 3]; *qend = i + 4;
  return o;
}

static bool nameBlocked(const char* name, int n) {
  const char* s = name;
  if (n > 4 && memcmp(s, "www.", 4) == 0) { s += 4; n -= 4; }
  const char* end = s + n;
  while (s < end) {                                         // name, then each parent down to "a.b"
    uint64_t h = dnsHash(s, end - s);
    if (isCustom(h) || blContains(h)) return true;
    const char* dot = (const char*)memchr(s, '.', end - s); if (!dot) break;
    if (!memchr(dot + 1, '.', end - dot - 1)) break;
    s = dot + 1;
  }
  return false;
}

static int buildBlocked(const uint8_t* q, int qend, uint16_t qtype) {
  memcpy(tx, q, qend);
  tx[2] = 0x80 | (q[2] & 0x01); tx[3] = 0x80;               // QR + mirrored RD, RA, NOERROR
  tx[4] = 0; tx[5] = 1; tx[6] = 0; tx[7] = qtype == 1; tx[8] = tx[9] = tx[10] = tx[11] = 0;
  if (qtype != 1) return qend;                              // NODATA for AAAA/HTTPS/...
  static const uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 0, 0, 0, 0};   // A 0.0.0.0, TTL 300
  memcpy(tx + qend, ans, sizeof(ans));
  return qend + sizeof(ans);
}

static void onClient(int n, const ip_addr_t* from, uint16_t port) {
  if (n < 12 || (rx[2] & 0x80) || !IP_IS_V4(from)) return;  // not a query
  static char name[256];                                    // static: keeps the 4 KB tcpip stack free
  uint16_t qtype = 0, qclass = 0; int qend = 0;
  int nl = parseQuestion(rx, n, name, &qtype, &qclass, &qend);
  uint32_t cip = ip4_addr_get_u32(ip_2_ip4(from));
  dotNoteClient();                                          // keeps the TLS link warm while in use
  bool blocked = isBanned(cip) || (nl > 0 && blocking && nameBlocked(name, nl));
  DnsEvent ev = { cip, blocked }; xQueueSend(evq, &ev, 0);  // full queue: per-client count lost, totals still right
  if (blocked) {
    stBlocked++;
    if (nl > 0) { int len = buildBlocked(rx, qend, qtype); sendRaw(srvPcb, tx, len, from, port); }
    return;
  }
  stAllowed++;
  uint64_t key = nl > 0 ? cacheKey(name, nl, qtype, qclass, (rx[10] | rx[11]) != 0) : 0;
  if (key) {
    CacheEnt* e = cacheFind(key, rx, qend);
    if (e) {
      uint32_t now = nowS(), age = now - e->stored;
      memcpy(tx, e->data, e->len);
      tx[0] = rx[0]; tx[1] = rx[1];
      memcpy(tx + 12, rx + 12, qend - 12);                  // echo the client's exact question (0x20 case)
      tx[2] = (tx[2] & ~0x01) | (rx[2] & 0x01);
      if (age) walkTtl(tx, e->len, age, nullptr);
      sendRaw(srvPcb, tx, e->len, from, port);
      stHits++;
      uint32_t left = e->stored + e->ttl - now;
      if (!e->prefetching && e->ttl >= 10 && left * 10 < e->ttl) { e->prefetching = 1; stPrefetch++; forward(rx, n, qend, key, 0, 0); }
      return;
    }
  }
  forward(rx, n, nl > 0 ? qend : 12, key, cip, port);
}

// 50 ms lwIP timer, armed only while something is pending: resend to the second
// upstream after RETRY_MS, give up after GIVEUP_MS.
static void expireTick(void*) {
  timerArmed = false;
  uint32_t now = nowMs();
  for (int i = 0; i < MAX_PEND; i++) {
    Pending* p = &pend[i]; if (!p->used) continue;
    uint32_t age = now - p->sentMs;
    if (age >= GIVEUP_MS) { stLost++; release(p); continue; }   // may dispatch a waiter
    if (p->port == PORT_DOT && p->tries == 1 && age >= RETRY_MS) {
      p->tries = 2;                            // TLS link stalled: retry this one over UDP
      for (int i = 0; i < UP_PORTS; i++) if (upPcb[i] && !portOwner[i]) { dispatch(p, i); break; }
    }
    if (p->port >= 0 && p->tries == 1 && age >= RETRY_MS) {
      sendRaw(upPcb[p->port], p->q, p->qlen, &upAddr[1], UPSTREAM_PORT); p->tries = 2;
    }
  }
  for (int i = 0; i < MAX_PEND; i++) if (pend[i].used) { armTimer(); break; }
}

static void srvRecv(void*, udp_pcb*, pbuf* p, const ip_addr_t* addr, u16_t port) {
  int n = pbuf_copy_partial(p, rx, sizeof(rx), 0); pbuf_free(p);
  onClient(n, addr, port);
}
static void upRecv(void* slot, udp_pcb*, pbuf* p, const ip_addr_t* addr, u16_t port) {
  int n = pbuf_copy_partial(p, ux, sizeof(ux), 0); pbuf_free(p);
  onUpstream(n, addr, port, (int)(intptr_t)slot);
}
static void startInTcpip(void* arg) {
  static const uint8_t u1[] = {UPSTREAM_IP}, u2[] = {UPSTREAM2_IP};
  IP_ADDR4(&upAddr[0], u1[0], u1[1], u1[2], u1[3]);
  IP_ADDR4(&upAddr[1], u2[0], u2[1], u2[2], u2[3]);
  srvPcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (!srvPcb) return;
  udp_bind(srvPcb, IP4_ADDR_ANY, (uint16_t)(uintptr_t)arg);
  udp_recv(srvPcb, srvRecv, nullptr);
  for (int i = 0; i < UP_PORTS; i++) {                      // port 0: lwIP picks a fresh ephemeral port
    upPcb[i] = udp_new_ip_type(IPADDR_TYPE_V4);            // null if the PCB pool ran out: port unused
    if (!upPcb[i]) continue;
    udp_bind(upPcb[i], IP4_ADDR_ANY, 0);
    udp_recv(upPcb[i], upRecv, (void*)(intptr_t)i);
  }
}

void dnsStart(uint16_t port) {
  tcpip_callback(startInTcpip, (void*)(uintptr_t)port);
  dotInit();
}
