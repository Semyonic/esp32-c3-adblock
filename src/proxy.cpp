// proxy.cpp — HTTP CONNECT proxy with ClientHello fragmentation.
//
// The diagnostic showed why DNS alone cannot fix Discord: the ISP poisons the
// name, DoT gets the real address, TCP 443 opens, and the TLS handshake dies
// because the SNI is in the clear. This proxy puts the box in the TCP path for
// the names the PAC sends here. It resolves the name over DoT, opens a plain
// TCP connection, and splits the first TLS ClientHello into seven segments so
// a stateful DPI has to reassemble more than it will. TLS is never terminated:
// the bytes are relayed end to end, so there is no certificate to install.
//
// One task, one connection table, no per-connection task: a browser through a
// PAC opens a handful of connections, and the socket pool is 16 for the whole
// box (web, DoT and this listener included). Five slots leave room for them.
#include "proxy.h"
#include "dot.h"
#include <WiFi.h>
#include <NetworkServer.h>
#include <NetworkClient.h>
#include <algorithm>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const uint16_t PROXY_PORT = 8080;
static const int MAX_CONN = 4;
static const uint32_t HEADER_MS = 5000, HELLO_MS = 3000, IDLE_MS = 120000;
static const uint32_t RESOLVE_MS = 8000, CONNECT_MS = 5000;
static const int HELLO_MAX = 1024;
static const int RELAY_BUF = 1460;
static const int CHUNKS = 14;                // more than the DPI will reassemble; 4-7 was not enough here
static const int CACHE_N = 8;
static const uint32_t CACHE_MS = 120000;

// Edit this list to choose what the PAC sends through the box. Keep it to names
// whose traffic fits the radio: Discord and text sites, not 4K video.
static const char* PROXY_DOMAINS[] = {
  "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
  "discord.media", "discordstatus.com",
  "twitter.com", "x.com", "twimg.com", "t.co",
  "wikipedia.org", "wikimedia.org",
  "whatsapp.com", "whatsapp.net",
  "instagram.com", "cdninstagram.com",
};

enum PxState : uint8_t { PX_FREE = 0, PX_HEADER, PX_HELLO, PX_RELAY };
struct PxConn {
  NetworkClient client, up;
  PxState state = PX_FREE;
  uint32_t started = 0, lastActive = 0;
  char host[128] = {0};
  uint16_t port = 443;
  uint16_t headerLen = 0, helloLen = 0;
  uint8_t header[512];
  uint8_t hello[HELLO_MAX];
};

static PxConn conns[MAX_CONN];
static uint8_t relayBuf[RELAY_BUF];
static NetworkServer pxServer(PROXY_PORT, MAX_CONN);
static volatile uint32_t stTotal = 0, stActive = 0, stFail = 0, stSplit = 0, stBytes = 0;

struct PxCache { char host[128]; uint32_t ip; uint32_t at; };
static PxCache cache[CACHE_N];
static int cacheNext = 0;

static inline uint32_t nowMs() { return millis(); }
static inline int mn(int a, int b) { return a < b ? a : b; }

static bool cacheGet(const char* host, uint32_t* ip) {
  for (auto& e : cache)
    if (e.ip && strcmp(e.host, host) == 0 && nowMs() - e.at < CACHE_MS) { *ip = e.ip; return true; }
  return false;
}
static void cachePut(const char* host, uint32_t ip) {
  PxCache& e = cache[cacheNext++ % CACHE_N];
  strncpy(e.host, host, sizeof(e.host) - 1); e.host[sizeof(e.host) - 1] = 0;
  e.ip = ip; e.at = nowMs();
}

// Lowercase and strip a trailing root dot; the cache and DoT want the same form.
static bool normHost(const char* in, char* out, size_t cap) {
  size_t n = strlen(in);
  while (n && in[n - 1] == '.') n--;
  if (n < 1 || n >= cap) return false;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'))
      return false;
    out[i] = c;
  }
  out[n] = 0;
  return true;
}

static int findHeaderEnd(const uint8_t* p, int n) {
  for (int i = 3; i < n; i++)
    if (p[i - 3] == '\r' && p[i - 2] == '\n' && p[i - 1] == '\r' && p[i] == '\n') return i + 1;
  return -1;
}

static bool pxWrite(NetworkClient& s, const uint8_t* p, int n) {
  int off = 0;
  while (off < n) {
    int w = s.write(p + off, n - off);
    if (w <= 0) return false;
    off += w;
  }
  return true;
}

static void pxClose(int i) {
  PxConn& c = conns[i];
  if (c.state == PX_FREE) return;
  c.client.stop(); c.up.stop();
  c.state = PX_FREE; c.headerLen = c.helloLen = 0;
  if (stActive) stActive--;
}

static int freeSlot() {
  for (int i = 0; i < MAX_CONN; i++) if (conns[i].state == PX_FREE) return i;
  return -1;
}

static void serviceHeader(int i) {
  PxConn& c = conns[i];
  int space = (int)sizeof(c.header) - 1 - c.headerLen;
  int avail = c.client.available();
  if (avail > 0 && space > 0) {
    int n = c.client.read(c.header + c.headerLen, mn(avail, space));
    if (n > 0) { c.headerLen += (uint16_t)n; c.lastActive = nowMs(); }
  }
  int end = findHeaderEnd(c.header, c.headerLen);
  if (end < 0) {
    if (c.headerLen >= (int)sizeof(c.header) - 1 || nowMs() - c.started > HEADER_MS) pxClose(i);
    return;
  }
  char line[300];
  int ll = 0;
  while (ll < end && c.header[ll] != '\r' && c.header[ll] != '\n' && ll < (int)sizeof(line) - 1) {
    line[ll] = (char)c.header[ll]; ll++;
  }
  line[ll] = 0;

  char host[128]; unsigned port = 0;
  if (sscanf(line, "CONNECT %127[^:]:%u", host, &port) < 1) {
    const char* bad = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
    c.client.write((const uint8_t*)bad, strlen(bad));
    pxClose(i); return;
  }
  if (port == 0) port = 443;
  if (!normHost(host, c.host, sizeof(c.host))) { stFail++; pxClose(i); return; }
  c.port = (uint16_t)port;

  uint32_t ip = 0;
  IPAddress lit;
  bool isIp = true;
  for (const char* q = c.host; *q; q++)
    if (!((*q >= '0' && *q <= '9') || *q == '.')) { isIp = false; break; }
  if (isIp && lit.fromString(c.host)) ip = (uint32_t)lit;
  else if (!cacheGet(c.host, &ip)) {
    uint8_t rc = 0;
    if (!dotResolve(c.host, &ip, &rc, RESOLVE_MS) || !ip) { stFail++; pxClose(i); return; }
    cachePut(c.host, ip);
  }
  if (!ip || !c.up.connect(IPAddress(ip), c.port, CONNECT_MS)) { stFail++; pxClose(i); return; }
  c.up.setNoDelay(true);
  c.client.setNoDelay(true);
  const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
  c.client.write((const uint8_t*)ok, strlen(ok));
  c.state = PX_HELLO; c.started = nowMs(); c.lastActive = c.started;
}

static void serviceHello(int i) {
  PxConn& c = conns[i];
  int space = HELLO_MAX - c.helloLen;
  int avail = c.client.available();
  if (avail > 0 && space > 0) {
    int n = c.client.read(c.hello + c.helloLen, mn(avail, space));
    if (n > 0) { c.helloLen += (uint16_t)n; c.lastActive = nowMs(); }
  }
  if (c.helloLen == 0) {                 // nothing yet: wait, do not call it ready
    if (nowMs() - c.started > HELLO_MS) pxClose(i);
    return;
  }
  int need = c.helloLen;
  if (c.helloLen >= 5 && c.hello[0] == 0x16) {
    int rec = (c.hello[3] << 8) | c.hello[4];
    if (rec > 0 && rec + 5 < HELLO_MAX) need = rec + 5;
  }
  bool ready = c.helloLen >= need || c.helloLen >= HELLO_MAX;
  if (!ready) {
    if (nowMs() - c.started > HELLO_MS) ready = true;   // split what arrived
    else return;
  }
  int total = c.helloLen;
  if (total <= 0) { pxClose(i); return; }

  if (c.hello[0] == 0x16 && total >= 5) {
    int chunk = (total + CHUNKS - 1) / CHUNKS;
    if (chunk < 32) chunk = 32;
    int off = 0;
    while (off < total) {
      int n = mn(chunk, total - off);
      if (!pxWrite(c.up, c.hello + off, n)) { stFail++; pxClose(i); return; }
      off += n; stBytes += (uint32_t)n;
      if (off < total) vTaskDelay(pdMS_TO_TICKS(10));   // a separate segment per write, and time to see it
    }
    stSplit++;
  } else {
    if (!pxWrite(c.up, c.hello, total)) { stFail++; pxClose(i); return; }
    stBytes += (uint32_t)total;
  }
  c.helloLen = 0;
  c.state = PX_RELAY; c.lastActive = nowMs();
}

static void serviceRelay(int i) {
  PxConn& c = conns[i];
  bool moved = false;
  int a = c.client.available();
  if (a > 0) {
    int n = c.client.read(relayBuf, mn(a, RELAY_BUF));
    if (n > 0) {
      if (!pxWrite(c.up, relayBuf, n)) { pxClose(i); return; }
      stBytes += (uint32_t)n; moved = true;
    }
  }
  int b = c.up.available();
  if (b > 0) {
    int n = c.up.read(relayBuf, mn(b, RELAY_BUF));
    if (n > 0) {
      if (!pxWrite(c.client, relayBuf, n)) { pxClose(i); return; }
      stBytes += (uint32_t)n; moved = true;
    }
  }
  if (moved) c.lastActive = nowMs();
  if (!c.client.connected() || !c.up.connected()) { pxClose(i); return; }
  if (nowMs() - c.lastActive > IDLE_MS) pxClose(i);
}

static void proxyTask(void*) {
  for (;;) {
    NetworkClient nc = pxServer.accept();
    if (nc) {
      int slot = freeSlot();
      if (slot < 0) nc.stop();
      else {
        PxConn& c = conns[slot];
        c.client = nc;
        c.up.stop();
        c.state = PX_HEADER; c.started = nowMs(); c.lastActive = c.started;
        c.headerLen = c.helloLen = 0; c.host[0] = 0; c.port = 443;
        c.client.setNoDelay(true);
        stTotal++; stActive++;
      }
    }
    for (int i = 0; i < MAX_CONN; i++) {
      if (conns[i].state == PX_HEADER) serviceHeader(i);
      else if (conns[i].state == PX_HELLO) serviceHello(i);
      else if (conns[i].state == PX_RELAY) serviceRelay(i);
    }
    vTaskDelay(1);
  }
}

void proxyInit() {
  pxServer.begin();
#ifdef BOARD_HAS_PSRAM
  // The one-shot DoT lookup needs its TLS context from internal heap; putting
  // the task stack in PSRAM leaves that heap for it.
  xTaskCreatePinnedToCoreWithCaps(proxyTask, "proxy", 8192, nullptr, 2, nullptr, 0,
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#elif configNUMBER_OF_CORES > 1
  xTaskCreatePinnedToCore(proxyTask, "proxy", 8192, nullptr, 2, nullptr, 0);
#else
  xTaskCreate(proxyTask, "proxy", 8192, nullptr, 2, nullptr);
#endif
}

PxStats proxyStats() { return { stTotal, stActive, stFail, stSplit, stBytes }; }

String proxyPac() {
  String p; p.reserve(2048);
  p += "function FindProxyForURL(url, host) {\n host = host.toLowerCase();\n";
  String where = "PROXY " + WiFi.localIP().toString() + ":" + String(PROXY_PORT);
  for (const char* d : PROXY_DOMAINS) {
    p += " if (host == \""; p += d; p += "\" || shExpMatch(host, \"*."; p += d;
    p += "\")) return \""; p += where; p += "\";\n";
  }
  p += " return \"DIRECT\";\n}\n";
  return p;
}
