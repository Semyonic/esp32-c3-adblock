// proxy.cpp — HTTP CONNECT proxy with fake SNI + ClientHello fragmentation.
//
// The diagnostic showed why DNS alone cannot fix Discord: the ISP poisons the
// name, DoT gets the real address, TCP 443 opens, and the TLS handshake dies
// because the SNI is in the clear. This proxy puts the box in the TCP path for
// the names the PAC sends here. It resolves the name over DoT, opens a raw TCP
// connection, sends a fake ClientHello at the real snd_nxt with TTL 3 (the DPI
// reads the allowed name, the server never sees it), then splits the real
// ClientHello into fourteen segments. TLS is never terminated: the bytes are
// relayed end to end, so there is no certificate to install.
//
// One task, one connection table, no per-connection task: a browser through a
// PAC opens a handful of connections, and the socket pool is 16 for the whole
// box (web, DoT and this listener included). Four slots leave room for them.
#include "proxy.h"
#include "dot.h"
#include "wire.h"
#include <WiFi.h>
#include <NetworkServer.h>
#include <NetworkClient.h>
#include <algorithm>
#include <atomic>
#include <new>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "lwip/raw.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcp.h"

static const uint16_t PROXY_PORT = 8080;
static const int MAX_CONN = 4;
static const uint32_t HEADER_MS = 5000, HELLO_MS = 3000, IDLE_MS = 120000;
static const uint32_t RESOLVE_MS = 8000, CONNECT_MS = 5000;
static const int HELLO_MAX = 1024;
static const int RELAY_BUF = 1460;
static const int PX_RX = 4096;
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

enum PxState : uint8_t { PX_FREE = 0, PX_HEADER, PX_CONNECTING, PX_HELLO, PX_RELAY };
struct PxConn {
  NetworkClient client;
  std::atomic<struct tcp_pcb*> up{nullptr};
  std::atomic<uint16_t> rxHead{0}, rxTail{0};
  std::atomic<bool> upReady{false}, upClosed{false};
  PxState state = PX_FREE;
  uint32_t started = 0, lastActive = 0;
  char host[128] = {0};
  uint16_t port = 443;
  uint32_t ip = 0;
  uint16_t headerLen = 0, helloLen = 0;
  uint8_t header[512];
  uint8_t hello[HELLO_MAX];
  uint8_t rx[PX_RX];
};

static PxConn* conns = nullptr;
static uint8_t relayBuf[RELAY_BUF];
static NetworkServer pxServer(PROXY_PORT, MAX_CONN);
static volatile uint32_t stTotal = 0, stActive = 0, stFail = 0, stSplit = 0, stBytes = 0, stFake = 0;
static volatile int stLastErr = 0;
bool pxFakeOn = true;   // runtime switches: one image can test each combination
bool pxSplitOn = true;
uint8_t pxFakeTtl = 3;

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

// A synthetic TLS 1.3 ClientHello for www.google.com: 75 bytes, a name the DPI
// allows. Its length differs from the real hello on purpose: a same-length fake
// is a clean TCP duplicate, and a reassembling DPI may keep the real bytes; a
// shorter fake leaves the allowed name in the part the DPI keeps. The server
// never sees it (TTL 3); the real hello follows split.
static const uint8_t FAKE_HELLO[] = {
  0x16,0x03,0x01,0x00,0x46, 0x01,0x00,0x00,0x42, 0x03,0x03,
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
  0x00, 0x00,0x02,0x13,0x01, 0x01,0x00,
  0x00,0x17, 0x00,0x00,0x00,0x13, 0x00,0x11, 0x00, 0x00,0x0e,
  'w','w','w','.','g','o','o','g','l','e','.','c','o','m'
};

// A fake ClientHello is a copy of the real one with its SNI replaced by a name
// the middlebox allows. It is sent as a raw duplicate at the real snd_nxt with
// TTL 3: the DPI reads the allowed name, the server never sees the packet, and
// the real ClientHello follows split. The fake has the same length as the real
// hello, or the DPI's sequence bookkeeping sees a different stream.
struct FakeArgs { struct tcp_pcb* pcb; const uint8_t* data; uint16_t len; err_t err; };
static raw_pcb* fakePcb = nullptr;

static void fakeSendCb(void* arg) {
  FakeArgs* a = (FakeArgs*)arg;
  a->err = ERR_ARG;
  if (!a->pcb || !a->data || !a->len) return;
  if (!fakePcb) {
    fakePcb = raw_new(IPPROTO_TCP);
    if (!fakePcb) { a->err = ERR_MEM; return; }
    raw_bind(fakePcb, IP_ADDR_ANY);
    fakePcb->ttl = pxFakeTtl;
  }
  fakePcb->ttl = pxFakeTtl;
  uint16_t len = (uint16_t)(20 + a->len);
  pbuf* p = pbuf_alloc(PBUF_IP, len, PBUF_RAM);   // room for the IP header raw_sendto adds
  if (!p) { a->err = ERR_MEM; return; }
  uint8_t* h = (uint8_t*)p->payload;
  memset(h, 0, 20);
  h[0] = (uint8_t)(a->pcb->local_port >> 8); h[1] = (uint8_t)a->pcb->local_port;
  h[2] = (uint8_t)(a->pcb->remote_port >> 8); h[3] = (uint8_t)a->pcb->remote_port;
  uint32_t seq = a->pcb->snd_nxt, ack = a->pcb->rcv_nxt;
  h[4] = (uint8_t)(seq >> 24); h[5] = (uint8_t)(seq >> 16); h[6] = (uint8_t)(seq >> 8); h[7] = (uint8_t)seq;
  h[8] = (uint8_t)(ack >> 24); h[9] = (uint8_t)(ack >> 16); h[10] = (uint8_t)(ack >> 8); h[11] = (uint8_t)ack;
  h[12] = 0x50; h[13] = 0x18; h[14] = 0xFF; h[15] = 0xFF;
  memcpy(h + 20, a->data, a->len);
  uint32_t l = (uint32_t)WiFi.localIP();
  uint8_t s[4] = {(uint8_t)l, (uint8_t)(l >> 8), (uint8_t)(l >> 16), (uint8_t)(l >> 24)};
  uint32_t dw = ip4_addr_get_u32(ip_2_ip4(&a->pcb->remote_ip));
  uint8_t d[4] = {(uint8_t)dw, (uint8_t)(dw >> 8), (uint8_t)(dw >> 16), (uint8_t)(dw >> 24)};
  uint16_t ck = wire::tcpChecksum(h, len, s, d);
  h[16] = (uint8_t)(ck >> 8); h[17] = (uint8_t)ck;
  a->err = raw_sendto(fakePcb, p, &a->pcb->remote_ip);
  pbuf_free(p);
}

static bool upFake(PxConn& c, const uint8_t* data, uint16_t len) {
  struct tcp_pcb* pcb = c.up.load();
  if (!pcb || !len) return false;
  FakeArgs a{pcb, data, len, ERR_OK};
  tcpip_callback_with_block(fakeSendCb, &a, 1);
  if (a.err == ERR_OK) { stFake++; return true; }
  stLastErr = (int)a.err;
  Serial.printf("px fake err %d\n", (int)a.err);
  return false;
}

static void pxClose(int i);

static err_t upRecvCb(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) {
  PxConn* c = (PxConn*)arg;
  if (!p) { c->upClosed.store(true); return ERR_OK; }
  uint16_t len = p->tot_len;
  uint16_t head = c->rxHead.load(std::memory_order_relaxed);
  uint16_t tail = c->rxTail.load(std::memory_order_acquire);
  uint16_t used = (uint16_t)((head + PX_RX - tail) % PX_RX);
  uint16_t free = (uint16_t)(PX_RX - 1 - used);
  if (len <= free) {
    uint16_t first = (uint16_t)std::min<uint16_t>(len, (uint16_t)(PX_RX - head));
    pbuf_copy_partial(p, c->rx + head, first, 0);
    if (len > first) pbuf_copy_partial(p, c->rx, (uint16_t)(len - first), first);
    c->rxHead.store((uint16_t)((head + len) % PX_RX), std::memory_order_release);
  }
  tcp_recved(pcb, len);
  pbuf_free(p);
  return ERR_OK;
}

static void upErrCb(void* arg, err_t err) {
  PxConn* c = (PxConn*)arg;
  stLastErr = (int)err;
  Serial.printf("px pcb err %d\n", (int)err);
  c->upClosed.store(true);
  c->up.store(nullptr);
}

static err_t upConnectedCb(void* arg, struct tcp_pcb* pcb, err_t err) {
  PxConn* c = (PxConn*)arg;
  if (err != ERR_OK || !pcb) { stLastErr = (int)err; Serial.printf("px up err %d\n", (int)err); c->upClosed.store(true); return err; }
  c->up.store(pcb);
  tcp_arg(pcb, c);
  tcp_recv(pcb, upRecvCb);
  tcp_err(pcb, upErrCb);
  c->upReady.store(true);
  // the fake is sent from serviceHello, once the real hello is known
  return ERR_OK;
}

struct ConnectArgs { PxConn* c; ip_addr_t ip; uint16_t port; };

static void connectCb(void* arg) {
  ConnectArgs* a = (ConnectArgs*)arg;
  struct tcp_pcb* pcb = tcp_new();
  if (!pcb) { stLastErr = -100; Serial.printf("px tcp_new failed\n"); a->c->upClosed.store(true); return; }
  tcp_arg(pcb, a->c);
  err_t e = tcp_connect(pcb, &a->ip, a->port, upConnectedCb);
  if (e != ERR_OK) {
    stLastErr = (int)e;
    Serial.printf("px tcp_connect err %d\n", (int)e);
    tcp_abort(pcb);
    a->c->upClosed.store(true);
  }
}

static bool tcpStart(PxConn* c, uint32_t ip, uint16_t port) {
  ConnectArgs a;
  a.c = c;
  IP_ADDR4(&a.ip, ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
  a.port = port;
  tcpip_callback_with_block(connectCb, &a, 1);
  return true;
}

struct WriteArgs { struct tcp_pcb* pcb; const uint8_t* data; uint16_t len; err_t err; };

static void writeCb(void* arg) {
  WriteArgs* a = (WriteArgs*)arg;
  if (!a->pcb) { a->err = ERR_CLSD; return; }
  a->err = tcp_write(a->pcb, a->data, a->len, TCP_WRITE_FLAG_COPY);
  if (a->err == ERR_OK) tcp_output(a->pcb);
}

static bool upWrite(PxConn& c, const uint8_t* data, uint16_t len) {
  struct tcp_pcb* pcb = c.up.load();
  if (!pcb || !len) return false;
  WriteArgs a{pcb, data, len, ERR_OK};
  tcpip_callback_with_block(writeCb, &a, 1);
  return a.err == ERR_OK;
}

struct CloseArgs { struct tcp_pcb* pcb; };

static void closeCb(void* arg) {
  CloseArgs* a = (CloseArgs*)arg;
  if (!a->pcb) return;
  tcp_arg(a->pcb, NULL);
  tcp_recv(a->pcb, NULL);
  tcp_err(a->pcb, NULL);
  tcp_close(a->pcb);
}

static void pxClose(int i) {
  PxConn& c = conns[i];
  if (c.state == PX_FREE) return;
  struct tcp_pcb* pcb = c.up.exchange(nullptr);
  if (pcb) { CloseArgs a{pcb}; tcpip_callback_with_block(closeCb, &a, 1); }
  c.client.stop();
  c.state = PX_FREE; c.headerLen = c.helloLen = 0;
  c.rxHead.store(0); c.rxTail.store(0);
  c.upReady.store(false); c.upClosed.store(false);
  if (stActive) stActive--;
}

static int freeSlot() {
  for (int i = 0; i < MAX_CONN; i++) if (conns[i].state == PX_FREE) return i;
  return -1;
}

static void serviceConnecting(int i) {
  PxConn& c = conns[i];
  if (c.upClosed.load()) { stFail++; pxClose(i); return; }
  if (!c.upReady.load()) {
    if (nowMs() - c.started > CONNECT_MS) { stFail++; pxClose(i); }
    return;
  }
  const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
  if (!pxWrite(c.client, (const uint8_t*)ok, (int)strlen(ok))) { stFail++; pxClose(i); return; }
  c.state = PX_HELLO; c.started = nowMs(); c.lastActive = c.started;
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
  if (!ip) { stFail++; pxClose(i); return; }
  c.ip = ip;
  c.client.setNoDelay(true);
  c.state = PX_CONNECTING; c.started = nowMs(); c.lastActive = c.started;
  tcpStart(&c, ip, c.port);
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
    if (pxFakeOn) upFake(c, FAKE_HELLO, sizeof(FAKE_HELLO));
    int chunk = pxSplitOn ? (total + CHUNKS - 1) / CHUNKS : total;
    if (chunk < 32) chunk = 32;
    int off = 0;
    while (off < total) {
      int n = mn(chunk, total - off);
      if (!upWrite(c, c.hello + off, (uint16_t)n)) { stFail++; pxClose(i); return; }
      off += n; stBytes += (uint32_t)n;
      if (off < total) vTaskDelay(pdMS_TO_TICKS(10));   // a separate segment per write, and time to see it
    }
    stSplit++;
  } else {
    if (!upWrite(c, c.hello, (uint16_t)total)) { stFail++; pxClose(i); return; }
    stBytes += (uint32_t)total;
  }
  c.helloLen = 0;
  c.state = PX_RELAY; c.lastActive = nowMs();
}

static void serviceRelay(int i) {
  PxConn& c = conns[i];
  bool moved = false;
  uint16_t tail = c.rxTail.load(std::memory_order_relaxed);
  uint16_t head = c.rxHead.load(std::memory_order_acquire);
  while (tail != head) {
    uint16_t n = (uint16_t)((head > tail) ? (head - tail) : (PX_RX - tail));
    int w = c.client.write(c.rx + tail, n);
    if (w <= 0) break;
    tail = (uint16_t)((tail + w) % PX_RX);
    stBytes += (uint32_t)w; moved = true;
  }
  c.rxTail.store(tail, std::memory_order_release);
  int a = c.client.available();
  if (a > 0) {
    int n = c.client.read(relayBuf, mn(a, RELAY_BUF));
    if (n > 0) {
      if (!upWrite(c, relayBuf, (uint16_t)n)) { pxClose(i); return; }
      stBytes += (uint32_t)n; moved = true;
    }
  }
  if (moved) c.lastActive = nowMs();
  if (!c.client.connected() || c.upClosed.load()) { pxClose(i); return; }
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
        c.up.store(nullptr);
        c.rxHead.store(0); c.rxTail.store(0);
        c.upReady.store(false); c.upClosed.store(false);
        c.state = PX_HEADER; c.started = nowMs(); c.lastActive = c.started;
        c.headerLen = c.helloLen = 0; c.host[0] = 0; c.port = 443; c.ip = 0;
        c.client.setNoDelay(true);
        stTotal++; stActive++;
      }
    }
    for (int i = 0; i < MAX_CONN; i++) {
      if (conns[i].state == PX_HEADER) serviceHeader(i);
      else if (conns[i].state == PX_CONNECTING) serviceConnecting(i);
      else if (conns[i].state == PX_HELLO) serviceHello(i);
      else if (conns[i].state == PX_RELAY) serviceRelay(i);
    }
    vTaskDelay(1);
  }
}

void proxyInit() {
  // The table is ~23 KB; keeping it in PSRAM leaves the internal heap for the
  // one-shot DoT handshake dotResolve needs.
  conns = (PxConn*)heap_caps_malloc(sizeof(PxConn) * MAX_CONN, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!conns) { Serial.println("proxy: no PSRAM for the table"); return; }
  for (int i = 0; i < MAX_CONN; i++) new (&conns[i]) PxConn();
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

PxStats proxyStats() { return { stTotal, stActive, stFail, stSplit, stBytes, stFake, stLastErr }; }

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
