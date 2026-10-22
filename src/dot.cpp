// dot.cpp — see dot.h.
#include "dot.h"
#include <NetworkClientSecure.h>
#include <WiFi.h>
#include <esp_timer.h>
#include "lwip/tcpip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

// Resolver reached by IP (no plaintext lookup to find it) while the certificate is
// still verified against DOT_HOST. Quad9: no logging, malware filtering, and the
// same operator the UDP path already used. Swap all three to switch resolver —
// dns.google / 8.8.8.8 / 8.8.4.4 answers ~20 ms faster and holds an idle link for
// 60 s instead of 10 s, at the cost of handing Google every query.
#ifndef DOT_HOST
#define DOT_HOST "dns.quad9.net"
#define DOT_IP   9, 9, 9, 9
#define DOT_IP2  149, 112, 112, 112
#endif

// Only the root is needed for the chain above: dns.quad9.net <- DigiCert Global G3
// TLS ECC SHA384 2020 CA1 <- DigiCert Global Root G3 (ECC P-384, valid to 2038-01-15).
// SHA-256 31:AD:66:48:F8:10:41:38:C7:38:F3:9E:A4:32:01:33:39:3E:3A:18:CC:02:29:6E:F9:7C:2A:C9:EF:67:31:D0
static const char DOT_ROOT_CA[] = R"CERT(-----BEGIN CERTIFICATE-----
MIICPzCCAcWgAwIBAgIQBVVWvPJepDU1w6QP1atFcjAKBggqhkjOPQQDAzBhMQsw
CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
Fw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUw
EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
IDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE3afZu4q4C/sLfyHS8L6+c/MzXRq8NOrexpu80JX28MzQC7phW1FG
fp4tn+6OYwwX7Adw9c+ELkCDnOg/QW07rdOkFFk2eJ0DQ+4QE2xy3q6Ip6FrtUPO
Z9wj/wMco+I+o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAd
BgNVHQ4EFgQUs9tIpPmhxdiuNkHMEWNpYim8S8YwCgYIKoZIzj0EAwMDaAAwZQIx
AK288mw/EkrRLTnDCgmXc/SINoyIJ7vmiI1Qhadj+Z4y3maTD/HMsQmP3Wyr+mt/
oAIwOWZbwmSNuJ5Q3KjVSaLtx9zRSX8XAbjIho9OjIgrqJqpisXRAL34VOKa5Vt8
sycX
-----END CERTIFICATE-----)CERT";

static const uint32_t KEEPALIVE_MS = 7000;    // Quad9 drops an idle link at 10 s
static const uint32_t WARM_MS     = 120000;   // ...but only keep it warm while clients are active
static const uint32_t BACKOFF_MS  = 30000;    // after repeated failures, stop retrying for a while
static const int      MAX_FAILS   = 3;
#ifdef BOARD_HAS_PSRAM
static const int      QDEPTH      = 48;   // covers a burst against the engine's 64 slots
static const int      NSLOTS      = 8;    // 12 KB; 0 drops measured at 140 queries/s
#else
static const int      QDEPTH      = 12;   // the small boards have no DRAM to spare
static const int      NSLOTS      = 4;
#endif

// Task placement below depends on this being the real core count, not a macro
// that quietly expanded to nothing. Checked per target at compile time so a board
// can never be handed a core it does not have — the kind of mistake that only
// shows up as a boot loop on hardware you may not have on the desk.
#ifndef configNUMBER_OF_CORES
#error "configNUMBER_OF_CORES is not visible here; task placement would be a guess"
#endif
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6) || defined(CONFIG_IDF_TARGET_ESP32H2)
static_assert(configNUMBER_OF_CORES == 1, "this target is single-core");
#elif defined(CONFIG_IDF_TARGET_ESP32) || defined(CONFIG_IDF_TARGET_ESP32S3)
static_assert(configNUMBER_OF_CORES == 2, "this target is dual-core");
#endif

struct DotReq { uint32_t t; uint16_t slot, gen, len; uint8_t msg[512]; };   // t = submitted at
static QueueHandle_t dotQ;

static volatile bool up = false;
static volatile bool linkDown = false;        // known-broken: send over UDP instead of waiting
static volatile uint32_t lastClientMs = 0;
static volatile uint32_t stQ = 0, stR = 0, stF = 0, stHs = 0, stHsMs = 0, stDrop = 0;

static inline uint32_t nowMs() { return (uint32_t)(esp_timer_get_time() / 1000); }

void dotNoteClient() { lastClientMs = nowMs(); }
// Queue for TLS while the link is up, and while it is merely idle (the task will
// bring it back and the query goes out encrypted). Once a connect has actually
// failed, say no: the engine then sends plaintext immediately instead of letting
// every query wait out its 350 ms fallback timer for the length of the outage.
bool dotReady() { return up || (!linkDown && nowMs() - lastClientMs < WARM_MS); }
DotStats dotStats() { return { stQ, stR, stF, stHs, stHsMs, stDrop, up }; }

bool dotSubmit(uint16_t slot, uint16_t gen, const uint8_t* msg, uint16_t len) {
  if (!dotQ || len > sizeof(DotReq::msg)) return false;
  DotReq r; r.t = nowMs(); r.slot = slot; r.gen = gen; r.len = len; memcpy(r.msg, msg, len);
  return xQueueSend(dotQ, &r, 0) == pdTRUE;
}

// ---------- task ----------
// Hand-off buffers to the lwIP thread. Running out means a reply is thrown away
// and that query waits for its UDP retry, so keep enough for a burst in flight.
struct Slot { uint8_t data[1536]; int len; uint16_t slot, gen; volatile bool busy; };
static Slot slots[NSLOTS];
static void deliverCb(void* arg) {
  Slot* s = (Slot*)arg;
  dotDeliver(s->slot, s->gen, s->data, s->len);
  s->busy = false;
}

static NetworkClientSecure cli;
static uint8_t rbuf[2 + 1536];
static int rlen = 0;                           // bytes of the current framed reply held in rbuf

// Who ended the link: set before every cli.stop() we initiate, so the log can tell
// our own faults apart from the peer hanging up (a resolver rate-limiting a busy
// connection looks identical otherwise).
static const char* stopReason = nullptr;
static void closeLink(const char* why) { stopReason = why; cli.stop(); }

static bool connectDot() {
  static const uint8_t a1[] = {DOT_IP}, a2[] = {DOT_IP2};
  const bool alt = (stF & 1);                  // alternate servers across retries
  IPAddress ip = alt ? IPAddress(a2[0], a2[1], a2[2], a2[3]) : IPAddress(a1[0], a1[1], a1[2], a1[3]);
  cli.setHandshakeTimeout(12);
  cli.setTimeout(5);
  uint32_t t0 = nowMs();
  stopReason = nullptr;
  if (!cli.connect(ip, 853, DOT_HOST, DOT_ROOT_CA, nullptr, nullptr)) { cli.stop(); return false; }
  cli.setNoDelay(true);
  stHsMs = nowMs() - t0; stHs++;
  rlen = 0;
  Serial.printf("[dot] connected to %s (%s) in %u ms\n", DOT_HOST, ip.toString().c_str(), stHsMs);
  return true;
}

// One framed reply = 2-byte length + message (RFC 7858). Reassembles across reads.
static int drainReplies() {
  int got = 0;
  while (cli.connected()) {
    int want = rlen < 2 ? 2 : 2 + ((rbuf[0] << 8) | rbuf[1]);
    // A frame that can't hold a DNS header means the stream is out of step (or the
    // peer is broken); without this the parser would sit on it forever.
    if (want > (int)sizeof(rbuf) || (rlen >= 2 && want < 2 + 12)) { closeLink("bad frame length"); return got; }
    if (!cli.available()) return got;
    int n = cli.read(rbuf + rlen, want - rlen);
    if (n <= 0) return got;
    rlen += n;
    if (rlen < want || rlen < 4) continue;
    int len = want - 2;
    stR++; got++;
    uint16_t wid = (rbuf[2] << 8) | rbuf[3];
    Slot* s = nullptr;
    for (auto& sl : slots) if (!sl.busy) { s = &sl; break; }
    if (s) {                                   // slot index + gen are carried in the wire id
      memcpy(s->data, rbuf + 2, len); s->len = len; s->slot = wid >> 8; s->gen = wid & 0xFF; s->busy = true;
      if (tcpip_callback(deliverCb, s) != ERR_OK) { s->busy = false; stDrop++; }
    } else stDrop++;
    rlen = 0;
  }
  return got;
}

// Shortest legal query — root NS, id 0xFFFF so dotDeliver drops the answer (slot
// 0xFF is past MAX_PEND). 19 bytes on the wire: 2 length + 12 header + 5 question.
static void sendKeepalive() {
  static const uint8_t ka[] = {0, 17, 0xFF, 0xFF, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1};
  cli.write(ka, sizeof(ka));
}

// Header and body in one write so they share a TLS record (and a TCP segment).
// Returns false only when the link broke; a query that waited out its usefulness
// is skipped, since the engine has already answered that client over UDP.
static bool sendQuery(DotReq& r) {
  if (nowMs() - r.t > 1200) return true;
  r.msg[0] = r.slot; r.msg[1] = r.gen;         // wire id = slot<<8 | gen, so a reply finds its slot
  uint8_t frame[2 + sizeof(DotReq::msg)];
  frame[0] = r.len >> 8; frame[1] = (uint8_t)r.len;
  memcpy(frame + 2, r.msg, r.len);
  // A short write means the send buffer is full, not that the link is gone —
  // treating it as an error tore the connection down (and paid a 1.6 s handshake)
  // every time queries arrived faster than the socket drained.
  size_t total = r.len + 2, off = 0;
  uint32_t deadline = nowMs() + 1000;
  while (off < total) {
    int w = cli.write(frame + off, total - off);
    if (w > 0) { off += w; continue; }
    if (!cli.connected() || nowMs() > deadline) { closeLink("send stalled"); return false; }
    vTaskDelay(1);
  }
  stQ++;
  return true;
}

static void dotTask(void*) {
  uint32_t lastSend = 0, failedAt = 0;
  int fails = 0;
  for (;;) {
    bool warm = nowMs() - lastClientMs < WARM_MS;
    if (!cli.connected()) {
      if (up) {
        up = false;
        // Reconnecting costs ~1.6 s here (software ECDSA P-384), far longer than
        // the engine's 350 ms fallback timer, so every query in that window ends
        // up on UDP regardless. Saying so immediately removes the 350 ms each of
        // them would otherwise wait first; the privacy outcome is unchanged.
        linkDown = true;
        if (stopReason) Serial.printf("[dot] link closed by us: %s\n", stopReason);
        else Serial.println("[dot] link closed by the resolver");
        stopReason = nullptr;
      }
      bool backoff = fails >= MAX_FAILS && nowMs() - failedAt < BACKOFF_MS;
      if (WiFi.status() == WL_CONNECTED && warm && !backoff) {
        if (connectDot()) { up = true; linkDown = false; fails = 0; lastSend = nowMs(); }
        else { stF++; fails++; failedAt = nowMs(); linkDown = true; Serial.printf("[dot] connect failed (%d)\n", fails); }
      }
      // Queued queries are deliberately NOT discarded here: the engine retries
      // them over UDP after 350 ms, so the client is served either way, and
      // anything still fresh when the link comes up goes out encrypted. Dropping
      // the queue instead made every miss during a 30 s backoff time out.
      if (!up) { vTaskDelay(pdMS_TO_TICKS(250)); continue; }
    }

    // Drain the whole queue into the pipeline before waiting on anything: one
    // query per iteration meant a 32-query burst trickled out a tick at a time.
    // Then poll hard for 2 s after the last send (a reply is due within one
    // upstream RTT) and idle on the queue after that. Replies are matched by id,
    // so they may come back in any order.
    DotReq r;
    bool sent = false, dead = false;
    while (!dead && xQueueReceive(dotQ, &r, 0) == pdTRUE) {
      if (!sendQuery(r)) { dead = true; break; }
      sent = true;
    }
    if (dead) continue;
    if (sent) lastSend = nowMs();
    else if (xQueueReceive(dotQ, &r, pdMS_TO_TICKS(nowMs() - lastSend < 2000 ? 1 : 100)) == pdTRUE) {
      if (!sendQuery(r)) continue;
      lastSend = nowMs();
    }
    drainReplies();

    if (nowMs() - lastSend > KEEPALIVE_MS) {
      if (warm) { sendKeepalive(); lastSend = nowMs(); }
      else { closeLink(nullptr); }             // nobody is using DNS: let it go, reconnect on demand
    }
  }
}

void dotInit() {
  dotQ = xQueueCreate(QDEPTH, sizeof(DotReq));
  // The C3 is single-core, and FreeRTOS asserts xCoreID < 1 there (the string is
  // in libfreertos.a, with assertions compiled in), so pinning to core 1 aborts
  // at boot. Decide from configNUMBER_OF_CORES, which FreeRTOS.h always defines
  // — and note the test is "> 1", so if it ever stopped being visible the build
  // would fall to the unpinned call, which is correct everywhere, rather than to
  // a pin that bricks a single-core board.
#if configNUMBER_OF_CORES > 1
  xTaskCreatePinnedToCore(dotTask, "dot", 8192, nullptr, 6, nullptr, 1);
#else
  xTaskCreate(dotTask, "dot", 8192, nullptr, 6, nullptr);
#endif
}
