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
static const int      QDEPTH      = 24;

struct DotReq { uint16_t slot, gen, len; uint8_t msg[512]; };
static QueueHandle_t dotQ;

static volatile bool up = false;
static volatile uint32_t lastClientMs = 0;
static volatile uint32_t stQ = 0, stR = 0, stF = 0, stHs = 0, stHsMs = 0;

static inline uint32_t nowMs() { return (uint32_t)(esp_timer_get_time() / 1000); }

void dotNoteClient() { lastClientMs = nowMs(); }
bool dotReady() { return up || (nowMs() - lastClientMs < WARM_MS); }   // willing to connect on demand
DotStats dotStats() { return { stQ, stR, stF, stHs, stHsMs, up }; }

bool dotSubmit(uint16_t slot, uint16_t gen, const uint8_t* msg, uint16_t len) {
  if (!dotQ || len > sizeof(DotReq::msg)) return false;
  DotReq r; r.slot = slot; r.gen = gen; r.len = len; memcpy(r.msg, msg, len);
  return xQueueSend(dotQ, &r, 0) == pdTRUE;
}

// ---------- task ----------
struct Slot { uint8_t data[1536]; int len; uint16_t slot, gen; volatile bool busy; };
static Slot slots[6];
static void deliverCb(void* arg) {
  Slot* s = (Slot*)arg;
  dotDeliver(s->slot, s->gen, s->data, s->len);
  s->busy = false;
}

static NetworkClientSecure cli;
static uint8_t rbuf[2 + 1536];
static int rlen = 0;                           // bytes of the current framed reply held in rbuf

static bool connectDot() {
  static const uint8_t a1[] = {DOT_IP}, a2[] = {DOT_IP2};
  const bool alt = (stF & 1);                  // alternate servers across retries
  IPAddress ip = alt ? IPAddress(a2[0], a2[1], a2[2], a2[3]) : IPAddress(a1[0], a1[1], a1[2], a1[3]);
  cli.setHandshakeTimeout(12);
  cli.setTimeout(5);
  uint32_t t0 = nowMs();
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
    if (want > (int)sizeof(rbuf)) { cli.stop(); return got; }      // desync: drop the link
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
      if (tcpip_callback(deliverCb, s) != ERR_OK) s->busy = false;
    }
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

static void dotTask(void*) {
  uint32_t lastSend = 0, failedAt = 0;
  int fails = 0;
  for (;;) {
    bool warm = nowMs() - lastClientMs < WARM_MS;
    if (!cli.connected()) {
      if (up) { up = false; Serial.println("[dot] link closed"); }
      bool backoff = fails >= MAX_FAILS && nowMs() - failedAt < BACKOFF_MS;
      if (WiFi.status() == WL_CONNECTED && warm && !backoff) {
        if (connectDot()) { up = true; fails = 0; lastSend = nowMs(); }
        else { stF++; fails++; failedAt = nowMs(); Serial.printf("[dot] connect failed (%d)\n", fails); }
      }
      if (!up) { xQueueReset(dotQ); vTaskDelay(pdMS_TO_TICKS(250)); continue; }
    }

    // Poll hard for 2 s after each send (a reply is due within one upstream RTT),
    // then idle on the queue. Replies are matched by id, so order doesn't matter.
    DotReq r;
    bool busy = nowMs() - lastSend < 2000;
    if (xQueueReceive(dotQ, &r, pdMS_TO_TICKS(busy ? 1 : 100)) == pdTRUE) {
      r.msg[0] = r.slot; r.msg[1] = r.gen;     // wire id = slot<<8 | gen, so a reply finds its slot
      uint8_t hdr[2] = { (uint8_t)(r.len >> 8), (uint8_t)r.len };
      if (cli.write(hdr, 2) != 2 || cli.write(r.msg, r.len) != r.len) { cli.stop(); continue; }
      stQ++; lastSend = nowMs();
    }
    drainReplies();

    if (nowMs() - lastSend > KEEPALIVE_MS) {
      if (warm) { sendKeepalive(); lastSend = nowMs(); }
      else { cli.stop(); }                     // nobody is using DNS: let it go, reconnect on demand
    }
  }
}

void dotInit() {
  dotQ = xQueueCreate(QDEPTH, sizeof(DotReq));
  xTaskCreatePinnedToCore(dotTask, "dot", 8192, nullptr, 6, nullptr, 1);
}
