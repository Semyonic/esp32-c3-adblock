// diag.cpp — one-shot censorship diagnostic. See diag.h.
//
// The test answers one question: which layer refuses this name? It compares the
// answer a client would get from the LAN's resolver with a DoT answer, then tries
// TCP 443 and a TLS handshake with the name as SNI. It runs in its own task so a
// 1-2 s handshake cannot stall the web server or the DNS engine, and only one
// test runs at a time: a second caller is told the box is busy.
#include "diag.h"
#include "dns.h"
#include "dot.h"
#include "wire.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <NetworkClientSecure.h>
#include <Update.h>
#include <esp_random.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

static const uint32_t DNS_MS = 2000;
static const uint32_t TCP_MS = 3000;
static const uint32_t TLS_S  = 6;

struct Job { char domain[256]; };
static QueueHandle_t jobq;
static SemaphoreHandle_t resMux;
static DiagResult result;
static uint8_t state = DIAG_IDLE;
static bool ready = false;

static inline uint32_t nowMs() { return millis(); }

// Lowercase, strip one trailing root dot, and refuse what the query builder
// cannot encode. The result is what the blocklist and the DNS path use.
static bool normalize(const char* in, char* out, size_t cap) {
  if (!in || !out || cap < 5) return false;
  size_t n = strlen(in);
  while (n && in[n - 1] == '.') n--;
  if (n < 4 || n >= cap || in[0] == '.') return false;
  bool dot = false;
  for (size_t i = 0; i < n; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    if (c >= 'a' && c <= 'z') { out[i] = c; continue; }
    if ((c >= '0' && c <= '9') || c == '-' || c == '_') { out[i] = c; continue; }
    if (c == '.') {
      if (i == 0 || out[i - 1] == '.') return false;
      dot = true; out[i] = c; continue;
    }
    return false;
  }
  out[n] = 0;
  return dot;
}

// One UDP A query. True when a reply with our id arrived; `ip` stays 0 for
// NXDOMAIN/NODATA, and `rcode` carries the DNS code either way.
static bool udpQuery(const IPAddress& server, const char* name, uint16_t id,
                     uint32_t* ip, uint8_t* rcode, bool* tc) {
  WiFiUDP udp;
  if (!udp.begin(0)) return false;
  uint8_t q[512];
  int qlen = wire::buildQuery(name, q, sizeof(q), id);
  if (qlen <= 0) { udp.stop(); return false; }
  if (!udp.beginPacket(server, 53)) { udp.stop(); return false; }
  if (udp.write(q, qlen) != (size_t)qlen || !udp.endPacket()) { udp.stop(); return false; }
  uint8_t r[1536];
  uint32_t t0 = nowMs();
  bool got = false;
  while ((int32_t)(nowMs() - t0) < (int32_t)DNS_MS) {
    int sz = udp.parsePacket();
    if (sz > 0) {
      IPAddress from = udp.remoteIP();
      int n = udp.read(r, sizeof(r));
      if (from == server && n >= 12 && (r[0] << 8 | r[1]) == id &&
          wire::walkTtl(r, n, 0, nullptr)) {
        bool t = false;
        wire::firstA(r, n, ip, rcode, &t);
        if (tc) *tc = t;
        got = true;
        break;
      }
    }
    vTaskDelay(1);
  }
  udp.stop();
  return got;
}

// Reachability, not trust: the certificate is not the question here.
static bool tlsProbe(uint32_t ip, const char* name, uint16_t* ms, char* err, size_t errcap) {
  NetworkClientSecure c;
  c.setInsecure();
  c.setHandshakeTimeout(TLS_S);
  c.setTimeout(4);
  uint32_t t0 = nowMs();
  bool ok = c.connect(IPAddress(ip), 443, name, nullptr, nullptr, nullptr);
  *ms = (uint16_t)(nowMs() - t0);
  if (!ok) {
    char buf[80] = {0};
    int e = c.lastError(buf, sizeof(buf) - 1);
    if (e > 0) { strncpy(err, buf, errcap - 1); err[errcap - 1] = 0; }
    else snprintf(err, errcap, "TLS bağlantısı kurulamadı");
  }
  c.stop();
  return ok;
}

static void runTest(const char* domain, DiagResult* r) {
  memset(r, 0, sizeof(*r));
  strncpy(r->domain, domain, sizeof(r->domain) - 1);
  uint32_t t0 = nowMs();
  r->localBlocked = dnsIsBlocked(domain);

  // Trusted answer: DoT first. Plain Quad9 is only the fallback, and the result
  // says which one answered, because a hijacked port 53 makes that fallback weak.
  uint32_t trusted = 0; uint8_t trc = 0;
  bool trustedOk = dotResolve(domain, &trusted, &trc, 8000);
  r->dotUsed = trustedOk;
  if (!trustedOk) {
    bool tc = false;
    trustedOk = udpQuery(IPAddress(9, 9, 9, 9), domain, (uint16_t)esp_random(), &trusted, &trc, &tc);
  }
  r->trustedIp = trusted; r->trustedRcode = trc; r->trustedAnswered = trustedOk;

  // The LAN resolver is what a client would use, so the gateway comes first.
  IPAddress isp = WiFi.gatewayIP();
  if (isp == IPAddress(0, 0, 0, 0)) isp = WiFi.dnsIP();
  uint32_t ispIp = 0; uint8_t ispRc = 0; bool ispTc = false;
  bool ispOk = isp != IPAddress(0, 0, 0, 0) &&
               udpQuery(isp, domain, (uint16_t)esp_random(), &ispIp, &ispRc, &ispTc);
  r->ispIp = ispIp; r->ispRcode = ispRc; r->ispAnswered = ispOk;
  r->poisoned = ispOk && trustedOk && (ispRc != trc || ispIp != trusted);

  if (trusted) {
    WiFiClient tcp;
    uint32_t c0 = nowMs();
    r->tcpOk = tcp.connect(IPAddress(trusted), 443, TCP_MS) == 1;
    r->tcpMs = (uint16_t)(nowMs() - c0);
    tcp.stop();
    if (r->tcpOk) r->tlsOk = tlsProbe(trusted, domain, &r->tlsMs, r->tlsErr, sizeof(r->tlsErr));
  }

  if (r->localBlocked) {
    strcpy(r->verdict, "local");
    strcpy(r->note, "Cihazın kendi listesinde; sansür değil.");
  } else if (!trustedOk) {
    strcpy(r->verdict, "error");
    strcpy(r->note, "Güvenilir DNS yanıtı yok; DoT ve Quad9 denendi.");
  } else if (!trusted) {
    strcpy(r->verdict, "nodata");
    snprintf(r->note, sizeof(r->note), "A kaydı yok (rcode %u); TCP testi atlandı.", (unsigned)trc);
  } else if (!r->tcpOk) {
    strcpy(r->verdict, "ip");
    if (r->poisoned) strcpy(r->note, "DNS zehirlemesi + IP engeli; TCP 443 açılmadı.");
    else             strcpy(r->note, "TCP 443 açılmadı; IP engeli veya yol yok.");
  } else if (!r->tlsOk) {
    if (r->poisoned) {
      strcpy(r->verdict, "dns+sni");
      strcpy(r->note, "DNS zehirlemesi + SNI/DPI engeli; DNS tek başına yetmez.");
    } else {
      strcpy(r->verdict, "sni");
      strcpy(r->note, "TCP açıldı, TLS düştü; SNI/DPI engeli.");
    }
  } else if (r->poisoned) {
    strcpy(r->verdict, "dns");
    snprintf(r->note, sizeof(r->note), "ISP DNS farklı (rcode %u/%u); TLS geçti, CDN veya DNS zehirlemesi olabilir.",
             (unsigned)ispRc, (unsigned)trc);
  } else {
    strcpy(r->verdict, "clean");
    strcpy(r->note, "DNS, TCP 443 ve TLS SNI temiz.");
  }
  if (!r->dotUsed && trustedOk && r->verdict[0] != 'e') {
    size_t used = strlen(r->note);
    snprintf(r->note + used, sizeof(r->note) - used, " DoT yok, düz Quad9 kullanıldı.");
  }
  if (!r->ispAnswered && r->verdict[0] != 'e') {
    size_t used = strlen(r->note);
    snprintf(r->note + used, sizeof(r->note) - used, " ISP DNS yanıt vermedi.");
  }
  r->totalMs = nowMs() - t0;
}

static void diagTask(void*) {
  Job j;
  for (;;) {
    if (xQueueReceive(jobq, &j, portMAX_DELAY) != pdTRUE) continue;
    DiagResult r;
    if (ESP.getFreeHeap() < 50000 || Update.isRunning()) {
      memset(&r, 0, sizeof(r));
      strncpy(r.domain, j.domain, sizeof(r.domain) - 1);
      strcpy(r.verdict, "error");
      strcpy(r.note, Update.isRunning() ? "OTA sürüyor; test ertelendi." : "Boş heap az; test ertelendi.");
    } else {
      runTest(j.domain, &r);
    }
    xSemaphoreTake(resMux, portMAX_DELAY);
    result = r;
    state = strcmp(r.verdict, "error") == 0 ? DIAG_ERROR : DIAG_DONE;
    xSemaphoreGive(resMux);
  }
}

void diagInit() {
  resMux = xSemaphoreCreateMutex();
  jobq = xQueueCreate(1, sizeof(Job));
  memset(&result, 0, sizeof(result));
  state = DIAG_IDLE;
  if (!resMux || !jobq) return;
#ifdef BOARD_HAS_PSRAM
  if (xTaskCreatePinnedToCoreWithCaps(diagTask, "diag", 8192, nullptr, 1, nullptr, 0,
                                      MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) == pdPASS) ready = true;
#elif configNUMBER_OF_CORES > 1
  if (xTaskCreatePinnedToCore(diagTask, "diag", 8192, nullptr, 1, nullptr, 0) == pdPASS) ready = true;
#else
  if (xTaskCreate(diagTask, "diag", 8192, nullptr, 1, nullptr) == pdPASS) ready = true;
#endif
  if (!ready) state = DIAG_ERROR;
}

int diagStart(const char* domain) {
  if (!ready || !resMux || !jobq) return -1;
  char norm[256];
  if (!normalize(domain, norm, sizeof(norm))) return -1;
  xSemaphoreTake(resMux, portMAX_DELAY);
  if (state == DIAG_RUNNING) { xSemaphoreGive(resMux); return 0; }
  state = DIAG_RUNNING;
  xSemaphoreGive(resMux);
  Job j; memset(&j, 0, sizeof(j));
  strncpy(j.domain, norm, sizeof(j.domain) - 1);
  if (xQueueSend(jobq, &j, 0) != pdTRUE) {
    xSemaphoreTake(resMux, portMAX_DELAY);
    state = DIAG_ERROR;
    xSemaphoreGive(resMux);
    return -1;
  }
  return 1;
}
uint8_t diagGet(DiagResult* out) {
  if (!resMux) return DIAG_ERROR;
  xSemaphoreTake(resMux, portMAX_DELAY);
  if (out) *out = result;
  uint8_t s = state;
  xSemaphoreGive(resMux);
  return s;
}
