// C3 AdBlock — DNS sinkhole + web dashboard (ESP32-C3 / ESP32-S3).
// DNS engine (filtering, answer cache, forwarding) lives in dns.cpp; this file is
// the web UI, persistence, provisioning and per-client bookkeeping.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)
#include "lcd.h"       // ST7789 status display (Waveshare 1.47 board)
#include "dns.h"

// ---- config ----
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";

// ---- globals ----
WebServer web(80);

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; String mdns; uint8_t mdnsTried; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

// manual per-device names, keyed by MAC (survives DHCP address changes)
static const int MAX_LABELS = 96;
struct LabelRec { String mac, name; };
static LabelRec labels[MAX_LABELS]; static int numLabels = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = dnsHash(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
  dnsSetCustom(customHash, numCustom);
}
static void saveCustom() { dnsSetCustom(customHash, numCustom); File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = dnsHash(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
  dnsSetBanned(bannedIP, numBanned);
}
// bannedIP[] is the source of truth (rebuilding it from clients[] dropped bans for
// devices that hadn't queried yet this boot).
static void saveBanned() {
  dnsSetBanned(bannedIP, numBanned);
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- device labels (manual names, MAC-keyed) ----------
static void loadLabels() {
  numLabels = 0; File f = LittleFS.open("/labels.txt", "r"); if (!f) return;
  while (f.available() && numLabels < MAX_LABELS) {
    String l = f.readStringUntil('\n'); l.trim();
    int eq = l.indexOf('='); if (eq != 17) continue;          // 17 = "aa:bb:cc:dd:ee:ff"
    String mac = l.substring(0, eq), nm = l.substring(eq + 1); nm.trim();
    mac.toLowerCase(); if (nm.length()) { labels[numLabels].mac = mac; labels[numLabels].name = nm; numLabels++; }
  }
  f.close();
}
static void saveLabels() {
  File f = LittleFS.open("/labels.txt", "w"); if (!f) return;
  for (int i = 0; i < numLabels; i++) f.println(labels[i].mac + "=" + labels[i].name);
  f.close();
}
static String getLabel(const String& mac) {
  for (int i = 0; i < numLabels; i++) if (labels[i].mac == mac) return labels[i].name;
  return "";
}
static void setLabel(const String& mac, const String& name) {   // name "" = remove
  String m = mac; m.toLowerCase();
  int hit = -1; for (int i = 0; i < numLabels && hit < 0; i++) if (labels[i].mac == m) hit = i;
  if (!name.length()) { if (hit >= 0) { labels[hit] = labels[numLabels - 1]; numLabels--; } }
  else if (hit >= 0) labels[hit].name = name;
  else if (numLabels < MAX_LABELS) { labels[numLabels].mac = m; labels[numLabels].name = name; numLabels++; }
  saveLabels();
}

// ---------- client table ----------
static String macStr(const uint8_t* m);
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = ""; c->mdns = ""; c->mdnsTried = 0;
    getMac(ip, c->mac);
    c->label = getLabel(macStr(c->mac));      // manual name survives IP changes
    return c;
  }
  return nullptr;
}

// ---------- mDNS reverse lookup (PTR -> hostname for new clients) ----------
// Queries 224.0.0.251:5353 from an ephemeral port (legacy unicast mDNS), so no
// multicast membership is needed and we don't collide with MDNS.begin()'s socket
// on 5353. One client at a time, 2 s deadline, one attempt per client per boot —
// all non-blocking for the DNS hot path.
static WiFiUDP mdnsCli;
static Dev* mdnsTarget = nullptr;
static uint32_t mdnsSentAt = 0;
static char mdnsQName[32];                       // "d.c.b.a.in-addr.arpa"
static bool mdnsUp = false;

static bool mdnsBegin() {
  mdnsUp = mdnsCli.begin(5354);                  // ephemeral: legacy queries get unicasted back
  if (!mdnsUp) Serial.println("[mdns] reverse lookup socket failed");
  return mdnsUp;
}
// Parse a DNS-format name (with compression pointers) starting at *pos.
static bool parseDnsName(const uint8_t* p, int len, int* pos, char* out, int outCap) {
  int o = 0, jumps = 0, save = -1, i = *pos;
  while (jumps++ < 8) {
    if (i >= len) return false;
    uint8_t l = p[i];
    if ((l & 0xC0) == 0xC0) { if (i + 1 >= len) return false; if (save < 0) save = i + 2; i = ((l & 0x3F) << 8) | p[i + 1]; continue; }
    i++;
    if (l == 0) break;
    if (i + l > len || o + l + 1 >= outCap) return false;
    if (o) out[o++] = '.';
    memcpy(out + o, p + i, l); o += l; i += l;
  }
  out[o] = 0; *pos = save >= 0 ? save : i;
  return true;
}
static void sendPtrQuery(Dev* c) {
  IPAddress ip(c->ip);
  uint8_t qp[64]; int o = 12;                          // 12-byte DNS header, written below
  qp[0] = 0; qp[1] = 0; qp[2] = 0; qp[3] = 0;          // id 0, flags 0
  qp[4] = 0; qp[5] = 1; qp[6] = 0; qp[7] = 0; qp[8] = 0; qp[9] = 0; qp[10] = 0; qp[11] = 0;  // qd=1, rest 0
  uint8_t oct[4] = { ip[3], ip[2], ip[1], ip[0] };     // reversed octets
  for (int k = 0; k < 4; k++) {
    char t[4]; int n = snprintf(t, sizeof(t), "%u", oct[k]);
    qp[o++] = (uint8_t)n; memcpy(qp + o, t, n); o += n;
  }
  memcpy(qp + o, "\7in-addr\4arpa", 13); o += 13; qp[o++] = 0;
  qp[o++] = 0; qp[o++] = 12;                       // QTYPE = PTR
  qp[o++] = 0; qp[o++] = 1;                        // QCLASS = IN
  snprintf(mdnsQName, sizeof(mdnsQName), "%u.%u.%u.%u.in-addr.arpa", oct[0], oct[1], oct[2], oct[3]);
  mdnsCli.flush();
  mdnsCli.beginPacket(IPAddress(224, 0, 0, 251), 5353);
  mdnsCli.write(qp, o);
  mdnsCli.endPacket();
  mdnsTarget = c; mdnsSentAt = millis();
}
// Returns true and fills `host` if the reply is a PTR answer to our question.
static bool parsePtrReply(const uint8_t* p, int len, char* host, int cap) {
  if (len < 12) return false;
  int i = 12, qd = (p[4] << 8) | p[5];
  char qn[32]; qn[0] = 0;
  for (int k = 0; k < qd; k++) {
    if (!parseDnsName(p, len, &i, qn, sizeof(qn))) return false;
    i += 4;
  }
  if (strcmp(qn, mdnsQName) != 0) return false;
  int an = (p[6] << 8) | p[7];
  for (int k = 0; k < an; k++) {
    char throwName[32];
    if (!parseDnsName(p, len, &i, throwName, sizeof(throwName))) return false;
    if (i + 10 > len) return false;
    uint16_t type = (p[i] << 8) | p[i + 1]; int rdlen = (p[i + 8] << 8) | p[i + 9]; i += 10;
    if (type == 12 && rdlen > 0 && i + rdlen <= len) {
      int r = i;                                   // rdata is another domain name
      if (!parseDnsName(p, len, &r, host, cap)) return false;
      return true;
    }
    i += rdlen;
  }
  return false;
}
static void mdnsTick() {
  if (!mdnsUp) return;
  if (mdnsTarget) {
    int sz = mdnsCli.parsePacket();
    if (sz > 0) {
      static uint8_t mbuf[512];
      int n = mdnsCli.read(mbuf, sizeof(mbuf)); mdnsCli.flush();
      Dev* t = mdnsTarget; mdnsTarget = nullptr; if (t) t->mdnsTried = 1;
      char host[33];
      if (n > 0 && parsePtrReply(mbuf, n, host, sizeof(host))) {
        String h(host);
        if (h.endsWith(".local")) h = h.substring(0, h.length() - 6);   // "MacBook-Pro.local" -> cleaner
        h.trim();
        if (h.length()) { t->mdns = h; Serial.printf("[mdns] %s -> %s\n", IPAddress(t->ip).toString().c_str(), h.c_str()); }
      }
    } else if (millis() - mdnsSentAt > 2000) {
      Dev* t = mdnsTarget; mdnsTarget = nullptr; if (t) t->mdnsTried = 1;
    }
    return;
  }
  for (int i = 0; i < numClients; i++)
    if (!clients[i].mdnsTried && WiFi.status() == WL_CONNECTED) { sendPtrQuery(&clients[i]); return; }
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
// Control chars must be \u-escaped too: mDNS names come from any LAN host, and a
// raw 0x0A in one would break JSON.parse for the whole dashboard.
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 2);
  for (char ch : s) {
    if ((uint8_t)ch < 0x20) { char u[7]; snprintf(u, sizeof(u), "\\u%04x", (uint8_t)ch); o += u; continue; }
    if (ch == '"' || ch == '\\') o += '\\';
    o += ch;
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  DnsStats ds = dnsStats();
  String j; j.reserve(512 + numClients * 170 + numCustom * 48);   // one allocation, not ~700 reallocs
  j += "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + ds.blocked + ",\"allowed\":" + ds.allowed + ",\"chits\":" + ds.cacheHits +
             ",\"dot\":" + (ds.dotUp ? "true" : "false") + ",\"dotq\":" + ds.dotQueries +
             ",\"doths\":" + ds.dotHandshakes + ",\"dothsms\":" + ds.dotHsMs +
             ",\"lost\":" + ds.upstreamLost + ",\"dotdrop\":" + ds.dotDropped + ",\"txfailreply\":" + ds.txFailedReply + ",\"txfailquery\":" + ds.txFailedQuery +
             ",\"domains\":" + dnsBlocklistCount() + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"psram\":" + ESP.getFreePsram() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    const char* src = c.label.length() ? "man" : (c.mdns.length() ? "mdns" : "ip");
    String nm = c.label.length() ? c.label : (c.mdns.length() ? c.mdns : "");
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + ",\"name\":\"" + jesc(nm) + "\",\"src\":\"" + src + "\"}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip;
  if (ip.fromString(web.arg("ip"))) {
    uint32_t a = (uint32_t)ip; int i = 0;
    while (i < numBanned && bannedIP[i] != a) i++;
    if (i < numBanned) bannedIP[i] = bannedIP[--numBanned];          // unban
    else if (numBanned < MAX_BAN) bannedIP[numBanned++] = a;         // ban
    saveBanned();
    Dev* c = getClient(a); if (c) c->banned = isBannedIP(a);
  }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// With PSRAM the new list goes to /blocklist.new and is swapped in only once it
// validates (size, sort order): the live list keeps filtering the whole time.
// Without PSRAM (C3: the 1.3 MB FS holds one list) the old file has to go first.
static void beginBlocklistSwap() {
  LittleFS.remove("/blocklist.new");
  if (!dnsUsesPsram()) { dnsUnloadBlocklist(); LittleFS.remove(BLOCKLIST_PATH); }
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  if (!dnsUsesPsram()) return LittleFS.rename("/blocklist.new", BLOCKLIST_PATH) && dnsLoadBlocklist(BLOCKLIST_PATH);
  bool ok = dnsLoadBlocklist("/blocklist.new");
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  return ok;
}
static void abortBlocklistSwap() {                  // transfer failed midway
  LittleFS.remove("/blocklist.new");
  if (!dnsUsesPsram()) dnsLoadBlocklist(BLOCKLIST_PATH);
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: not a blocklist.bin — it must be sorted 5-byte "
                         "hashes (build one with tools/build_blocklist.py), or point "
                         "Remote auto-update at a text list instead");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", dnsBlocklistCount());
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      abortBlocklistSwap();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
// Third line is the last fetch result. Without it the dashboard said "never" after
// every reboot, which reads as "auto-update has never run" — the exact thing you
// check when you suspect it is broken.
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  String st = f.readStringUntil('\n'); st.trim(); if (st.length()) updateStatus = st;
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.println(updateStatus); f.close();
}
// A .bin URL is a prebuilt hash blob and goes to flash; anything else is treated as
// a text source (hosts / AdGuard syntax) and is hashed straight into PSRAM as it
// streams, so the box can point at an upstream list directly — nothing to prebuild,
// nothing multi-MB written to flash. Several URLs may be given, separated by spaces;
// they merge into one list.
static bool fetchOne(String url, bool textMode, size_t* total) {
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // a public blocklist needs no pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  File f;
  if (!textMode) {
    f = LittleFS.open("/blocklist.new", "w");
    if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
  }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); static uint8_t b[1460]; size_t got = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)got < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) { if (textMode) dnsTextFeed(b, n); else f.write(b, n); got += n; idle = millis(); }
    } else { if (millis() - idle > 15000) break; delay(2); }
  }
  if (f) f.close();
  http.end();
  *total += got;
  if (len >= 0 && (int)got != len) { updateStatus = "incomplete (" + String(got) + "B)"; return false; }
  return true;
}

static bool fetchBlocklist(String urls) {
  urls.trim(); if (!urls.length()) { updateStatus = "no url set"; return false; }
  const bool textMode = dnsUsesPsram() && !urls.endsWith(".bin");
  if (textMode && !dnsTextBegin()) { updateStatus = "no memory for list build"; return false; }
  if (!textMode) beginBlocklistSwap();

  size_t total = 0; bool ok = true;
  for (int i = 0; ok && i < urls.length(); ) {      // space-separated list of sources
    while (i < urls.length() && urls[i] == ' ') i++;
    int sp = urls.indexOf(' ', i); if (sp < 0) sp = urls.length();
    if (sp > i) ok = fetchOne(urls.substring(i, sp), textMode, &total);
    i = sp;
  }

  if (textMode) {
    uint32_t parsed = dnsTextCount();
    ok = ok && dnsTextCommit();
    if (!ok) dnsTextAbort();
    if (ok && !dnsSaveBlocklist(BLOCKLIST_PATH))   // live either way, just not across a reboot
      Serial.println("[remote] built list could not be saved to flash");
    updateStatus = ok ? ("ok: " + String(dnsBlocklistCount()) + " domains")
                      : ("failed after " + String(parsed) + " domains / " + String(total / 1024) + "KB");
  } else {
    ok = ok && commitNewBlocklist();
    if (!ok) abortBlocklistSwap();
    updateStatus = ok ? ("ok: " + String(dnsBlocklistCount()) + " domains")
                      : ("bad data (" + String(total) + "B)");
  }
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  saveUpdateCfg();                                 // remember the result across a reboot
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
#ifdef STATIC_IP
  // Optional static IP (defined in secrets.h): clients point their DNS at this address,
  // so it must not drift across reboots. Skipped silently when not defined (DHCP).
  {
    // STATIC_IP may be a quoted string ("192.168.1.50"); Arduino IPAddress has no
    // string constructor on all cores, so parse octets manually.
    #define IP_OCTET(s, i) ((uint8_t)atoi(s))
    const char* sip = STATIC_IP;
    const char* sgw = STATIC_GW;
    const char* smask = STATIC_MASK;
    uint8_t o1, o2, o3, o4;
    auto parseIP = [](const char* s, uint8_t* out) {
      char tmp[16]; strncpy(tmp, s, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
      int idx = 0; char* p = tmp;
      while (*p && idx < 4) { out[idx++] = (uint8_t)atoi(p); while (*p && *p != '.') p++; if (*p) p++; }
    };
    uint8_t ipb[4], gwb[4], mb[4];
    parseIP(sip, ipb); parseIP(sgw, gwb); parseIP(smask, mb);
    IPAddress lip(ipb), lgw(gwb), lmask(mb);
    // The 3-argument form leaves the resolver at 0.0.0.0, so the device itself
    // could not look up a hostname: every blocklist auto-update failed with
    // "DNS Failed ... error -54" for as long as a static IP was configured.
    // Resolve through our own upstream, with the router as a fallback.
    const IPAddress dns1(UPSTREAM_IP), dns2 = lgw;
    if (!WiFi.config(lip, lgw, lmask, dns1, dns2)) Serial.println("[setup] static IP config FAILED, falling back to DHCP");
  }
#endif
  WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>adblocker.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap, AP_PORTAL_PASS);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  dnsInit();
  if (dnsLoadBlocklist(BLOCKLIST_PATH))
    Serial.printf("blocklist: %u domains%s\n", dnsBlocklistCount(), dnsUsesPsram() ? " (PSRAM)" : "");
  else Serial.println("blocklist: missing or invalid -> forwarding everything");
  loadCustom(); loadBanned(); loadLabels(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d, labels: %d\n", numCustom, numBanned, numLabels);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("adblocker")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://adblocker.local"); }
  mdnsBegin();   // reverse-lookup socket for client hostnames (independent of MDNS's 5353)

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsStart(DNS_PORT);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/label", []() {                    // /label?mac=aa:bb:..&n=name (n empty = clear)
    if (!requireAuth()) return;
    String mac = web.arg("mac"), n = web.arg("n"); mac.trim(); mac.toLowerCase(); n.trim();
    if (n.length() > 32) n = n.substring(0, 32);
    if (mac.length() == 17) {
      setLabel(mac, n);
      for (int i = 0; i < numClients; i++) if (macStr(clients[i].mac) == mac) { clients[i].label = n; break; }
    }
    web.send(200, "text/plain", "ok");
  });
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    if (s > 7L * 86400) s = 7L * 86400;      // keeps s*1000 inside uint32 millis
    blockingOn = false; dnsSetBlocking(false); resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; dnsSetBlocking(true); resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { long h = web.arg("h").toInt(); updateIntervalH = h < 1 ? 1 : h > 720 ? 720 : h; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("adblocker");   // pio run -t upload --upload-port adblocker.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  lcdInit();
  lcdUpdate(dnsStats().blocked, dnsStats().allowed, dnsBlocklistCount(), WiFi.RSSI());
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  for (DnsEvent e; dnsPollEvent(&e); ) {   // per-client counters, fed by the DNS task
    Dev* c = getClient(e.ip); if (c) { if (e.blocked) c->blocked++; else c->allowed++; }
  }
  mdnsTick();                             // async PTR lookups for client hostnames
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; dnsSetBlocking(true); resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  lcdButtonPoll();                        // BOOT press wakes the screen
  static uint32_t lastLcd = 0;
  if (millis() - lastLcd > 1000) {        // 1 Hz — only when a value changed does SPI fire
    lastLcd = millis();
    lcdUpdate(dnsStats().blocked, dnsStats().allowed, dnsBlocklistCount(), WiFi.RSSI());
  }
  delay(2);              // DNS runs in its own task; this loop only serves UI/OTA/upkeep
}
