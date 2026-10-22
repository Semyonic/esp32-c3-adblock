// wire.h — the parsing and matching logic, with no platform dependencies.
//
// This is the part of the engine that is byte-for-byte identical on every target,
// and the part a malformed packet reaches first. Keeping it free of Arduino, lwIP
// and FreeRTOS means it compiles and runs on a desktop, so tools/test_wire.cpp can
// exercise the cases that are awkward to produce against a real device: names at
// the 255-byte limit, compression-pointer loops, record counts that lie, TTLs at
// the boundaries, and every blocklist line syntax. CI runs those tests for all
// targets at once, because there is only one copy of this code.
#pragma once
#include <stdint.h>
#include <string.h>

namespace wire {

static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// 40-bit FNV-1a, matching tools/build_blocklist.py exactly.
inline uint64_t hash(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
inline uint64_t unpack5(const uint8_t* b) {
  return (uint64_t)b[0] | (uint64_t)b[1] << 8 | (uint64_t)b[2] << 16 |
         (uint64_t)b[3] << 24 | (uint64_t)b[4] << 32;
}
inline void pack5(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) b[k] = (uint8_t)(h >> (8 * k));
}

// Step over one name. Returns the offset after it, or -1 if it runs off the end
// or uses a label length the format does not allow.
inline int skipName(const uint8_t* p, int len, int i) {
  while (i < len) {
    uint8_t l = p[i];
    if (l == 0) return i + 1;
    if ((l & 0xC0) == 0xC0) return i + 2 <= len ? i + 2 : -1;   // pointer: 2 bytes
    if (l & 0xC0) return -1;                                     // reserved bits set
    i += 1 + l;
  }
  return -1;
}

// Smallest TTL over every record except OPT. With age > 0, also subtracts age from
// each of them in place — that is how a cached reply is aged on its way out.
inline bool walkTtl(uint8_t* p, int len, uint32_t age, uint32_t* minTtl) {
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

// A single plain question -> lowercase dotted name. Returns its length, or -1 when
// the packet is not one this engine will inspect (then it is forwarded untouched).
// `out` needs 256 bytes.
inline int parseQuestion(const uint8_t* p, int len, char* out,
                         uint16_t* qtype, uint16_t* qclass, int* qend) {
  if (len < 17 || (p[4] << 8 | p[5]) != 1) return -1;
  int i = 12, o = 0;
  while (i < len) {
    uint8_t l = p[i++];
    if (l == 0) break;
    if (l & 0xC0 || o + l + 1 >= 250 || i + l > len) return -1;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) {
      char c = (char)p[i++];
      out[o++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
  }
  if (i + 4 > len || o == 0) return -1;
  out[o] = 0;
  *qtype = p[i] << 8 | p[i + 1]; *qclass = p[i + 2] << 8 | p[i + 3]; *qend = i + 4;
  return o;
}

// Build one A/IN question with RD set. Returns the packet length, or 0 when the
// name cannot be encoded (empty label, label over 63, or no room in `cap`).
inline int buildQuery(const char* name, uint8_t* out, int cap, uint16_t id) {
  size_t n = strlen(name);
  if (n < 1 || n > 253 || cap < 12 + (int)n + 6) return 0;
  memset(out, 0, 12);
  out[0] = (uint8_t)(id >> 8); out[1] = (uint8_t)id;
  out[2] = 0x01;                                 // RD
  out[5] = 1;                                    // qdcount
  int o = 12;
  const char* s = name;
  for (;;) {
    const char* dot = strchr(s, '.');
    size_t l = dot ? (size_t)(dot - s) : strlen(s);
    if (l == 0 || l > 63) return 0;
    out[o++] = (uint8_t)l;
    memcpy(out + o, s, l); o += (int)l;
    if (!dot) break;
    s = dot + 1;
    if (!*s) break;                              // a trailing root dot
  }
  out[o++] = 0;
  out[o++] = 0; out[o++] = 1;                    // A
  out[o++] = 0; out[o++] = 1;                    // IN
  return o;
}

// The first A record in the answer section. rcode and tc come from the header;
// false means no A (NXDOMAIN, NODATA, truncated or malformed). The address is
// packed the way IPAddress(uint32_t) reads it (first octet in the low byte, the
// same convention as ip4_addr_get_u32), not as a network-order integer.
inline bool firstA(const uint8_t* p, int len, uint32_t* ip, uint8_t* rcode, bool* tc) {
  if (len < 12) return false;
  if (rcode) *rcode = p[3] & 0x0F;
  if (tc) *tc = (p[2] & 0x02) != 0;
  int qd = p[4] << 8 | p[5];
  int an = p[6] << 8 | p[7];
  int i = 12;
  for (int k = 0; k < qd; k++) {
    i = skipName(p, len, i);
    if (i < 0 || i + 4 > len) return false;
    i += 4;
  }
  for (int k = 0; k < an; k++) {
    i = skipName(p, len, i);
    if (i < 0 || i + 10 > len) return false;
    uint16_t type = p[i] << 8 | p[i + 1];
    uint16_t rdlen = p[i + 8] << 8 | p[i + 9];
    if (i + 10 + rdlen > len) return false;
    if (type == 1 && rdlen == 4) {
      if (ip) *ip = (uint32_t)p[i + 10] | (uint32_t)p[i + 11] << 8 |
                    (uint32_t)p[i + 12] << 16 | (uint32_t)p[i + 13] << 24;
      return true;
    }
    i += 10 + rdlen;
  }
  return false;
}

// The SNI host name inside a TLS ClientHello. A TCP segment can stop in the
// middle of the hello, so the parser works with the bytes it has and still
// finds an extension that is complete. Returns false when there is no
// ClientHello, no SNI extension, or the extension is cut.
inline bool findSni(const uint8_t* p, int len, int* off, int* nameLen) {
  if (!p || len < 9 || p[0] != 0x16) return false;
  int recLen = (p[3] << 8) | p[4];
  int end = 5 + recLen;
  if (recLen <= 0 || end > len) end = len;        // partial record: use what arrived
  int i = 5;
  if (i + 4 > end || p[i] != 0x01) return false;
  int hsLen = ((int)p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3];
  int hsEnd = i + 4 + hsLen;
  if (hsEnd > end) hsEnd = end;
  i += 4;
  if (i + 34 > hsEnd) return false;               // version + random
  i += 34;
  int sid = p[i++];
  if (sid > 32 || i + sid > hsEnd) return false;
  i += sid;
  if (i + 2 > hsEnd) return false;
  int cs = (p[i] << 8) | p[i + 1];
  i += 2;
  if (i + cs > hsEnd) return false;
  i += cs;
  if (i + 1 > hsEnd) return false;
  int comp = p[i++];
  if (i + comp > hsEnd) return false;
  i += comp;
  if (i + 2 > hsEnd) return false;
  int extLen = (p[i] << 8) | p[i + 1];
  i += 2;
  int extEnd = i + extLen;
  if (extEnd > hsEnd) extEnd = hsEnd;
  while (i + 4 <= extEnd) {
    int type = (p[i] << 8) | p[i + 1];
    int elen = (p[i + 2] << 8) | p[i + 3];
    i += 4;
    if (i + elen > extEnd) return false;
    if (type == 0x0000) {
      if (elen < 5) return false;
      int listLen = (p[i] << 8) | p[i + 1];
      if (listLen + 2 > elen) return false;
      int j = i + 2;
      if (p[j++] != 0) return false;              // host_name type
      int nl = (p[j] << 8) | p[j + 1];
      j += 2;
      if (nl < 1 || j + nl > i + elen) return false;
      *off = j;
      *nameLen = nl;
      return true;
    }
    i += elen;
  }
  return false;
}

// Copy a ClientHello and replace its SNI with `decoy`, repeated or cut to the
// same length so every length field stays valid. The fake is only ever read by
// a middlebox; the server never sees it (TTL 3).
inline bool fakeHello(const uint8_t* real, int len, uint8_t* out, const char* decoy) {
  int off = 0, n = 0;
  if (!real || !out || !decoy || !findSni(real, len, &off, &n)) return false;
  int d = (int)strlen(decoy);
  if (d < 1) return false;
  memcpy(out, real, (size_t)len);
  for (int i = 0; i < n; i++) out[off + i] = (uint8_t)decoy[i % d];
  return true;
}

// TCP checksum over a header and payload, with the IPv4 pseudo-header. The
// addresses are the four octets in wire order; the result is stored at offset
// 16 as a big-endian value.
inline uint16_t tcpChecksum(const uint8_t* seg, int len, const uint8_t src[4], const uint8_t dst[4]) {
  uint32_t sum = 0;
  sum += (uint16_t)((src[0] << 8) | src[1]);
  sum += (uint16_t)((src[2] << 8) | src[3]);
  sum += (uint16_t)((dst[0] << 8) | dst[1]);
  sum += (uint16_t)((dst[2] << 8) | dst[3]);
  sum += 6;                                       // TCP
  sum += (uint16_t)len;
  for (int i = 0; i + 1 < len; i += 2) sum += (uint16_t)((seg[i] << 8) | seg[i + 1]);
  if (len & 1) sum += (uint16_t)(seg[len - 1] << 8);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)~sum;
}

// Walk a name and each of its parents down to "a.b", calling listed() on the hash
// of each. "www." is stripped first, matching how the lists are built.
template <typename Listed>
inline bool nameBlocked(const char* name, int n, Listed listed) {
  const char* s = name;
  if (n > 4 && memcmp(s, "www.", 4) == 0) { s += 4; n -= 4; }
  const char* end = s + n;
  while (s < end) {
    if (listed(hash(s, end - s))) return true;
    const char* dot = (const char*)memchr(s, '.', end - s); if (!dot) break;
    if (!memchr(dot + 1, '.', end - dot - 1)) break;
    s = dot + 1;
  }
  return false;
}

// One line of a blocklist: hosts ("0.0.0.0 ads.example"), AdGuard ("||ads.example^")
// or a bare domain. Allow rules (@@), comments, regex and anything with a wildcard
// or an out-of-place character are skipped. Writes the hash and returns true when
// the line yields a domain. `line` is modified in place (lowercased, cut).
inline bool parseListLine(char* line, int len, uint64_t* out) {
  char* s = line; s[len] = 0;
  while (*s == ' ' || *s == '\t') s++;
  if (!*s || *s == '#' || *s == '!' || *s == '[' || *s == '/') return false;
  if (s[0] == '@' && s[1] == '@') return false;
  if (s[0] == '|' && s[1] == '|') s += 2;
  else {
    char* sp = strpbrk(s, " \t");
    if (sp) {
      // Only a hosts line when the first column is an address. Treating any
      // whitespace as a hosts separator silently dropped every line with a
      // trailing comment or trailing spaces.
      bool addr = true;
      for (char* q = s; q < sp && addr; q++)
        addr = (*q >= '0' && *q <= '9') || *q == '.' || *q == ':';
      if (addr) {
        bool sink = strncmp(s, "0.0.0.0", 7) == 0 || strncmp(s, "127.0.0.1", 9) == 0 ||
                    strncmp(s, "::", 2) == 0 || strncmp(s, "::1", 3) == 0;
        if (!sink) return false;                  // maps a name to a real address
        s = sp; while (*s == ' ' || *s == '\t') s++;
      }
      // Otherwise the first token is the domain and the cut below ends at the space.
    }
  }
  char* e = s;                                    // cut at the first terminator
  while (*e && *e != '^' && *e != '$' && *e != ' ' && *e != '\t') {
    // A comment has to be separated by whitespace, so a '#' touching the name is
    // element-hiding syntax ("example.com##.ad"). Taking the part before it would
    // sinkhole the whole site, which is the opposite of what that rule asks for.
    if (*e == '#') return false;
    e++;
  }
  *e = 0;
  if (e > s && e[-1] == '.') *--e = 0;
  size_t n = (size_t)(e - s);
  if (n < 4 || n > 253) return false;
  bool dot = false;
  for (char* p = s; *p; p++) {
    char c = (char)(*p | 0x20);                   // lowercase in place
    if (c >= 'a' && c <= 'z') { *p = c; continue; }
    if ((*p >= '0' && *p <= '9') || *p == '-' || *p == '_') continue;
    if (*p == '.') { dot = true; continue; }
    return false;                                 // wildcard, slash, colon...
  }
  if (!dot || strcmp(s, "localhost") == 0) return false;
  if (n > 4 && memcmp(s, "www.", 4) == 0) { s += 4; n -= 4; }
  *out = hash(s, n);
  return true;
}

// Membership in a sorted array of packed 5-byte hashes.
inline bool contains(const uint8_t* data, uint32_t count, uint64_t h) {
  uint32_t lo = 0, hi = count;
  while (lo < hi) {
    uint32_t mid = (lo + hi) >> 1;
    uint64_t v = unpack5(data + (size_t)mid * HASH_BYTES);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid; else return true;
  }
  return false;
}

}  // namespace wire
