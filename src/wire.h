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
