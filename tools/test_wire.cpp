// Host tests for src/wire.h — the parsing and matching logic the firmware shares
// across every target. Build and run anywhere:
//
//   c++ -std=c++17 -I src -o /tmp/test_wire tools/test_wire.cpp && /tmp/test_wire
//
// These cover what is awkward to produce against a real device: names at the
// 255-byte limit, label lengths the format forbids, compression pointers and
// loops, record counts that lie about what follows, TTL boundaries, and every
// blocklist line syntax. One copy of the code, so one run covers all targets.
#include "wire.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;
static void check(bool ok, const char* what) {
  printf("  %s  %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) failures++;
}

// A query packet: header, one question, optional trailing bytes.
static std::vector<uint8_t> query(const std::string& name, uint16_t qtype = 1,
                                  uint16_t qdcount = 1) {
  std::vector<uint8_t> p = {0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
  p[4] = (uint8_t)(qdcount >> 8); p[5] = (uint8_t)(qdcount & 0xFF);
  size_t start = 0;
  while (start <= name.size()) {
    size_t dot = name.find('.', start);
    std::string label = name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    p.push_back((uint8_t)label.size());
    p.insert(p.end(), label.begin(), label.end());
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  p.push_back(0);
  p.push_back((uint8_t)(qtype >> 8)); p.push_back((uint8_t)(qtype & 0xFF));
  p.push_back(0); p.push_back(1);
  return p;
}

static void test_hash() {
  puts("hash");
  // Pinned against tools/build_blocklist.py: a divergence here silently stops the
  // firmware matching lists that tool produces.
  check(wire::hash("doubleclick.net", 15) == 0xcd127775cdULL, "doubleclick.net matches the builder");
  check(wire::hash("googlesyndication.com", 21) == 0xf2167bff62ULL, "googlesyndication.com matches the builder");
  check(wire::hash("a", 1) != wire::hash("b", 1), "different input, different hash");
  uint8_t packed[5];
  wire::pack5(0xcd127775cdULL, packed);
  check(wire::unpack5(packed) == 0xcd127775cdULL, "pack5 and unpack5 round-trip");
  check(wire::hash("x", 1) <= wire::HASH_MASK, "stays inside 40 bits");
}

static void test_skip_name() {
  puts("skipName");
  uint8_t p[] = {3,'a','b','c',3,'c','o','m',0};
  check(wire::skipName(p, sizeof(p), 0) == 9, "steps over a two-label name");
  uint8_t ptr[] = {0xC0, 0x0C};
  check(wire::skipName(ptr, 2, 0) == 2, "a pointer is two bytes");
  check(wire::skipName(ptr, 1, 0) == -1, "a pointer needs both bytes");
  uint8_t runon[] = {5,'a','b'};
  check(wire::skipName(runon, sizeof(runon), 0) == -1, "refuses a label running past the end");
  uint8_t reserved[] = {0x40, 0};
  check(wire::skipName(reserved, sizeof(reserved), 0) == -1, "refuses reserved length bits");
}

static void test_parse_question() {
  puts("parseQuestion");
  char out[256]; uint16_t qt = 0, qc = 0; int qend = 0;
  auto p = query("ExAmPlE.CoM");
  int n = wire::parseQuestion(p.data(), (int)p.size(), out, &qt, &qc, &qend);
  check(n == 11 && strcmp(out, "example.com") == 0, "lowercases the name");
  check(qt == 1 && qc == 1 && qend == (int)p.size(), "reports qtype, qclass and the end offset");

  p = query("a.b.c.d.example.com", 28);
  n = wire::parseQuestion(p.data(), (int)p.size(), out, &qt, &qc, &qend);
  check(n == 19 && qt == 28, "handles many labels and a non-A qtype");

  std::string longest(63, 'a');                       // 4 x 63 + 3 dots = 255
  std::string name = longest + "." + longest + "." + longest + "." + longest;
  p = query(name);
  check(wire::parseQuestion(p.data(), (int)p.size(), out, &qt, &qc, &qend) == -1,
        "refuses a name at the 255-byte limit rather than overrun its buffer");

  p = query("example.com");
  check(wire::parseQuestion(p.data(), 16, out, &qt, &qc, &qend) == -1, "refuses a truncated packet");
  check(wire::parseQuestion(p.data(), 0, out, &qt, &qc, &qend) == -1, "refuses an empty packet");

  p = query("example.com", 1, 2);
  check(wire::parseQuestion(p.data(), (int)p.size(), out, &qt, &qc, &qend) == -1, "refuses qdcount 2");
  p = query("example.com", 1, 0);
  check(wire::parseQuestion(p.data(), (int)p.size(), out, &qt, &qc, &qend) == -1, "refuses qdcount 0");

  std::vector<uint8_t> bad = {0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0, 0xC0,0x0C, 0,1,0,1};
  check(wire::parseQuestion(bad.data(), (int)bad.size(), out, &qt, &qc, &qend) == -1,
        "refuses a compression pointer in the question");
  bad = {0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0, 64};
  bad.insert(bad.end(), 64, 'a');
  bad.insert(bad.end(), {0, 0,1,0,1});
  check(wire::parseQuestion(bad.data(), (int)bad.size(), out, &qt, &qc, &qend) == -1,
        "refuses label length 64");
  bad = {0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0, 0,0,1,0,1};
  check(wire::parseQuestion(bad.data(), (int)bad.size(), out, &qt, &qc, &qend) == -1,
        "refuses an empty name");
}

// A reply: header, question, then `n` A records with the given TTL.
static std::vector<uint8_t> reply(uint32_t ttl, int n, bool withOpt = false) {
  std::vector<uint8_t> p = query("example.com");
  p[2] = 0x81; p[3] = 0x80;
  p[6] = 0; p[7] = (uint8_t)n;
  if (withOpt) { p[10] = 0; p[11] = 1; }
  for (int k = 0; k < n; k++) {
    uint8_t rr[] = {0xC0, 0x0C, 0, 1, 0, 1,
                    (uint8_t)(ttl >> 24), (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
                    0, 4, 10, 0, 0, (uint8_t)(k + 1)};
    p.insert(p.end(), rr, rr + sizeof(rr));
  }
  if (withOpt) {
    uint8_t opt[] = {0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0};   // OPT, TTL 0, rdlen 0
    p.insert(p.end(), opt, opt + sizeof(opt));
  }
  return p;
}

static void test_walk_ttl() {
  puts("walkTtl");
  auto p = reply(300, 2);
  uint32_t mn = 0;
  check(wire::walkTtl(p.data(), (int)p.size(), 0, &mn) && mn == 300, "finds the TTL");

  check(wire::walkTtl(p.data(), (int)p.size(), 100, nullptr), "ages the records");
  wire::walkTtl(p.data(), (int)p.size(), 0, &mn);
  check(mn == 200, "every TTL came down by the age");

  wire::walkTtl(p.data(), (int)p.size(), 5000, nullptr);
  wire::walkTtl(p.data(), (int)p.size(), 0, &mn);
  check(mn == 0, "an age past the TTL floors it at zero, it does not wrap");

  p = reply(60, 1, true);
  check(wire::walkTtl(p.data(), (int)p.size(), 0, &mn) && mn == 60,
        "ignores the OPT record's TTL, which is not a TTL");

  p = reply(300, 1);
  p[7] = 5;                                        // claims five answers, carries one
  check(!wire::walkTtl(p.data(), (int)p.size(), 0, &mn), "refuses a lying answer count");
  check(!wire::walkTtl(p.data(), 11, 0, &mn), "refuses a packet too short for a header");
  p = reply(300, 1);
  p[p.size() - 6] = 0xFF; p[p.size() - 5] = 0xFF;  // rdlen beyond the packet
  check(!wire::walkTtl(p.data(), (int)p.size(), 0, &mn), "refuses rdata that overruns the packet");
}

static void test_build_query() {
  puts("buildQuery");
  uint8_t q[512];
  int n = wire::buildQuery("example.com", q, sizeof(q), 0x1234);
  check(n == 29, "encodes a two-label name");
  check(q[0] == 0x12 && q[1] == 0x34 && q[2] == 0x01 && q[5] == 1, "header, RD and qdcount");
  check(q[12] == 7 && memcmp(q + 13, "example", 7) == 0 &&
        q[20] == 3 && memcmp(q + 21, "com", 3) == 0 && q[24] == 0, "labels and root");
  check(q[25] == 0 && q[26] == 1 && q[27] == 0 && q[28] == 1, "A/IN question");
  check(wire::buildQuery("example.com.", q, sizeof(q), 1) == 29, "accepts a trailing root dot");
  check(wire::buildQuery("a..b", q, sizeof(q), 1) == 0, "refuses an empty label");
  check(wire::buildQuery("example.com", q, 28, 1) == 0, "refuses a buffer one byte short");
  check(wire::buildQuery("", q, sizeof(q), 1) == 0, "refuses an empty name");
}

static void test_first_a() {
  puts("firstA");
  uint32_t ip = 0; uint8_t rc = 0; bool tc = true;
  auto p = reply(300, 1);
  check(wire::firstA(p.data(), (int)p.size(), &ip, &rc, &tc) && ip == 0x0100000A && rc == 0 && !tc,
        "finds the A record, address and rcode");

  auto nx = query("example.com");
  nx[2] = 0x81; nx[3] = 0x83;
  check(!wire::firstA(nx.data(), (int)nx.size(), &ip, &rc, &tc) && rc == 3, "NXDOMAIN has no A");

  auto cn = query("www.example.com");
  cn[2] = 0x81; cn[3] = 0x80; cn[6] = 0; cn[7] = 2;
  uint8_t cname[] = {0xC0,0x0C, 0,5, 0,1, 0,0,0,60, 0,9, 3,'c','d','n',3,'c','o','m',0};
  cn.insert(cn.end(), cname, cname + sizeof(cname));
  uint8_t arec[] = {0xC0,0x0C, 0,1, 0,1, 0,0,0,60, 0,4, 93,184,216,34};
  cn.insert(cn.end(), arec, arec + sizeof(arec));
  check(wire::firstA(cn.data(), (int)cn.size(), &ip, &rc, &tc) && ip == 0x22D8B85D,
        "skips a CNAME and returns the A that follows");

  auto bad = reply(300, 1);
  bad[bad.size() - 6] = 0xFF; bad[bad.size() - 5] = 0xFF;
  check(!wire::firstA(bad.data(), (int)bad.size(), &ip, &rc, &tc), "refuses rdata that overruns");
  check(!wire::firstA(p.data(), 11, &ip, &rc, &tc), "refuses a packet too short for a header");
}

// A minimal TLS 1.3 ClientHello with one SNI extension, enough to exercise the
// parser without a live handshake.
static std::vector<uint8_t> clientHello(const char* name) {
  size_t n = strlen(name);
  size_t hsLen = 52 + n;
  size_t recLen = 4 + hsLen;
  std::vector<uint8_t> h;
  h.push_back(0x16); h.push_back(0x03); h.push_back(0x01);
  h.push_back((uint8_t)(recLen >> 8)); h.push_back((uint8_t)recLen);
  h.push_back(0x01);
  h.push_back((uint8_t)(hsLen >> 16)); h.push_back((uint8_t)(hsLen >> 8)); h.push_back((uint8_t)hsLen);
  h.push_back(0x03); h.push_back(0x03);
  for (int i = 0; i < 32; i++) h.push_back((uint8_t)i);
  h.push_back(0);
  h.push_back(0); h.push_back(2); h.push_back(0x13); h.push_back(0x01);
  h.push_back(1); h.push_back(0);
  size_t extLen = 5 + n;
  size_t extBlock = 4 + extLen;
  h.push_back((uint8_t)(extBlock >> 8)); h.push_back((uint8_t)extBlock);
  h.push_back(0); h.push_back(0);
  h.push_back((uint8_t)(extLen >> 8)); h.push_back((uint8_t)extLen);
  h.push_back((uint8_t)((3 + n) >> 8)); h.push_back((uint8_t)(3 + n));
  h.push_back(0);
  h.push_back((uint8_t)(n >> 8)); h.push_back((uint8_t)n);
  for (size_t i = 0; i < n; i++) h.push_back((uint8_t)name[i]);
  return h;
}

static void test_tcp_checksum() {
  puts("tcpChecksum");
  uint8_t seg[25] = {0x30,0x39, 0x01,0xbb, 0,0,0,1, 0,0,0,0, 0x50,0x18, 0xff,0xff, 0,0, 0,0,
                     'h','e','l','l','o'};
  uint8_t s[4] = {192,168,1,2}, d[4] = {93,184,216,34};
  uint16_t ck = wire::tcpChecksum(seg, sizeof(seg), s, d);
  check(ck != 0, "computes a checksum");
  seg[16] = (uint8_t)(ck >> 8); seg[17] = (uint8_t)ck;
  check(wire::tcpChecksum(seg, sizeof(seg), s, d) == 0, "the checksum verifies to zero");
}

static void test_find_sni() {
  puts("findSni / fakeHello");
  auto h = clientHello("discord.com");
  int off = 0, n = 0;
  check(wire::findSni(h.data(), (int)h.size(), &off, &n) && off == 61 && n == 11 &&
        memcmp(h.data() + off, "discord.com", 11) == 0, "finds the SNI in a ClientHello");
  uint8_t out[600];
  check(wire::fakeHello(h.data(), (int)h.size(), out, "example.com") &&
        memcmp(out + off, "example.com", 11) == 0 &&
        memcmp(out, h.data(), 61) == 0 &&
        memcmp(out + off + 11, h.data() + off + 11, h.size() - (size_t)(off + 11)) == 0,
        "replaces the name and leaves every other byte alone");
  check(wire::fakeHello(h.data(), (int)h.size(), out, "a") &&
        memcmp(out + off, "aaaaaaaaaaa", 11) == 0, "pads a short decoy to the same length");
  auto no = clientHello("discord.com");
  no[0] = 0x15;
  check(!wire::findSni(no.data(), (int)no.size(), &off, &n), "rejects a non-handshake record");
  auto ext = clientHello("discord.com");
  ext[50] = 0; ext[51] = 0;
  check(!wire::findSni(ext.data(), (int)ext.size(), &off, &n), "a hello without extensions has no SNI");
  check(!wire::findSni(h.data(), 61 + 5, &off, &n), "a cut name is not enough");
  check(!wire::fakeHello(h.data(), 61 + 5, out, "example.com"), "fakeHello says no when the SNI is cut");
}

static void test_name_blocked() {
  puts("nameBlocked");
  const char* listed[] = {"ads.example", "tracker.io"};
  auto in = [&](uint64_t h) {
    for (const char* d : listed) if (wire::hash(d, strlen(d)) == h) return true;
    return false;
  };
  check(wire::nameBlocked("ads.example", 11, in), "the listed name itself");
  check(wire::nameBlocked("deep.sub.ads.example", 20, in), "a subdomain of it");
  check(wire::nameBlocked("www.ads.example", 15, in), "with a www. prefix");
  check(!wire::nameBlocked("example", 7, in), "a bare label is not a match");
  check(!wire::nameBlocked("notads.example", 14, in), "a name that merely ends similarly");
  check(!wire::nameBlocked("ads.example.org", 15, in), "a different TLD");
  check(!wire::nameBlocked("example.com", 11, in), "an unlisted name");
  auto in2 = [&](uint64_t h) { return wire::hash("co.uk", 5) == h; };
  check(wire::nameBlocked("a.b.co.uk", 9, in2), "walks parents down to two labels");
}

static void test_parse_list_line() {
  puts("parseListLine");
  auto one = [](const char* line) -> long long {
    char buf[600]; size_t n = strlen(line);
    memcpy(buf, line, n); buf[n] = 0;
    uint64_t h = 0;
    return wire::parseListLine(buf, (int)n, &h) ? (long long)h : -1;
  };
  long long want = (long long)wire::hash("ads.example.com", 15);
  check(one("||ads.example.com^") == want, "AdGuard syntax");
  check(one("||ads.example.com^$third-party") == want, "AdGuard with modifiers");
  check(one("0.0.0.0 ads.example.com") == want, "hosts syntax");
  check(one("127.0.0.1\tads.example.com") == want, "hosts with a tab and a different IP");
  check(one("ads.example.com") == want, "a bare domain");
  check(one("  ads.example.com  ") == want, "surrounding whitespace");
  check(one("ADS.Example.COM") == want, "mixed case is folded");
  check(one("ads.example.com.") == want, "a trailing root dot is dropped");
  check(one("www.ads.example.com") == want, "a www. prefix is stripped");
  check(one("ads.example.com # comment") == want, "a trailing comment");

  check(one("@@||ads.example.com^") == -1, "an allow rule is skipped");
  check(one("# ads.example.com") == -1, "a comment line");
  check(one("! ads.example.com") == -1, "an AdGuard comment");
  check(one("[Adblock Plus 2.0]") == -1, "a list header");
  check(one("/^ad[0-9]+\\./") == -1, "a regex rule");
  check(one("*.example.com") == -1, "a wildcard");
  check(one("example.com##.ad") == -1, "a cosmetic rule");
  check(one("") == -1, "an empty line");
  check(one("com") == -1, "no dot");
  check(one("a.b") == -1, "shorter than four characters");
  check(one("localhost") == -1, "localhost");
  check(one("192.168.1.1 printer") == -1, "a hosts line for a LAN name with no dot");
  check(one("1.2.3.4 example.com") == -1, "a hosts line whose IP is not a sinkhole");
  std::string toolong(260, 'a');
  check(one((toolong + ".com").c_str()) == -1, "longer than 253 characters");
}

static void test_contains() {
  puts("contains");
  std::vector<uint64_t> hashes;
  for (int i = 0; i < 1000; i++) {
    std::string s = std::to_string(i);
    hashes.push_back(wire::hash(s.c_str(), s.size()));
  }
  std::sort(hashes.begin(), hashes.end());
  hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());
  std::vector<uint8_t> packed(hashes.size() * 5);
  for (size_t i = 0; i < hashes.size(); i++) wire::pack5(hashes[i], &packed[i * 5]);

  bool all = true;
  for (uint64_t h : hashes) all &= wire::contains(packed.data(), (uint32_t)hashes.size(), h);
  check(all, "finds every entry, including the first and last");
  check(!wire::contains(packed.data(), (uint32_t)hashes.size(), 0), "a hash below the range");
  check(!wire::contains(packed.data(), (uint32_t)hashes.size(), wire::HASH_MASK), "a hash above the range");
  check(!wire::contains(packed.data(), 0, hashes[0]), "an empty list matches nothing");
  int misses = 0;
  for (int i = 1000; i < 2000; i++) {
    std::string s = std::to_string(i);
    if (!wire::contains(packed.data(), (uint32_t)hashes.size(), wire::hash(s.c_str(), s.size()))) misses++;
  }
  check(misses == 1000, "reports no false positives over a thousand absent keys");
}

// Random input through every entry point. On its own this only proves nothing
// crashes; built with -fsanitize=address,undefined (as CI does) it proves the
// parser stays inside its buffers and does nothing undefined, which matters most
// here because these bytes arrive from anyone on the network.
static void test_fuzz() {
  puts("fuzz (meaningful under -fsanitize=address,undefined)");
  uint32_t seed = 1;
  auto rnd = [&]() { seed = seed * 1103515245u + 12345u; return (seed >> 16) & 0xFFFF; };
  char name[256]; uint16_t qt, qc; int qend; uint32_t ttl; uint64_t h;
  uint32_t ip; uint8_t rc; bool tc; uint8_t q[512];
  int snioff = 0, snilen = 0; uint8_t fake[600];
  uint8_t cs[4] = {192,168,1,2}, cd[4] = {93,184,216,34};
  for (int iter = 0; iter < 200000; iter++) {
    int len = 1 + (int)(rnd() % 600);
    std::vector<uint8_t> p((size_t)len);
    for (int i = 0; i < len; i++) p[(size_t)i] = (uint8_t)rnd();
    if (iter % 4 == 0 && len > 12) {              // sometimes start from a plausible header
      p[2] = 0x01; p[3] = 0x00; p[4] = 0; p[5] = 1;
      p[6] = 0; p[7] = (uint8_t)(rnd() % 8);
    }
    wire::parseQuestion(p.data(), len, name, &qt, &qc, &qend);
    wire::walkTtl(p.data(), len, rnd() % 1000, &ttl);
    wire::buildQuery(name, q, sizeof(q), (uint16_t)rnd());
    wire::firstA(p.data(), len, &ip, &rc, &tc);
    wire::findSni(p.data(), len, &snioff, &snilen);
    wire::fakeHello(p.data(), len, fake, "example.com");
    wire::tcpChecksum(p.data(), len, cs, cd);
    wire::skipName(p.data(), len, (int)(rnd() % (unsigned)len));
    wire::contains(p.data(), (uint32_t)(len / 5), ((uint64_t)rnd() << 16) | rnd());

    char line[600];                                // the list parser writes in place
    int ll = (int)(rnd() % 550);
    for (int i = 0; i < ll; i++) {
      unsigned r = rnd() % 70;
      line[i] = r < 60 ? (char)("abcdefghijklmnopqrstuvwxyz0123456789.-_|@#!/[]^$ \t:"[r % 51]) : (char)rnd();
    }
    line[ll] = 0;
    wire::parseListLine(line, ll, &h);
  }
  check(true, "200,000 random inputs through every entry point without a fault");
}

int main() {
  test_hash();
  test_skip_name();
  test_parse_question();
  test_walk_ttl();
  test_build_query();
  test_first_a();
  test_find_sni();
  test_tcp_checksum();
  test_name_blocked();
  test_parse_list_line();
  test_contains();
  test_fuzz();
  printf("\n%s\n", failures ? "FAILURES" : "all wire tests passed");
  return failures ? 1 : 0;
}
