// dot.h — DNS-over-TLS upstream (internal to the DNS engine; main.cpp doesn't use it).
//
// Without it, every cache miss leaves the box as plaintext UDP on port 53: the ISP
// sees each name and can rewrite the answer. DoT puts those queries inside TLS to a
// verified resolver, which closes the DNS half of DPI-based filtering.
//
// Runs in its own task (TLS needs a blocking socket and a big stack). It never
// touches the cache or the pending table: replies go back to the lwIP thread
// through dotDeliver(), so that data stays single-threaded.
#pragma once
#include <Arduino.h>

void dotInit();                                            // starts the task; safe before WiFi
bool dotReady();                                           // connected, or willing to connect now
bool dotSubmit(uint16_t slot, uint16_t gen, const uint8_t* msg, uint16_t len);
void dotNoteClient();                                      // a client queried: keep the link warm

struct DotStats { uint32_t queries, replies, fails, handshakes, hsMs, dropped; bool up; };
DotStats dotStats();

// One-shot DoT A lookup for the diagnostic. The long-lived link above is never
// touched: a second connection costs one handshake, so a button press cannot
// disturb the DNS path. rcode is the DNS code when a reply arrived; ip stays 0
// for NXDOMAIN/NODATA. False means the link or the reply could not be read.
bool dotResolve(const char* name, uint32_t* ip, uint8_t* rcode, uint32_t timeoutMs = 8000);

// Implemented in dns.cpp, called from the lwIP thread via tcpip_callback.
void dotDeliver(uint16_t slot, uint16_t gen, const uint8_t* reply, int len);
