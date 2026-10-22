// diag.h — one-shot censorship diagnostic. See diag.cpp.
#pragma once
#include <stdint.h>

enum DiagState : uint8_t { DIAG_IDLE = 0, DIAG_RUNNING = 1, DIAG_DONE = 2, DIAG_ERROR = 3 };

struct DiagResult {
  char domain[256];
  char verdict[8];       // clean, dns, ip, sni, local, nodata, error
  char note[96];
  char tlsErr[48];
  uint32_t ispIp, trustedIp;
  uint16_t tcpMs, tlsMs;
  uint32_t totalMs;
  uint8_t ispRcode, trustedRcode;
  bool ispAnswered, trustedAnswered, dotUsed, poisoned, localBlocked, tcpOk, tlsOk;
};

void diagInit();
int  diagStart(const char* domain);       // 1 started, 0 busy, -1 invalid or not ready
uint8_t diagGet(DiagResult* out);         // state; fills the last result when done
