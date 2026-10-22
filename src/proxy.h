// proxy.h — HTTP CONNECT proxy with ClientHello fragmentation. See proxy.cpp.
#pragma once
#include <Arduino.h>

struct PxStats { uint32_t total, active, failed, splits, bytes, fakes; int lastErr; };
extern bool pxFakeOn;   // send the decoy ClientHello before the real one
extern uint8_t pxFakeTtl;  // its IP TTL: high enough for the DPI, low enough to die before the server
extern bool pxSplitOn;  // split the real ClientHello into CHUNKS segments
void    proxyInit();
PxStats proxyStats();
String  proxyPac();          // the PAC file, with this device's address
