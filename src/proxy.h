// proxy.h — HTTP CONNECT proxy with ClientHello fragmentation. See proxy.cpp.
#pragma once
#include <Arduino.h>

struct PxStats { uint32_t total, active, failed, splits, bytes; };
void    proxyInit();
PxStats proxyStats();
String  proxyPac();          // the PAC file, with this device's address
