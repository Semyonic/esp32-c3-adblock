// lcd.h — Waveshare ESP32-S3-LCD-1.47 (ST7789 172x320, SPI pins from Waveshare wiki).
// Minimal, readable status screen: big counters, tiny footprint, no graphs.
// Pushes the full frame only when a value actually changes.
#pragma once
#include <Arduino.h>
#if defined(ARDUINO_ESP32S3_DEV)
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <SPI.h>

#define LCD_MOSI 45
#define LCD_SCLK 40
#define LCD_CS   42
#define LCD_DC   41
#define LCD_RST  39
#define LCD_BL   48

#define BUTTON_PIN 0        // BOOT button, active low, INPUT_PULLUP
#define LCD_TIMEOUT_MS (10UL * 60UL * 1000UL)   // blank after 10 min idle

extern Adafruit_ST7789 lcd;
void lcdInit();
void lcdButtonPoll();   // call every loop: button wake logic
void lcdUpdate(uint32_t blocked, uint32_t allowed, uint32_t domains, int rssi);
#else
// Boards without the display (C3 SuperMini): keep dashboard calls compiling
// as no-ops so one source builds for every env — and the c3 image stays
// within its 0x150000 OTA slot (Adafruit libs would push it ~90 KB over).
inline void lcdInit() {}
inline void lcdButtonPoll() {}
inline void lcdUpdate(uint32_t, uint32_t, uint32_t, int) {}
#endif
