// lcd.h — Waveshare ESP32-S3-LCD-1.47 (ST7789 172x320, SPI pins from Waveshare wiki).
// Minimal, readable status screen: big counters, tiny footprint, no graphs.
// Pushes the full frame only when a value actually changes.
#pragma once
#include <Arduino.h>
// Opt-in (-DLCD_ENABLE): the Adafruit ST7789 driver bit-bangs SPI here, and a
// full-frame push blocks loop() for ~1 s. Measured with the panel on: DNS p50
// 1750 ms vs 72 ms off. Leave it disabled unless that is fixed.
#if defined(ARDUINO_ESP32S3_DEV) && defined(LCD_ENABLE)
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
// Display disabled or absent (C3 SuperMini): keep dashboard calls compiling
// as no-ops so one source builds for every env — and the c3 image stays
// within its 0x150000 OTA slot (Adafruit libs would push it ~90 KB over).
#if defined(ARDUINO_ESP32S3_DEV)
inline void lcdInit() { pinMode(48, OUTPUT); digitalWrite(48, LOW); }   // backlight off
#else
inline void lcdInit() {}
#endif
inline void lcdButtonPoll() {}
inline void lcdUpdate(uint32_t, uint32_t, uint32_t, int) {}
#endif
