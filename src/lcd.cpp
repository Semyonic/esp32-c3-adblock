// lcd.cpp — minimal, effective status screen for the Waveshare ESP32-S3-LCD-1.47.
// Design goals (user): no graphs, big readable numbers, near-zero CPU/DMA cost so
// DNS performance never suffers. Full-frame push only when something changed.
#include "lcd.h"
#if defined(ARDUINO_ESP32S3_DEV) && defined(LCD_ENABLE)
#include <Fonts/FreeSans9pt7b.h>
#include <Fonts/FreeSansBold12pt7b.h>
#include <Fonts/FreeSansBold24pt7b.h>

Adafruit_ST7789 lcd = Adafruit_ST7789(LCD_CS, LCD_DC, LCD_MOSI, LCD_SCLK, LCD_RST);

// palette (RGB565)
static const uint16_t C_BG     = 0x0006;
static const uint16_t C_TEXT   = 0xFFFF;
static const uint16_t C_MUTED  = 0x7bcf;
static const uint16_t C_RED    = 0xfa5a;
static const uint16_t C_GREEN  = 0x6f4d;
static const uint16_t C_LINE   = 0x3186;

static uint32_t lastBlocked = 0xFFFFFFFF, lastAllowed = 0xFFFFFFFF, lastDomains = 0;
static int lastRssiBars = -1;

static GFXcanvas16 *frame = nullptr;   // 110 KB full-frame canvas

// backlight state machine
static bool screenOn = true;
static uint32_t lastActivityMs = 0;
static bool lastBtnLevel = HIGH;

static void backlight(bool on) { digitalWrite(LCD_BL, on ? HIGH : LOW); }

static void wifiBars(uint16_t x, uint16_t y, int level) {  // 0..4
  for (int i = 0; i < 4; i++) {
    uint16_t bh = 3 + i * 3;
    uint16_t color = (i < level) ? C_GREEN : C_LINE;
    frame->fillRect(x + i * 5, y - bh, 3, bh, color);
  }
}

static void redrawStatic(uint32_t domains) {
  frame->fillScreen(C_BG);
  frame->setFont(&FreeSansBold12pt7b);
  frame->setTextColor(C_TEXT);
  frame->setCursor(8, 26); frame->print("ADBLOCK");
  frame->setFont(&FreeSans9pt7b);
  frame->setTextColor(C_MUTED);
  frame->setCursor(120, 24); frame->printf("%uk", (unsigned)(domains / 1000));
  frame->drawFastHLine(0, 36, 172, C_LINE);
  // labels
  frame->setFont(&FreeSansBold12pt7b);
  frame->setTextColor(C_RED);
  frame->setCursor(12, 88);  frame->print("BLOCKED");
  frame->setTextColor(C_GREEN);
  frame->setCursor(12, 178); frame->print("ALLOWED");
  // footer
  frame->drawFastHLine(0, 274, 172, C_LINE);
  frame->setFont(&FreeSans9pt7b);
  frame->setTextColor(C_MUTED);
  frame->setCursor(8, 296); frame->print("adblocker.local");
}

void lcdInit() {
  pinMode(LCD_BL, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  backlight(true);
  lastActivityMs = millis();
  lastBtnLevel = digitalRead(BUTTON_PIN);
  lcd.init(172, 320);
  lcd.setRotation(0);
  frame = new GFXcanvas16(172, 320);     // 110 KB — fits the S3 heap
  frame->fillScreen(C_BG);
  redrawStatic(0);
  lcd.drawRGBBitmap(0, 0, frame->getBuffer(), frame->width(), frame->height());
}

void lcdButtonPoll() {
  bool lvl = digitalRead(BUTTON_PIN);
  if (lastBtnLevel == HIGH && lvl == LOW) {
    lastActivityMs = millis();
    if (!screenOn) {
      backlight(true);
      screenOn = true;
      lastBlocked = lastAllowed = 0xFFFFFFFF;
    }
  }
  lastBtnLevel = lvl;
  if (screenOn && millis() - lastActivityMs > LCD_TIMEOUT_MS) {
    backlight(false);
    screenOn = false;
  }
}

void lcdUpdate(uint32_t blocked, uint32_t allowed, uint32_t domains, int rssi) {
  if (!screenOn) return;
  bool changed = false;

  if (domains != lastDomains) { redrawStatic(domains); lastDomains = domains; changed = true; }

  if (blocked != lastBlocked) {
    lastBlocked = blocked;
    frame->fillRect(12, 100, 150, 44, C_BG);
    frame->setFont(&FreeSansBold24pt7b);
    frame->setTextColor(C_RED);
    frame->setCursor(12, 134);
    frame->print(blocked);
    changed = true;
  }
  if (allowed != lastAllowed) {
    lastAllowed = allowed;
    frame->fillRect(12, 190, 150, 44, C_BG);
    frame->setFont(&FreeSansBold24pt7b);
    frame->setTextColor(C_GREEN);
    frame->setCursor(12, 224);
    frame->print(allowed);
    changed = true;
  }
  int bars = rssi < -80 ? 0 : rssi < -70 ? 1 : rssi < -60 ? 2 : rssi < -50 ? 3 : 4;
  if (bars != lastRssiBars) {
    lastRssiBars = bars;
    frame->fillRect(130, 280, 40, 18, C_BG);
    wifiBars(136, 296, bars);
    changed = true;
  }
  if (changed) {
    lcd.drawRGBBitmap(0, 0, frame->getBuffer(), frame->width(), frame->height());
  }
}
#endif   // ARDUINO_ESP32S3_DEV
