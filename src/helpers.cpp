// ===================== helpers.cpp =====================
#include "helpers.h"

bool macEqual(const uint8_t* a, const uint8_t* b) { return memcmp(a, b, 6) == 0; }
bool isBroadcast(const uint8_t* mac) { for (int i = 0; i < 6; i++) if (mac[i] != 0xFF) return false; return true; }
bool isMulticast(const uint8_t* mac) { return (mac[0] & 0x01) == 0x01; }

void getOui(const uint8_t* mac, char* ouiStr) { snprintf(ouiStr, 9, "%02X:%02X:%02X", mac[0], mac[1], mac[2]); }

void getTimestamp(char* buffer, size_t size) {
  if (rtcFound) {
    DateTime now = rtc.now();
    if (now.year() > 2000) snprintf(buffer, size, "%04d-%02d-%02d %02d:%02d:%02d", now.year(), now.month(), now.day(), now.hour(), now.minute(), now.second());
    else snprintf(buffer, size, "%lu", millis());
  } else snprintf(buffer, size, "%lu", millis());
}

void readBattery() {
  int adcValue = analogRead(BAT_ADC_PIN);
  float v_adc = (adcValue / 4095.0) * 3.3;
  batteryVoltage = v_adc * 3.0;
  if (batteryVoltage < 3.0) batteryPercent = 0;
  else if (batteryVoltage > 4.2) batteryPercent = 100;
  else batteryPercent = ((batteryVoltage - 3.0) / 1.2) * 100;
}

void playTone(int freq, int duration) { if (silentMode || batterySaverMode) return; tone(BUZZER_PIN, freq, duration); }
void beepHandshake() { playTone(2000, 200); delay(50); playTone(2000, 200); }
void beepDeauth() { playTone(1000, 100); }
void beepGPS() { playTone(3000, 500); }
void beepAlert() { playTone(4000, 300); delay(100); playTone(4000, 300); }

PacketBuffer* allocPacketBuffer() {
  for (int i = 0; i < PACKET_POOL_SIZE; i++) {
    if (!packetPool[i].used) { packetPool[i].used = true; return &packetPool[i]; }
  }
  packetDropCount++; return nullptr;
}
void freePacketBuffer(PacketBuffer* pkt) { if (!pkt) return; pkt->used = false; }

