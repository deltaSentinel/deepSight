// ===================== helpers.cpp =====================
#include "helpers.h"
#include "pure_utils.h"

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
  if (!packetPool) return nullptr;  // pool not initialised yet
  for (int i = 0; i < PACKET_POOL_SIZE; i++) {
    if (!packetPool[i].used) {
      // Zero-fill so no previous packet's payload/metadata leaks to consumers
      memset(&packetPool[i], 0, sizeof(PacketBuffer));
      packetPool[i].used = true;
      return &packetPool[i];
    }
  }
  packetDropCount = packetDropCount + 1;
  return nullptr;
}

void freePacketBuffer(PacketBuffer* pkt) {
  if (!pkt || !packetPool) return;
  if (pkt < &packetPool[0] || pkt >= &packetPool[0] + PACKET_POOL_SIZE) {
    Serial.printf("[ERROR] freePacketBuffer: foreign ptr %p\n", (void*)pkt);
    return;
  }
  size_t idx = pkt - packetPool;
  if (!packetPool[idx].used) {
    Serial.printf("[ERROR] double-free slot %u\n", (unsigned)idx);
    return;
  }
  packetPool[idx].used = false;
}
