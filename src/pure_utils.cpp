#include "pure_utils.h"
#include <string.h>
#include <stdio.h>

bool macEqual(const uint8_t* a, const uint8_t* b) {
  return a && b && memcmp(a, b, 6) == 0;
}

bool isBroadcast(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (!mac || mac[i] != 0xFF) return false;
  }
  return mac != nullptr;
}

bool isMulticast(const uint8_t* mac) {
  if (!mac || isBroadcast(mac)) return false;
  return (mac[0] & 0x01) == 0x01;
}

bool getOui(const uint8_t* mac, char* buf) {
  if (!mac || !buf) return false;
  snprintf(buf, 9, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
  return true;
}
