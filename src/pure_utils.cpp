#include "pure_utils.h"
#include <string.h>
#include <stdio.h>

bool macEqual(const uint8_t* a, const uint8_t* b) {
  return memcmp(a, b, 6) == 0;
}

bool isBroadcast(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (mac[i] != 0xFF) return false;
  }
  return true;
}

bool isMulticast(const uint8_t* mac) {
  return (mac[0] & 0x01) == 0x01;
}

void getOui(const uint8_t* mac, char* buf) {
  snprintf(buf, 9, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
}
