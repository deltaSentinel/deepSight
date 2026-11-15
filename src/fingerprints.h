// ===================== fingerprints.h =====================
#pragma once
#include "globals.h"

void fingerprintsLoad();     
void saveFingerprints();
const char* getVendorFromOui(const uint8_t* mac);
int getDeviceStatus(const uint8_t* mac);
int calculateThreatScore(AccessPoint* ap);
void updateKarmaTracking(const uint8_t* mac, bool isProbeRequest);
void checkKarmaAttack();
void updateAnomalyTracking(const uint8_t* mac, int8_t rssi);
void processHandshake(const uint8_t* payload, uint16_t len,
                      const uint8_t* bssid, int8_t rssi);
void autoTag(AccessPoint* ap);
