// ============================================================
// src/sensors.h — GPS, BLE, channel hopping
// ============================================================
#pragma once
#include "globals.h"

// GPS
void initGPS();
void updateGPS();

// BLE
void initBLE();
void startBLEScan();

// Channel hopping
void updateChannelActivity();
void forceHop();
void handleChannelHopping();
