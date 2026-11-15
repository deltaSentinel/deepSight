// ===================== sensors.h =====================
#pragma once
#include "globals.h"

void sensorsInit();   // Wire.begin, rtc, GPS serial, SD (calls initSD), BLE init
void sensorsUpdate(); // per-loop: GPS read, BLE scan scheduling, battery read
float readBattery();
void startBLEScan();
