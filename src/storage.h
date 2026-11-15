// ============================================================
// src/storage.h — SD init, CSV persistence, file rotation
// ============================================================
#pragma once
#include "globals.h"

void initSD();
void loadFilters();
void loadOuiDatabase();
void loadKnownDevices();
void loadVendorAliases();
void loadFingerprints();
void saveFingerprints();
void rotateLogFile();
void rotatePcapFile();
