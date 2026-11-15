// ===================== logging.h =====================
#pragma once
#include "globals.h"

void enqueueLog(const char* subsystem, const char* event,
                const char* msg, int8_t rssi, uint8_t channel);
void logWriterTask(void* param);
void pcapWriterTask(void* param);
void initSD();      
void flushLogFiles();
