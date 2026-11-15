// ===================== packets.h =====================
#pragma once
#include "globals.h"

void packetProcessorTask(void* param);
void enqueuePcap(const uint8_t* payload, uint16_t len);
