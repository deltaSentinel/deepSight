// ============================================================
// src/packets.h — Promiscuous capture, processor task
// ============================================================
#pragma once
#include "globals.h"

void packetProcessorTask(void* param);
void installPromiscuousMode();  // call once after queues/mutexes exist
