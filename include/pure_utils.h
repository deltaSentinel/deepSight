#pragma once
#include <stdint.h>

// Pure, hardware-free utilities extracted from helpers.cpp
// for host-side unit testing (no Arduino dependencies).

// Compare two MAC addresses for equality (6-byte memcmp).
bool macEqual(const uint8_t* a, const uint8_t* b);

// True if MAC is broadcast ff:ff:ff:ff:ff:ff
bool isBroadcast(const uint8_t* mac);

// True if MAC is multicast (LSB of first octet set, excluding broadcast)
bool isMulticast(const uint8_t* mac);

// Format first 3 bytes of MAC as "AA:BB:CC" into a buffer.
// buf MUST be at least 9 bytes ('A','A',':','B','B',':','C','C','\0').
void getOui(const uint8_t* mac, char* buf);
