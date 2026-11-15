// ===================== ui.h =====================
#pragma once
#include "globals.h"

void uiInit();        // display.begin, splash, buzzer pin done in main
void uiUpdate();      // handleChannelHopping + handleButtons + updateDisplay
void updateDisplay();
void handleButtons();
void handleChannelHopping();
void forceHop();
void beepAlert();
void beepDeauth();
void playTone(int freq, int dur);
void generateHTMLReport();
