// Simple code that sends a keystroke every few seconds
#include <DigiKeyboard.h>

void setup() {
  DigiKeyboard.sendKeyStroke(0); // Do nothing, just initialize
}

void loop() {
  DigiKeyboard.sendKeyStroke(0); // Keeps the HID connection alive
  delay(5000); // Optional periodic activity
}
