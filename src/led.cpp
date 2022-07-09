#include "ENCRoute.h"

const PROGMEM uint8_t led_r[] = {1, 0, 1, 0, 1, 0, 1, 0};
const PROGMEM uint8_t led_g[] = {1, 1, 0, 0, 1, 1, 0, 0};
const PROGMEM uint8_t led_b[] = {1, 1, 1, 1, 0, 0, 0, 0};


void ENCRoute::lightProtocol() {
  digitalWrite(5, led_r[protocol_type]);
  digitalWrite(6, led_g[protocol_type]);
  digitalWrite(7, led_b[protocol_type]);
}