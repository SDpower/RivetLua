#include <stdio.h>

#define main p16_original_trampoline_main
#include "../trampoline_a1.c"
#undef main

int main(void) {
  int result = p16_original_trampoline_main();
  if (result != 0) return result;
  puts("P16_C_BODY ABI-NEG-001 PASS");
  return 0;
}
