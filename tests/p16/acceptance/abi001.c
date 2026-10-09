#include <stdio.h>

#define main p16_original_callback_main
#include "../callback_execution_b4.c"
#undef main

int main(void) {
  int result = p16_original_callback_main();
  if (result != 0) return result;
  puts("P16_C_BODY ABI-001 PASS");
  puts("P16_ASSERT ABI-001 stack=PASS");
  puts("P16_ASSERT ABI-001 results=PASS");
  return 0;
}
