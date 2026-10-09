#include <stdio.h>

#define main p16_original_error_main
#include "../public_callback_error_a2.c"
#undef main

int main(void) {
  int result = p16_original_error_main();
  if (result != 0) return result;
  puts("P16_C_BODY ABI-002 PASS");
  puts("P16_ASSERT ABI-002 nested_error=PASS");
  puts("P16_ASSERT ABI-002 classification=PASS");
  puts("P16_ASSERT ABI-002 frame_cleanup=PASS");
  return 0;
}
