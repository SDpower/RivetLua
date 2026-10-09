#include <stdio.h>

#define main p16_original_allocator_main
#include "../allocator_state_a50.c"
#undef main

int main(void) {
  int result = p16_original_allocator_main();
  if (result != 0) return result;
  puts("P16_C_BODY ABI-NEG-004 PASS");
  puts("P16_ASSERT ABI-NEG-004 reject_allocator_fallback=PASS");
  return 0;
}
