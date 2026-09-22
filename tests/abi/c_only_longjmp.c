#include <setjmp.h>

static jmp_buf checkpoint;

static int nested_callback(void) {
  longjmp(checkpoint, 7);
}

int main(void) {
  int result = setjmp(checkpoint);
  if (result == 0) return nested_callback();
  return result == 7 ? 0 : 1;
}
