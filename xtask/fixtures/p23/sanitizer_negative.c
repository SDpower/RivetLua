/* 僅供獨立受監督的手動負例工作，不得連入產品。 */
#include <limits.h>
#include <stdlib.h>

int main(void) {
#if defined(P23_NEGATIVE_UBSAN)
  volatile int maximum = INT_MAX;
  volatile int one = 1;
  return maximum + one;
#else
  void *allocation = malloc(1);
  volatile unsigned char *bytes = allocation;
  if (bytes == NULL) return 2;
  bytes[0] = 0;
  bytes[1] = 1;
  free(allocation);
  return 0;
#endif
}
