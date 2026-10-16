/* 僅供獨立受監督的 TSan 手動負例工作，不得連入產品。 */
#include <pthread.h>

static volatile int shared_counter;

static void *write_counter(void *unused) {
  (void)unused;
  for (int index = 0; index < 1000; ++index) shared_counter++;
  return NULL;
}

int main(void) {
  pthread_t first;
  pthread_t second;
  if (pthread_create(&first, NULL, write_counter, NULL) != 0) return 2;
  if (pthread_create(&second, NULL, write_counter, NULL) != 0) {
    pthread_join(first, NULL);
    return 2;
  }
  if (pthread_join(first, NULL) != 0) return 2;
  if (pthread_join(second, NULL) != 0) return 2;
  return shared_counter == 0;
}
