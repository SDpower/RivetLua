/* 由 tests/p16/generate_manifest.py 產生；只測試固定 header 純巨集。 */
#include "lauxlib.h"
#include <assert.h>
#include <string.h>

static void assert_buffer(
    luaL_Buffer *buffer, char *storage, const char *expected_storage,
    size_t storage_size, size_t expected_length) {
  assert(luaL_buffaddr(buffer) == storage);
  assert(luaL_bufflen(buffer) == expected_length);
  assert(memcmp(storage, expected_storage, storage_size) == 0);
}

int main(void) {
  char storage[] = {'a', 'b', 'c', 'd'};
  const char expected_storage[] = {'a', 'b', 'c', 'd'};
  luaL_Buffer buffer = {0};
  buffer.b = storage;
  buffer.n = 0;
  buffer.size = sizeof(storage);

  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);
  luaL_addsize(&buffer, 0);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);
  luaL_addsize(&buffer, 2);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 2);
  luaL_addsize(&buffer, 2);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), sizeof(storage));
  luaL_buffsub(&buffer, 0);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), sizeof(storage));
  luaL_buffsub(&buffer, 3);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 1);
  luaL_buffsub(&buffer, 1);
  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);
  return 0;
}
