/* P16 Unix 平台薄層：不包含 Lua 引擎，也不呼叫 module opener。 */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

struct lua_State;
typedef int (*rivetlua_native_opener)(struct lua_State *);

int rivetlua_native_open_candidate(const char *path) {
  if (path == NULL) return -1;
  return open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
}

void *rivetlua_native_open(const char *path, int global) {
  if (path == NULL) return NULL;
  return dlopen(path, RTLD_NOW | (global ? RTLD_GLOBAL : RTLD_LOCAL));
}

int rivetlua_native_symbol(void *handle, const char *name,
                           rivetlua_native_opener *out) {
  if (handle == NULL || name == NULL || out == NULL) return 0;
  *out = NULL;
  (void)dlerror();
  void *symbol = dlsym(handle, name);
  if (dlerror() != NULL || symbol == NULL) return 0;
  _Static_assert(sizeof(symbol) == sizeof(*out),
                 "P16 target 的資料與函式指標大小須相同");
  memcpy(out, &symbol, sizeof(symbol));
  return 1;
}

void rivetlua_native_close(void *handle) {
  if (handle != NULL) (void)dlclose(handle);
}

int rivetlua_worker_set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int rivetlua_worker_poll(int stdout_fd, int stdin_fd, int want_write,
                         int timeout_ms, int *can_read, int *can_write) {
  if (can_read == NULL || can_write == NULL || timeout_ms < 0) return -1;
  *can_read = 0;
  *can_write = 0;
  struct pollfd fds[2];
  nfds_t count = 1;
  fds[0].fd = stdout_fd;
  fds[0].events = POLLIN;
  fds[0].revents = 0;
  if (want_write) {
    fds[1].fd = stdin_fd;
    fds[1].events = POLLOUT;
    fds[1].revents = 0;
    count = 2;
  }
  int result = poll(fds, count, timeout_ms);
  if (result < 0 && errno == EINTR) return 0;
  if (result <= 0) return result;
  *can_read = (fds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
  if (want_write)
    *can_write = (fds[1].revents & (POLLOUT | POLLHUP | POLLERR | POLLNVAL)) != 0;
  return result;
}
