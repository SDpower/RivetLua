#include "lauxlib.h"
#include "lua.h"

#include <stdio.h>
#include <string.h>

enum {
  MAX_EVENTS = 32,
  MAX_LABEL = 16,
  MAX_MESSAGE = 128,
  MAX_OUTPUT = 8192
};

typedef struct {
  char label[MAX_LABEL];
  char message[MAX_MESSAGE];
  int tocont;
  int stable;
  long long observed;
} WarningEvent;

typedef struct {
  lua_State *state;
  WarningEvent events[MAX_EVENTS];
  size_t count;
  int overflow;
  int nested;
} WarningSink;

static WarningSink sink;

static size_t record_event(WarningSink *target, const char *label,
                           const char *message, int tocont, int stable,
                           long long observed) {
  WarningEvent *event;
  size_t index;
  size_t length;

  if (target->count >= MAX_EVENTS) {
    target->overflow = 1;
    return MAX_EVENTS;
  }
  index = target->count++;
  event = &target->events[index];
  snprintf(event->label, sizeof(event->label), "%s", label);
  length = strlen(message);
  if (length >= sizeof(event->message)) {
    length = sizeof(event->message) - 1;
    target->overflow = 1;
  }
  memcpy(event->message, message, length);
  event->message[length] = '\0';
  event->tocont = tocont;
  event->stable = stable;
  event->observed = observed;
  return index;
}

static void recording_warning(void *ud, const char *message, int tocont) {
  WarningSink *target = (WarningSink *)ud;
  record_event(target, "record", message, tocont, -1, -1);
}

static void replacement_warning(void *ud, const char *message, int tocont) {
  WarningSink *target = (WarningSink *)ud;
  record_event(target, "replacement", message, tocont, -1, -1);
  lua_setwarnf(target->state, NULL, NULL);
}

static void reentrant_warning(void *ud, const char *message, int tocont) {
  WarningSink *target = (WarningSink *)ud;
  lua_State *L = target->state;
  size_t event_index;
  size_t message_length;
  char snapshot[MAX_MESSAGE];
  int is_number = 0;
  lua_Integer observed;

  if (target->nested) {
    record_event(target, "nested", message, tocont, -1, -1);
    return;
  }

  event_index = record_event(target, "primary", message, tocont, 0, -1);
  message_length = strlen(message);
  if (message_length >= sizeof(snapshot))
    message_length = sizeof(snapshot) - 1;
  memcpy(snapshot, message, message_length);
  snapshot[message_length] = '\0';

  target->nested = 1;
  lua_settop(L, 0);
  lua_gc(L, LUA_GCCOLLECT);
  lua_getglobal(L, "P17_CALLBACK_VALUE");
  observed = lua_tointegerx(L, -1, &is_number);
  lua_settop(L, 0);
  lua_pushinteger(L, is_number ? observed + 1 : -1);
  lua_setglobal(L, "P17_CALLBACK_PUSHED");
  lua_warning(L, "nested-callback", 0);
  lua_setwarnf(L, replacement_warning, target);

  if (event_index < target->count) {
    target->events[event_index].stable =
        (strlen(message) == message_length &&
         memcmp(message, snapshot, message_length) == 0);
    target->events[event_index].observed = is_number ? (long long)observed : -1;
  }
  target->nested = 0;
}

static int probe_setup(lua_State *L) {
  const char *mode = lua_tostring(L, 1);
  memset(&sink, 0, sizeof(sink));
  sink.state = L;
  lua_setwarnf(L, mode != NULL && strcmp(mode, "reenter") == 0
                      ? reentrant_warning
                      : recording_warning,
              &sink);
  return 0;
}

static int probe_events(lua_State *L) {
  char output[MAX_OUTPUT];
  size_t used = 0;
  size_t index;

  if (sink.overflow) {
    lua_pushstring(L, "<warning-event-overflow>\n");
    return 1;
  }
  for (index = 0; index < sink.count; index++) {
    const WarningEvent *event = &sink.events[index];
    int written = snprintf(output + used, sizeof(output) - used,
                           "%s|%d|%d|%lld|%s\n", event->label,
                           event->tocont, event->stable, event->observed,
                           event->message);
    if (written < 0 || (size_t)written >= sizeof(output) - used) {
      lua_pushstring(L, "<warning-event-output-overflow>\n");
      return 1;
    }
    used += (size_t)written;
  }
  lua_pushlstring(L, output, used);
  return 1;
}

int luaopen_p17_warning_probe(lua_State *L) {
  static const luaL_Reg functions[] = {
      {"setup", probe_setup},
      {"events", probe_events},
      {NULL, NULL},
  };
  luaL_newlib(L, functions);
  return 1;
}
