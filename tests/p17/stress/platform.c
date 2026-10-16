#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__clang__)
#define P17_COMPILER_TAG "clang"
#elif defined(__GNUC__)
#define P17_COMPILER_TAG "gcc"
#elif defined(_MSC_VER)
#define P17_COMPILER_TAG "msvc"
#else
#define P17_COMPILER_TAG "unknown"
#endif

static int valid_profile(const char *profile) {
  return strcmp(profile, "lua55-i64f64") == 0 ||
      strcmp(profile, "lua54-i64f64") == 0;
}

static void print_json_string(const char *value) {
  const unsigned char *byte = (const unsigned char *)value;
  putchar('"');
  while (*byte != '\0') {
    switch (*byte) {
      case '"': fputs("\\\"", stdout); break;
      case '\\': fputs("\\\\", stdout); break;
      case '\b': fputs("\\b", stdout); break;
      case '\f': fputs("\\f", stdout); break;
      case '\n': fputs("\\n", stdout); break;
      case '\r': fputs("\\r", stdout); break;
      case '\t': fputs("\\t", stdout); break;
      default:
        if (*byte < 0x20) printf("\\u%04x", (unsigned)*byte);
        else putchar((int)*byte);
        break;
    }
    ++byte;
  }
  putchar('"');
}

int main(int argc, char **argv) {
  char name[L_tmpnam];
  char diagnostic[256];
  const char *capability;
  const char *category;
  const char *path;
  int saved_errno;

  if (argc != 2 || !valid_profile(argv[1])) {
    fputs("P17 平台探測需要一個有效 profile\n", stderr);
    return 2;
  }

  errno = 0;
  path = tmpnam(name);
  saved_errno = errno;
  if (path != NULL && path[0] != '\0') {
    capability = "available";
    category = "name-returned";
    diagnostic[0] = '\0';
  } else {
    capability = "unsupported";
    category = "C_TMPNAM_UNAVAILABLE";
    if (saved_errno != 0) {
      const char *message = strerror(saved_errno);
      if (message == NULL || message[0] == '\0') {
        fputs("P17 tmpnam 錯誤缺少 strerror 診斷\n", stderr);
        return 1;
      }
      (void)snprintf(diagnostic, sizeof(diagnostic), "%s", message);
    } else {
      (void)snprintf(diagnostic, sizeof(diagnostic),
          "tmpnam returned NULL; errno remained zero");
    }
  }

  printf("P17_B03_CASE {\"case_id\":\"p17_platform_c\",\"profile\":");
  print_json_string(argv[1]);
  printf(",\"seed\":0,\"iterations\":1,\"outcome\":\"PASS\","
         "\"platform\":\"aarch64-apple-darwin\",\"compiler\":");
  print_json_string(P17_COMPILER_TAG);
  printf(",\"sizes\":{\"int\":%zu,\"long\":%zu,\"long_long\":%zu,"
         "\"pointer\":%zu,\"float\":%zu,\"double\":%zu,"
         "\"long_double\":%zu},\"capabilities\":{\"tmpnam\":",
         sizeof(int), sizeof(long), sizeof(long long), sizeof(void *),
         sizeof(float), sizeof(double), sizeof(long double));
  print_json_string(capability);
  printf(",\"tmpnam_category\":");
  print_json_string(category);
  printf(",\"tmpnam_errno\":%d,\"tmpnam_diagnostic\":", saved_errno);
  print_json_string(diagnostic);
  puts("}}");
  return ferror(stdout) ? 1 : 0;
}
