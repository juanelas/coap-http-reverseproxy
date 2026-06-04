#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TEST

#include "../coap-http-reverseproxy.c"

#define REQUIRE(cond)                                                         \
  do {                                                                        \
    if (!(cond)) {                                                            \
      return 0;                                                               \
    }                                                                         \
  } while (0)

static int parse_args_silenced(int argc, char **argv, proxy_config_t *cfg) {
  int saved_stderr = dup(STDERR_FILENO);
  int devnull = -1;
  int ok;

  if (saved_stderr < 0) {
    return parse_args(argc, argv, cfg);
  }

  devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    fflush(stderr);
    (void)dup2(devnull, STDERR_FILENO);
    close(devnull);
  }

  ok = parse_args(argc, argv, cfg);

  fflush(stderr);
  (void)dup2(saved_stderr, STDERR_FILENO);
  close(saved_stderr);
  return ok;
}

static int test_no_args_defaults_to_coap(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy"};
  int ok = parse_args(1, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 0);
  REQUIRE(cfg.port == 5683);
  REQUIRE(strcmp(cfg.http_url, "http://localhost:3000") == 0);
  return 1;
}

static int test_single_positional_backend_url(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "http://127.0.0.1:4000"};
  int ok = parse_args(2, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 0);
  REQUIRE(cfg.port == 5683);
  REQUIRE(strcmp(cfg.http_url, "http://127.0.0.1:4000") == 0);
  return 1;
}

static int test_too_many_positionals_fail(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "http://x", "extra"};
  int ok = parse_args_silenced(3, argv, &cfg);

  REQUIRE(ok == 0);
  return 1;
}

static int test_dtls_psk_requires_psk_file(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "psk"};
  int ok = parse_args_silenced(3, argv, &cfg);

  REQUIRE(ok == 0);
  return 1;
}

static int test_dtls_psk_ok_and_default_port(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "psk", "--psk-file", "psk.txt"};
  int ok = parse_args(5, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 1);
  REQUIRE(cfg.mode == DTLS_MODE_PSK);
  REQUIRE(cfg.port == 5684);
  REQUIRE(strcmp(cfg.psk_path, "psk.txt") == 0);
  return 1;
}

static int test_dtls_psk_accepts_positional_backend_url(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "http://127.0.0.1:3000", "--dtls", "psk", "--psk-file",
      "psk.txt"};
  int ok = parse_args(6, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 1);
  REQUIRE(cfg.mode == DTLS_MODE_PSK);
  REQUIRE(cfg.port == 5684);
  REQUIRE(strcmp(cfg.http_url, "http://127.0.0.1:3000") == 0);
  REQUIRE(strcmp(cfg.psk_path, "psk.txt") == 0);
  return 1;
}

static int test_dtls_psk_accepts_positional_backend_url_after_flags(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--dtls", "psk", "--psk-file", "psk.txt",
      "http://127.0.0.1:3000"};
  int ok = parse_args(6, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 1);
  REQUIRE(cfg.mode == DTLS_MODE_PSK);
  REQUIRE(cfg.port == 5684);
  REQUIRE(strcmp(cfg.http_url, "http://127.0.0.1:3000") == 0);
  REQUIRE(strcmp(cfg.psk_path, "psk.txt") == 0);
  return 1;
}

static int test_dtls_pki_requires_cert_and_key(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "pki", "--cert", "server.crt"};
  int ok = parse_args_silenced(5, argv, &cfg);

  REQUIRE(ok == 0);
  return 1;
}

static int test_dtls_pki_ok(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--dtls", "pki", "--cert", "server.crt", "--key", "server.key"};
  int ok = parse_args(7, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.dtls_set == 1);
  REQUIRE(cfg.mode == DTLS_MODE_PKI);
  REQUIRE(cfg.port == 5684);
  return 1;
}

static int test_custom_port_applies(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--port", "9999"};
  int ok = parse_args(3, argv, &cfg);

  REQUIRE(ok == 1);
  REQUIRE(cfg.port == 9999);
  return 1;
}

static int test_listen_addr_and_iface_mutually_exclusive(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--listen-addr", "127.0.0.1", "--listen-iface", "lo"};
  int ok = parse_args_silenced(5, argv, &cfg);

  REQUIRE(ok == 0);
  return 1;
}

static int test_psk_line_utf8_ok(void) {
  psk_client_t c;
  char err[128] = {0};
  int ok = parse_psk_line("alice:mySecret:utf8", &c, err, sizeof(err));

  REQUIRE(ok == 1);
  REQUIRE(strcmp(c.identity, "alice") == 0);
  REQUIRE(c.key_len == strlen("mySecret"));
  REQUIRE(memcmp(c.key, "mySecret", c.key_len) == 0);
  return 1;
}

static int test_psk_line_hex_ok(void) {
  psk_client_t c;
  char err[128] = {0};
  int ok = parse_psk_line("bob:48656c6c6f:hex", &c, err, sizeof(err));

  REQUIRE(ok == 1);
  REQUIRE(strcmp(c.identity, "bob") == 0);
  REQUIRE(c.key_len == 5);
  REQUIRE(memcmp(c.key, "Hello", 5) == 0);
  return 1;
}

static int test_psk_line_base64_ok(void) {
  psk_client_t c;
  char err[128] = {0};
  int ok = parse_psk_line("carol:SGVsbG8=:base64", &c, err, sizeof(err));

  REQUIRE(ok == 1);
  REQUIRE(strcmp(c.identity, "carol") == 0);
  REQUIRE(c.key_len == 5);
  REQUIRE(memcmp(c.key, "Hello", 5) == 0);
  return 1;
}

static int test_psk_line_invalid_encoding_fails(void) {
  psk_client_t c;
  char err[128] = {0};
  int ok = parse_psk_line("dave:abc:deflate", &c, err, sizeof(err));

  REQUIRE(ok == 0);
  return 1;
}

static int test_psk_line_missing_encoding_fails(void) {
  psk_client_t c;
  char err[128] = {0};
  int ok = parse_psk_line("erin:abc", &c, err, sizeof(err));

  REQUIRE(ok == 0);
  return 1;
}

typedef int (*test_fn_t)(void);

typedef struct {
  const char *name;
  test_fn_t fn;
} test_case_t;

static int run_test(const test_case_t *tc) {
  int ok;

  printf("[RUN ] %s\n", tc->name);
  ok = tc->fn();
  printf("[%s] %s\n", ok ? "PASS" : "FAIL", tc->name);
  return ok;
}

int main(void) {
  const test_case_t tests[] = {
      {"no_args_defaults_to_coap", test_no_args_defaults_to_coap},
      {"single_positional_backend_url", test_single_positional_backend_url},
      {"too_many_positionals_fail", test_too_many_positionals_fail},
      {"dtls_psk_requires_psk_file", test_dtls_psk_requires_psk_file},
      {"dtls_psk_ok_and_default_port", test_dtls_psk_ok_and_default_port},
      {"dtls_psk_accepts_positional_backend_url",
       test_dtls_psk_accepts_positional_backend_url},
      {"dtls_psk_accepts_positional_backend_url_after_flags",
       test_dtls_psk_accepts_positional_backend_url_after_flags},
      {"dtls_pki_requires_cert_and_key", test_dtls_pki_requires_cert_and_key},
      {"dtls_pki_ok", test_dtls_pki_ok},
      {"custom_port_applies", test_custom_port_applies},
      {"listen_addr_and_iface_mutually_exclusive",
       test_listen_addr_and_iface_mutually_exclusive},
      {"psk_line_utf8_ok", test_psk_line_utf8_ok},
      {"psk_line_hex_ok", test_psk_line_hex_ok},
      {"psk_line_base64_ok", test_psk_line_base64_ok},
      {"psk_line_invalid_encoding_fails", test_psk_line_invalid_encoding_fails},
      {"psk_line_missing_encoding_fails", test_psk_line_missing_encoding_fails},
  };
  size_t passed = 0;
  size_t failed = 0;

  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    if (run_test(&tests[i])) {
      passed++;
    } else {
      failed++;
    }
  }

  printf("Summary: %zu passed, %zu failed\n", passed, failed);
  return failed == 0 ? 0 : 1;
}
