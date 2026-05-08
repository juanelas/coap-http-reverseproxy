#include <assert.h>
#include <stdio.h>
#include <string.h>

#define UNIT_TEST
#include "../coap-http-reverseproxy.c"

static void test_no_args_defaults_to_coap(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy"};
  int ok = parse_args(1, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 0);
  assert(cfg.port == 5683);
  assert(strcmp(cfg.http_url, "http://localhost:3000") == 0);
}

static void test_single_positional_backend_url(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "http://127.0.0.1:4000"};
  int ok = parse_args(2, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 0);
  assert(cfg.port == 5683);
  assert(strcmp(cfg.http_url, "http://127.0.0.1:4000") == 0);
}

static void test_too_many_positionals_fail(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "http://x", "extra"};
  int ok = parse_args(3, argv, &cfg);

  assert(ok == 0);
}

static void test_dtls_psk_requires_psk_file(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "psk"};
  int ok = parse_args(3, argv, &cfg);

  assert(ok == 0);
}

static void test_dtls_psk_ok_and_default_port(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "psk", "--psk-file", "psk.txt"};
  int ok = parse_args(5, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 1);
  assert(cfg.mode == DTLS_MODE_PSK);
  assert(cfg.port == 5684);
  assert(strcmp(cfg.psk_path, "psk.txt") == 0);
}

static void test_dtls_psk_accepts_positional_backend_url(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "http://127.0.0.1:3000", "--dtls", "psk", "--psk-file",
      "psk.txt"};
  int ok = parse_args(6, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 1);
  assert(cfg.mode == DTLS_MODE_PSK);
  assert(cfg.port == 5684);
  assert(strcmp(cfg.http_url, "http://127.0.0.1:3000") == 0);
  assert(strcmp(cfg.psk_path, "psk.txt") == 0);
}

static void test_dtls_psk_accepts_positional_backend_url_after_flags(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--dtls", "psk", "--psk-file", "psk.txt",
      "http://127.0.0.1:3000"};
  int ok = parse_args(6, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 1);
  assert(cfg.mode == DTLS_MODE_PSK);
  assert(cfg.port == 5684);
  assert(strcmp(cfg.http_url, "http://127.0.0.1:3000") == 0);
  assert(strcmp(cfg.psk_path, "psk.txt") == 0);
}

static void test_dtls_pki_requires_cert_and_key(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--dtls", "pki", "--cert", "server.crt"};
  int ok = parse_args(5, argv, &cfg);

  assert(ok == 0);
}

static void test_dtls_pki_ok(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--dtls", "pki", "--cert", "server.crt", "--key", "server.key"};
  int ok = parse_args(7, argv, &cfg);

  assert(ok == 1);
  assert(cfg.dtls_set == 1);
  assert(cfg.mode == DTLS_MODE_PKI);
  assert(cfg.port == 5684);
}

static void test_custom_port_applies(void) {
  proxy_config_t cfg;
  char *argv[] = {"proxy", "--port", "9999"};
  int ok = parse_args(3, argv, &cfg);

  assert(ok == 1);
  assert(cfg.port == 9999);
}

static void test_listen_addr_and_iface_mutually_exclusive(void) {
  proxy_config_t cfg;
  char *argv[] = {
      "proxy", "--listen-addr", "127.0.0.1", "--listen-iface", "lo"};
  int ok = parse_args(5, argv, &cfg);

  assert(ok == 0);
}

int main(void) {
  test_no_args_defaults_to_coap();
  test_single_positional_backend_url();
  test_too_many_positionals_fail();
  test_dtls_psk_requires_psk_file();
  test_dtls_psk_ok_and_default_port();
  test_dtls_psk_accepts_positional_backend_url();
  test_dtls_psk_accepts_positional_backend_url_after_flags();
  test_dtls_pki_requires_cert_and_key();
  test_dtls_pki_ok();
  test_custom_port_applies();
  test_listen_addr_and_iface_mutually_exclusive();

  puts("All unit tests passed.");
  return 0;
}
