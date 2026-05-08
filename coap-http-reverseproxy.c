#include <coap3/coap.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENTS 100
#define MAX_STR_LEN 128
#define MAX_PATH_LEN 512
#define MAX_RESPONSE_SIZE (1024 * 1024)

typedef struct {
  char identity[MAX_STR_LEN];
  char key[MAX_STR_LEN];
  coap_bin_const_t key_bin;
} psk_client_t;

typedef struct {
  uint8_t *data;
  size_t len;
  size_t cap;
} response_buffer_t;

typedef enum {
  DTLS_MODE_PSK = 0,
  DTLS_MODE_PKI = 1
} dtls_mode_t;

typedef struct {
  dtls_mode_t mode;
  int dtls_set;
  const char *psk_path;
  const char *http_url;
  uint16_t port;
  const char *listen_addr;
  const char *listen_iface;
  const char *cert_file;
  const char *key_file;
  const char *ca_file;
} proxy_config_t;

static int parse_port(const char *s, uint16_t *out_port);
#ifndef UNIT_TEST
static psk_client_t clients[MAX_CLIENTS];
static size_t client_count = 0;

static const char *http_base_url = "http://localhost:3000";

static void load_psk_file(const char *filename);
static const coap_bin_const_t *psk_callback(coap_bin_const_t *identity,
                                            coap_session_t *session,
                                            void *arg);
static int fill_bind_addr(const proxy_config_t *cfg, uint16_t port,
                          coap_address_t *out);
#endif

static void print_usage(const char *progname) {
  fprintf(stderr,
          "Usage:\n"
          "  %s [<http_url>]\n"
          "  %s [<http_url>] --dtls psk --psk-file <psk.txt> [--port <port>]\n"
          "  %s [<http_url>] --dtls pki --cert <server.crt> --key <server.key> [--ca <ca.crt>] [--port <port>]\n"
          "Options:\n"
          "  --help              Show this help message and exit\n"
          "  --http-url <url>    HTTP backend base URL (default: http://localhost:3000). It can be also specified as a positional argument.\n"
          "  --dtls psk|pki      Enable DTLS; omit for plain CoAP\n"
          "  --psk-file <path>   PSK file; required when --dtls psk\n"
          "  --cert <path>       Server certificate PEM; required when --dtls pki\n"
          "  --key <path>        Server private key PEM; required when --dtls pki\n"
          "  --ca <path>         CA certificate PEM (optional, --dtls pki)\n"
          "  --port <port>       UDP port (default: 5684 with --dtls, 5683 without)\n"
          "  --listen-addr <ip>  IP address to listen on, IPv4 or IPv6 (default: all interfaces)\n"
          "  --listen-iface <if> Network interface to listen on, e.g. eth0. Mutually exclusive with --listen-addr\n",
          progname, progname, progname);
}

static int parse_port(const char *s, uint16_t *out_port) {
  char *end = NULL;
  long v;

  if (!s || !out_port) {
    return 0;
  }

  errno = 0;
  v = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || v < 1 || v > 65535) {
    return 0;
  }

  *out_port = (uint16_t)v;
  return 1;
}

static int parse_args(int argc, char **argv, proxy_config_t *cfg) {
  int positional_count = 0;

  memset(cfg, 0, sizeof(*cfg));
  cfg->http_url = "http://localhost:3000";
  cfg->port = 0; /* resolved after parsing: 5684 with DTLS, 5683 without */

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      exit(0);
    }
  }

  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--", 2) != 0) {
      if (positional_count > 0) {
        fprintf(stderr, "Too many positional arguments.\n");
        print_usage(argv[0]);
        return 0;
      }
      cfg->http_url = argv[i];
      positional_count++;
    } else if (strcmp(argv[i], "--dtls") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      if (strcmp(argv[i + 1], "psk") == 0) {
        cfg->mode = DTLS_MODE_PSK;
        cfg->dtls_set = 1;
      } else if (strcmp(argv[i + 1], "pki") == 0) {
        cfg->mode = DTLS_MODE_PKI;
        cfg->dtls_set = 1;
      } else {
        fprintf(stderr, "Invalid --dtls mode: %s\n", argv[i + 1]);
        print_usage(argv[0]);
        return 0;
      }
      i++;
    } else if (strcmp(argv[i], "--psk-file") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->psk_path = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--http-url") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->http_url = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--port") == 0) {
      if (i + 1 >= argc || !parse_port(argv[i + 1], &cfg->port)) {
        fprintf(stderr, "Invalid --port value\n");
        print_usage(argv[0]);
        return 0;
      }
      i++;
    } else if (strcmp(argv[i], "--cert") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->cert_file = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--key") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->key_file = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--ca") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->ca_file = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--listen-addr") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->listen_addr = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--listen-iface") == 0) {
      if (i + 1 >= argc) {
        print_usage(argv[0]);
        return 0;
      }
      cfg->listen_iface = argv[i + 1];
      i++;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      print_usage(argv[0]);
      return 0;
    }
  }

  if (cfg->listen_addr && cfg->listen_iface) {
    fprintf(stderr, "--listen-addr and --listen-iface are mutually exclusive\n");
    print_usage(argv[0]);
    return 0;
  }

  if (cfg->dtls_set) {
    if (cfg->mode == DTLS_MODE_PSK && !cfg->psk_path) {
      fprintf(stderr, "--psk-file is required when --dtls psk\n");
      print_usage(argv[0]);
      return 0;
    }
    if (cfg->mode == DTLS_MODE_PKI && (!cfg->cert_file || !cfg->key_file)) {
      fprintf(stderr, "--cert and --key are required when --dtls pki\n");
      print_usage(argv[0]);
      return 0;
    }
    if (cfg->port == 0) cfg->port = 5684;
  } else {
    if (cfg->port == 0) cfg->port = 5683;
  }

  return 1;
}

#ifndef UNIT_TEST
static int fill_bind_addr(const proxy_config_t *cfg, uint16_t port,
                          coap_address_t *out) {
  coap_address_init(out);

  if (cfg->listen_iface) {
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) {
      perror("getifaddrs");
      return 0;
    }
    /* Prefer IPv4; fall back to IPv6. */
    for (int pass = 0; pass < 2; pass++) {
      int want_family = pass == 0 ? AF_INET : AF_INET6;
      for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, cfg->listen_iface) != 0) continue;
        if (ifa->ifa_addr->sa_family != want_family) continue;
        if (want_family == AF_INET) {
          struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
          out->addr.sin.sin_family = AF_INET;
          out->addr.sin.sin_addr   = s->sin_addr;
          out->addr.sin.sin_port   = htons(port);
          out->size = sizeof(struct sockaddr_in);
        } else {
          struct sockaddr_in6 *s = (struct sockaddr_in6 *)ifa->ifa_addr;
          out->addr.sin6.sin6_family = AF_INET6;
          out->addr.sin6.sin6_addr   = s->sin6_addr;
          out->addr.sin6.sin6_port   = htons(port);
          out->size = sizeof(struct sockaddr_in6);
        }
        freeifaddrs(ifap);
        return 1;
      }
    }
    freeifaddrs(ifap);
    fprintf(stderr, "Interface '%s' not found or has no usable address\n",
            cfg->listen_iface);
    return 0;
  }

  if (cfg->listen_addr) {
    struct in_addr  a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, cfg->listen_addr, &a4) == 1) {
      out->addr.sin.sin_family     = AF_INET;
      out->addr.sin.sin_addr       = a4;
      out->addr.sin.sin_port       = htons(port);
      out->size = sizeof(struct sockaddr_in);
      return 1;
    }
    if (inet_pton(AF_INET6, cfg->listen_addr, &a6) == 1) {
      out->addr.sin6.sin6_family   = AF_INET6;
      out->addr.sin6.sin6_addr     = a6;
      out->addr.sin6.sin6_port     = htons(port);
      out->size = sizeof(struct sockaddr_in6);
      return 1;
    }
    fprintf(stderr, "Invalid listen address: %s\n", cfg->listen_addr);
    return 0;
  }

  /* Default: bind to all IPv4 interfaces. */
  out->addr.sin.sin_family     = AF_INET;
  out->addr.sin.sin_addr.s_addr = INADDR_ANY;
  out->addr.sin.sin_port       = htons(port);
  out->size = sizeof(struct sockaddr_in);
  return 1;
}

static void format_bind_addr(const coap_address_t *addr, char *buf, size_t len) {
  if (addr->addr.sa.sa_family == AF_INET6) {
    buf[0] = '[';
    inet_ntop(AF_INET6, &addr->addr.sin6.sin6_addr, buf + 1, (socklen_t)(len - 2));
    strncat(buf, "]", len - strlen(buf) - 1);
  } else {
    if (addr->addr.sin.sin_addr.s_addr == INADDR_ANY) {
      strncpy(buf, "0.0.0.0", len - 1);
      buf[len - 1] = '\0';
    } else {
      inet_ntop(AF_INET, &addr->addr.sin.sin_addr, buf, (socklen_t)len);
    }
  }
}

static int configure_dtls_psk(coap_context_t *ctx, const char *psk_path) {
  coap_dtls_spsk_t dtls_psk;

  load_psk_file(psk_path);

  memset(&dtls_psk, 0, sizeof(dtls_psk));
  dtls_psk.version = COAP_DTLS_SPSK_SETUP_VERSION;
  dtls_psk.validate_id_call_back = psk_callback;
  dtls_psk.psk_info.hint.s = (const uint8_t *)"CoAP-HTTP-Proxy";
  dtls_psk.psk_info.hint.length = strlen("CoAP-HTTP-Proxy");

  if (client_count > 0) {
    dtls_psk.psk_info.key = clients[0].key_bin;
  }

  return coap_context_set_psk2(ctx, &dtls_psk);
}

static int configure_dtls_pki(coap_context_t *ctx,
                              const char *cert_file,
                              const char *key_file,
                              const char *ca_file) {
  coap_dtls_pki_t dtls_pki;

  memset(&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;

  /* If a CA is provided, enable peer certificate verification. */
  dtls_pki.verify_peer_cert = ca_file ? 1 : 0;
  dtls_pki.check_common_ca = ca_file ? 1 : 0;
  dtls_pki.allow_self_signed = ca_file ? 0 : 1;
  dtls_pki.cert_chain_validation = ca_file ? 1 : 0;
  dtls_pki.cert_chain_verify_depth = 3;

  dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
  dtls_pki.pki_key.key.pem.ca_file = ca_file;
  dtls_pki.pki_key.key.pem.public_cert = cert_file;
  dtls_pki.pki_key.key.pem.private_key = key_file;

  if (ca_file && !coap_context_set_pki_root_cas(ctx, ca_file, NULL)) {
    return 0;
  }

  return coap_context_set_pki(ctx, &dtls_pki);
}

static void load_psk_file(const char *filename) {
  FILE *f = fopen(filename, "r");
  if (!f) {
    perror("Error opening PSK file");
    exit(1);
  }

  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char *sep = strchr(line, ':');
    if (!sep) {
      continue;
    }

    *sep = '\0';
    char *identity = line;
    char *key = sep + 1;

    key[strcspn(key, "\r\n")] = '\0';

    if (client_count >= MAX_CLIENTS) {
      break;
    }

    size_t identity_len = strlen(identity);
    if (identity_len >= MAX_STR_LEN) {
      identity_len = MAX_STR_LEN - 1;
    }
    memcpy(clients[client_count].identity, identity, identity_len);
    clients[client_count].identity[identity_len] = '\0';

    size_t key_len = strlen(key);
    if (key_len >= MAX_STR_LEN) {
      key_len = MAX_STR_LEN - 1;
    }
    memcpy(clients[client_count].key, key, key_len);
    clients[client_count].key[key_len] = '\0';

    clients[client_count].key_bin.s = (const uint8_t *)clients[client_count].key;
    clients[client_count].key_bin.length = strlen(clients[client_count].key);

    client_count++;
  }

  fclose(f);
}

static const coap_bin_const_t *psk_callback(coap_bin_const_t *identity,
                                            coap_session_t *session,
                                            void *arg) {
  (void)session;
  (void)arg;

  if (!identity || !identity->s) {
    return NULL;
  }

  for (size_t i = 0; i < client_count; i++) {
    size_t id_len = strlen(clients[i].identity);
    if (identity->length == id_len &&
        memcmp(identity->s, clients[i].identity, id_len) == 0) {
      return &clients[i].key_bin;
    }
  }

  return NULL;
}

static const char *coap_code_to_http_method(coap_pdu_code_t code) {
  if (code == COAP_REQUEST_CODE_GET) {
    return "GET";
  }
  if (code == COAP_REQUEST_CODE_POST) {
    return "POST";
  }
  if (code == COAP_REQUEST_CODE_PUT) {
    return "PUT";
  }
  if (code == COAP_REQUEST_CODE_DELETE) {
    return "DELETE";
  }
  return NULL;
}

static coap_pdu_code_t http_status_to_coap_code(long status_code) {
  switch (status_code) {
  case 200:
    return COAP_RESPONSE_CODE_CONTENT;
  case 201:
    return COAP_RESPONSE_CODE_CREATED;
  case 202:
    return COAP_RESPONSE_CODE_VALID;
  case 204:
    return COAP_RESPONSE_CODE_CHANGED;
  case 400:
    return COAP_RESPONSE_CODE_BAD_REQUEST;
  case 401:
    return COAP_RESPONSE_CODE_UNAUTHORIZED;
  case 403:
    return COAP_RESPONSE_CODE_FORBIDDEN;
  case 404:
    return COAP_RESPONSE_CODE_NOT_FOUND;
  case 405:
    return COAP_RESPONSE_CODE_NOT_ALLOWED;
  case 408:
    return COAP_RESPONSE_CODE_REQUEST_TOO_LARGE;
  case 413:
    return COAP_RESPONSE_CODE_REQUEST_TOO_LARGE;
  case 415:
    return COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT;
  case 429:
    return COAP_RESPONSE_CODE_TOO_MANY_REQUESTS;
  case 500:
    return COAP_RESPONSE_CODE_INTERNAL_ERROR;
  case 501:
    return COAP_RESPONSE_CODE_NOT_IMPLEMENTED;
  case 502:
    return COAP_RESPONSE_CODE_BAD_GATEWAY;
  case 503:
    return COAP_RESPONSE_CODE_SERVICE_UNAVAILABLE;
  case 504:
    return COAP_RESPONSE_CODE_GATEWAY_TIMEOUT;
  default:
    if (status_code >= 200 && status_code < 300) {
      return COAP_RESPONSE_CODE_CONTENT;
    }
    if (status_code >= 400 && status_code < 500) {
      return COAP_RESPONSE_CODE_BAD_REQUEST;
    }
    return COAP_RESPONSE_CODE_INTERNAL_ERROR;
  }
}

static const char *coap_content_format_to_http(size_t fmt) {
  switch (fmt) {
  case COAP_MEDIATYPE_TEXT_PLAIN:
    return "text/plain";
  case COAP_MEDIATYPE_APPLICATION_JSON:
    return "application/json";
  case COAP_MEDIATYPE_APPLICATION_OCTET_STREAM:
    return "application/octet-stream";
  default:
    return "application/octet-stream";
  }
}

static void set_coap_response_content_format(coap_pdu_t *response,
                                             const char *content_type) {
  unsigned char buf[4];
  uint16_t media = COAP_MEDIATYPE_APPLICATION_OCTET_STREAM;

  if (content_type && strstr(content_type, "application/json")) {
    media = COAP_MEDIATYPE_APPLICATION_JSON;
  } else if (content_type && strstr(content_type, "text/plain")) {
    media = COAP_MEDIATYPE_TEXT_PLAIN;
  }

  coap_add_option(response, COAP_OPTION_CONTENT_FORMAT,
                  coap_encode_var_safe(buf, sizeof(buf), media), buf);
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  response_buffer_t *rb = (response_buffer_t *)userdata;
  size_t incoming = size * nmemb;

  if (!rb || incoming == 0) {
    return 0;
  }

  if (rb->len + incoming > MAX_RESPONSE_SIZE) {
    return 0;
  }

  if (rb->len + incoming > rb->cap) {
    size_t new_cap = rb->cap == 0 ? 4096 : rb->cap;
    while (new_cap < rb->len + incoming) {
      new_cap *= 2;
    }

    uint8_t *new_data = (uint8_t *)realloc(rb->data, new_cap);
    if (!new_data) {
      return 0;
    }

    rb->data = new_data;
    rb->cap = new_cap;
  }

  memcpy(rb->data + rb->len, ptr, incoming);
  rb->len += incoming;

  return incoming;
}

static int build_http_url_from_request(const coap_pdu_t *request,
                                       char *out, size_t out_len) {
  snprintf(out, out_len, "%s", http_base_url);

  coap_string_t *uri = coap_get_uri_path(request);
  if (!uri || uri->length == 0) {
    strncat(out, "/", out_len - strlen(out) - 1);
    if (uri) {
      coap_delete_string(uri);
    }
    return 0;
  }

  size_t curr = strlen(out);
  if (curr + 1 < out_len) {
    out[curr++] = '/';
    out[curr] = '\0';
  }

  size_t copy_len = uri->length;
  if (curr + copy_len >= out_len) {
    copy_len = out_len - curr - 1;
  }
  memcpy(out + curr, uri->s, copy_len);
  out[curr + copy_len] = '\0';
  coap_delete_string(uri);

  return 0;
}

static void proxy_request_to_http(coap_resource_t *resource,
                                  coap_session_t *session,
                                  const coap_pdu_t *request,
                                  const coap_string_t *query,
                                  coap_pdu_t *response) {
  (void)resource;
  (void)session;
  (void)query;

  const char *http_method = coap_code_to_http_method(coap_pdu_get_code(request));
  if (!http_method) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_NOT_ALLOWED);
    coap_add_data(response, 18, (const uint8_t *)"Method not allowed");
    return;
  }

  char url[MAX_PATH_LEN] = {0};
  build_http_url_from_request(request, url, sizeof(url));

  size_t payload_len = 0;
  const uint8_t *payload = NULL;
  coap_get_data(request, &payload_len, &payload);

  coap_opt_iterator_t opt_iter;
  const coap_opt_t *cf_opt = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
  size_t content_fmt = COAP_MEDIATYPE_APPLICATION_OCTET_STREAM;
  if (cf_opt) {
    content_fmt = coap_decode_var_bytes(coap_opt_value(cf_opt), coap_opt_length(cf_opt));
  }

  CURL *curl = curl_easy_init();
  if (!curl) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    const char *msg = "Failed to init HTTP client";
    coap_add_data(response, strlen(msg), (const uint8_t *)msg);
    return;
  }

  struct curl_slist *headers = NULL;
  char content_type_header[128] = {0};
  snprintf(content_type_header, sizeof(content_type_header), "Content-Type: %s",
           coap_content_format_to_http(content_fmt));
  headers = curl_slist_append(headers, content_type_header);

  response_buffer_t rb = {0};
  char errbuf[CURL_ERROR_SIZE] = {0};

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_method);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rb);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

  if (payload && payload_len > 0 && strcmp(http_method, "GET") != 0 &&
      strcmp(http_method, "DELETE") != 0) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)payload_len);
  }

  CURLcode rc = curl_easy_perform(curl);
  if (rc != CURLE_OK) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_GATEWAY);
    const char *msg = errbuf[0] ? errbuf : curl_easy_strerror(rc);
    coap_add_data(response, strlen(msg), (const uint8_t *)msg);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(rb.data);
    return;
  }

  long http_status = 0;
  char *resp_content_type = NULL;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
  curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &resp_content_type);

  coap_pdu_set_code(response, http_status_to_coap_code(http_status));
  set_coap_response_content_format(response, resp_content_type);

  if (rb.len > 0 && rb.data) {
    coap_add_data(response, rb.len, rb.data);
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  free(rb.data);
}

int main(int argc, char **argv) {
  coap_context_t *ctx;
  coap_address_t bind_addr;
  coap_endpoint_t *endpoint = NULL;
  proxy_config_t cfg;

  if (!parse_args(argc, argv, &cfg)) {
    return 1;
  }

  http_base_url = cfg.http_url;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  coap_startup();

  ctx = coap_new_context(NULL);
  if (!ctx) {
    fprintf(stderr, "Failed creating CoAP context\n");
    curl_global_cleanup();
    return 1;
  }

  if (cfg.dtls_set) {
    if (cfg.mode == DTLS_MODE_PSK) {
      if (!configure_dtls_psk(ctx, cfg.psk_path)) {
        fprintf(stderr, "Failed configuring DTLS PSK\n");
        coap_free_context(ctx);
        coap_cleanup();
        curl_global_cleanup();
        return 1;
      }
    } else {
      if (!configure_dtls_pki(ctx, cfg.cert_file, cfg.key_file, cfg.ca_file)) {
        fprintf(stderr, "Failed configuring DTLS PKI\n");
        coap_free_context(ctx);
        coap_cleanup();
        curl_global_cleanup();
        return 1;
      }
    }
  }

  if (!fill_bind_addr(&cfg, cfg.port, &bind_addr)) {
    coap_free_context(ctx);
    coap_cleanup();
    curl_global_cleanup();
    return 1;
  }

  endpoint = coap_new_endpoint(ctx, &bind_addr,
                               cfg.dtls_set ? COAP_PROTO_DTLS : COAP_PROTO_UDP);
  if (!endpoint) {
    fprintf(stderr, "Failed creating endpoint\n");
    coap_free_context(ctx);
    coap_cleanup();
    curl_global_cleanup();
    return 1;
  }

  coap_resource_t *proxy = coap_resource_unknown_init(proxy_request_to_http);
  coap_register_request_handler(proxy, COAP_REQUEST_GET, proxy_request_to_http);
  coap_register_request_handler(proxy, COAP_REQUEST_POST, proxy_request_to_http);
  coap_register_request_handler(proxy, COAP_REQUEST_PUT, proxy_request_to_http);
  coap_register_request_handler(proxy, COAP_REQUEST_DELETE, proxy_request_to_http);
  coap_add_resource(ctx, proxy);

  char addr_str[INET6_ADDRSTRLEN + 2] = {0};
  format_bind_addr(&bind_addr, addr_str, sizeof(addr_str));
  if (cfg.dtls_set) {
    printf("CoAP+DTLS -> HTTP reverse proxy listening on coaps://%s:%u\n",
           addr_str, cfg.port);
    if (cfg.mode == DTLS_MODE_PSK) {
      printf("DTLS mode: PSK (file: %s)\n", cfg.psk_path);
    } else {
      printf("DTLS mode: PKI (cert: %s, key: %s%s%s)\n",
             cfg.cert_file, cfg.key_file,
             cfg.ca_file ? ", ca: " : "",
             cfg.ca_file ? cfg.ca_file : "");
    }
  } else {
    printf("CoAP -> HTTP reverse proxy listening on coap://%s:%u\n",
           addr_str, cfg.port);
  }
  printf("Backend HTTP base URL: %s\n", http_base_url);

  while (1) {
    coap_io_process(ctx, COAP_IO_WAIT);
  }

  coap_free_context(ctx);
  coap_cleanup();
  curl_global_cleanup();

  return 0;
}
#endif
