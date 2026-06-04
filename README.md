# CoAP or CoAP+DTLS -> HTTP reverse proxy

A simple COAP reverse proxy to an HTTP backend. It supports plain CoAP, secure CoAP over DTLS (both with PSK and with PKI), or both at once. The proxy maps CoAP URI paths directly to HTTP paths. Request are forwarded to an HTTP backend.

## Installing/Uninstalling

If not already installed, install compilation requirements with:

```bash
sudo apt install libcoap3-dev libcurl4-openssl-dev
```

Compile:

```bash
make
```

Install to default prefix `/usr/local/bin`. You need `sudo` above because normal users have no write permissions there.

```bash
sudo make install
```

Install with custom prefix directory (example: `~/.local/bin`):

```bash
make install PREFIX=~/.local/bin
```

Uninstall from the default prefix:

```bash
sudo make uninstall
```

or, for the above custom prefix:

```bash
make uninstall PREFIX=~/.local/bin
```

## Invocation

Arguments / options:

- `--help`, `-h`: Show command usage and exit
- `--dtls psk|pki`: Enable DTLS; omit for plain CoAP
- `--psk-file <path>`: PSK file path; **required** when `--dtls psk`. Each line must be `id:secret:encoding` where `encoding` is `utf8`, `base64` or `hex`.
- `--cert <path>`: Server certificate in PEM format; **required** when `--dtls pki`
- `--key <path>`: Server private key in PEM format; **required** when `--dtls pki`
- `--ca <path>`: CA certificate in PEM format (optional, `--dtls pki`)
- `--http-url <url>`: HTTP backend base URL (default: `http://localhost:3000`). It can be also specified as a positional argument.
- `--port <port>`: UDP port (default: `5684` with `--dtls`, `5683` without)
- `--listen-addr <ip>`: IPv4 or IPv6 address to bind to (default: all interfaces)
- `--listen-iface <if>`: Network interface to bind to, e.g. `eth0` (mutually exclusive with `--listen-addr`)

The HTTP backend URL is also accepted as a positional argument.

### Invocation examples

- Run with no arguments (plain CoAP + default backend <http://localhost:3000>):

  ```bash
  coap-http-reverseproxy
  ```

- Run with with custom backend URL:

  ```bash
  coap-http-reverseproxy http://127.0.0.1:10080
  ```

  or

  ```bash
  coap-http-reverseproxy --http-url http://172.16.0.5
  ```

- Run with CoAPS + PSK:

  ```bash
  coap-http-reverseproxy --dtls psk --psk-file psk.txt
  ```

  PSK file example:

  ```text
  alice:9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=:base64
  bob:086123b48edc51cd5b28a9cbae07273195af0188a6187de15adae67a97f574a5:hex
  carol:musupersecretpresharedpassword:utf8
  ```

- Run with certificates (PKI):

  ```bash
  coap-http-reverseproxy --dtls pki --cert server.crt --key server.key --ca ca.crt --http-url http://127.0.0.1:10080
  ```

- Run on a custom port:

  ```bash
  coap-http-reverseproxy --port 8683 --http-url http://127.0.0.1:3000
  ```

  or

  ```bash
  coap-http-reverseproxy --dtls psk --psk-file psk.txt --port 8684 --http-url http://127.0.0.1:3000
  ```

## Testing

You can use `coap-client-notls` or `coap-client-gnutls` to initially test the reverse proxuy operation. If not already installed, install them with:

```zsh
sudo apt update && sudo apt install libcoap3-bin
```

- Test the GET `/` endpoint without DTLS.

  ```zsh
  coap-client-notls -m get coap://127.0.0.1/
  ```

- Test the GET `/` endpoint with DTLS and valid client id and secret.

  ```zsh
  coap-client-gnutls -m get -u carol -k musupersecretpresharedpassword coaps://127.0.0.1/
  ```

## Example usecase with an Express.js backend and a command-line SOAP client

The directory `example` holds an implementation of an HTTP API backend (Node.js express.js) running behind a CoAPs to HTTP reverse proxy, and a node client performing:

1. A CoAP GET request to `/hello`
2. A CoAP POST `/data` sending JSON `{ msg: "Hello I'm Alice" }`

DTLS handshake is authenticated using a PSK between the client and the reverse proxy.
