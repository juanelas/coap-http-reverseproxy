# Example usecase with an Express.js backend and a command-line SOAP client

Example flow:

1. CoAP GET request to `/hello` -> HTTP GET request to `/hello`
2. CoAP POST request to `/data` -> HTTP POST request to `/data`

## Run the http backend

The Example backend code can be found at `http-backend` directory (already in this repository).

Install it:

```bash
npm install
```

And run it:

```bash
npm start
```

It will run the backend listening at `http://127.0.0.1:3000`.

## Run the COAP-HTTP reverse proxy

Reverse proxy files can be found at `reverse-proxy` directory.

Let us run a COAP (without TLS) reverse proxy at default port UDP 5683:

```zsh
coap-http-reverseproxy http://127.0.0.1:3000
```

Now, let us also run our reverse proxy using COAPS with DTLS authenticated with pre-shared keys (PSK). The PSKs are in the `psk.txt` file with one client per line with format `id:secret`.

```text
alice:9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=
bob:EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=
```

Excute the COAPS reverse proxy with:

```console
coap-http-reverseproxy --dtls psk --psk-file psk.txt http://127.0.0.1:3000
```

## Test

Let us use `coap-client` for example CoAP client calls.

If not already installed, install it with:

```zsh
sudo apt update && sudo apt install libcoap3-bin
```

- Test the GET `/hello` endpoint without DTLS.

  ```zsh
  coap-client-notls -m get coap://127.0.0.1/hello
  ```

  It should return:

  ```json
  {"message":"Hello from Express backend!"}`
  ```

- Test the GET `/hello` endpoint with DTLS and valid client id and secret.

  ```zsh
  coap-client-gnutls -m get -u bob -k EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M= coaps://127.0.0.1/hello
  ```

  It should return:

  ```json
  {"message":"Hello from Express backend!"}`
  ```

- Test the POST `/data` endpoint. It should return ``.

  ```zsh
  coap-client-gnutls -m post -u bob -k EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M= -t application/json -e '{"msg":"I am Bob"}' coaps://127.0.0.1/data
  ```

  It should return:

  ```json
  {"received":{"msg":"I am Bob"},"info":"Processed by Express backend"}
  ```
