# Example usecase of a with an Express.js backend and a command-line SOAP client

This is an example usecase of a CoAPs-HTTP reverse proxy handling connections from a CoAPs client to an HTTP backend behind the proxy.

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

It will run the backend listening at `http://127.0.0.1:3000`. The backend has tow endpoints:

1. GET `/hello`. It should return JSON:

   ```json
   {"message":"Hello from Express backend!"}`
   ```

2. POST `/data`. It expects a JSON such as `{"msg":"I am Bob"}` and returns (for the previous JSON):
  
   ```json
   {"received":{"msg":"I am Bob"},"info":"Processed by Express backend"}
   ```

## Run the COAP-HTTP reverse proxy

Reverse proxy files can be found at `reverse-proxy` directory.

We could run a COAP (without TLS) reverse proxy for our http backend at default port UDP 5683 with:

```zsh
coap-http-reverseproxy http://127.0.0.1:3000
```

Now, let us also run our reverse proxy using COAPS with DTLS authenticated with pre-shared keys (PSK). The PSKs are in the `psk.txt` file with one client per line with format `id:secret:encoding`, where `encoding` can be `utf8`, `base64`, or `hex`.

```text
alice:9yPztDNbbBkV41JIhL833lfXX+zyBfPaD8VLCK0C88w=:base64
bob:EiAT3eboMqOa0ddtwsiX57JUBnw08ClON7wLR7n8N2M=:base64
```

Excute the COAPS reverse proxy listening at default port 5684 with:

```console
coap-http-reverseproxy --dtls psk --psk-file psk.txt http://127.0.0.1:3000
```

## Run a Node.js CoAPS client

The Node client example is in [example/coap-client/index.js](example/coap-client/index.js). It uses the package node-coap-client and sends:

1. GET to coaps://localhost:5684/hello. Expected return is JSON:

   ```json
   {"message":"Hello from Express backend!"}`
   ```

2. POST to coaps://localhost:5684/data with JSON payload `{"msg":"Hello, I'm Alice"}`. Expected return is JSON:

   ```json
   {"received":{"msg":"Hello, I'm Alice"},"info":"Processed by Express backend"}
   ```

The client authenticates with DTLS-PSK using identity alice. The key is loaded from the same base64 value used in [example/reverse-proxy/psk.txt](example/reverse-proxy/psk.txt).

From the [example/coap-client](example/coap-client):

Install it:

```bash
npm install
```

And run it:

```bash
npm start
```

Expected output is similar to:

```text
$ npm start

> coap-client@1.0.0 start
> node index.js

GET coaps://localhost:5684/hello ...
  Response status: 2.05
  Response payload: {"message":"Hello from Express backend!"}
POST coaps://localhost:5684/data {"msg":"Hello, I'm Alice"} ...
  Response status: 2.05
  Response payload: {"received":{"msg":"Hello, I'm Alice"},"info":"Processed by Express backend"}
```

### Troubleshooting

- Handshake/authentication errors: verify identity/key in [example/coap-client/index.js](example/coap-client/index.js#L3) matches [example/reverse-proxy/psk.txt](example/reverse-proxy/psk.txt), and that it is properly loaded as UTF-8, hexadecimal or Base64.
- Timeout/refused connection: verify the proxy is listening on UDP 5684 and reachable from localhost
- 4.xx/5.xx CoAP response codes: verify the backend is running
