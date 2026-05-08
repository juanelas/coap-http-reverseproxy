CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lcoap-3-openssl -lcurl
PREFIX ?= /usr/local/bin

BIN = coap-http-reverseproxy
SRC = coap-http-reverseproxy.c

TEST_BIN = tests/test_args
TEST_SRC = tests/test_args.c

.PHONY: all test install uninstall clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

install: $(BIN)
	install -d "$(PREFIX)"
	install -m 0755 "$(BIN)" "$(PREFIX)/$(BIN)"

uninstall:
	rm -f "$(PREFIX)/$(BIN)"

$(TEST_BIN): $(TEST_SRC) $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(BIN) $(TEST_BIN)
