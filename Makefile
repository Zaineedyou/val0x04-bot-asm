NASM ?= nasm
CC ?= gcc
LD ?= ld
BUILD_DIR := build
BINARY := $(BUILD_DIR)/val0x04-asm
ASM_OBJECTS := $(BUILD_DIR)/main.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/tls_record.o
ADAPTER_OBJECTS := $(BUILD_DIR)/driver.o $(BUILD_DIR)/secure_transport.o
OBJECTS := $(ASM_OBJECTS) $(ADAPTER_OBJECTS)
CRYPTO_TEST := $(BUILD_DIR)/crypto-vectors
CRYPTO_TEST_OBJECT := $(BUILD_DIR)/crypto-vectors.o
CFLAGS := -O2 -std=c11 -Wall -Wextra -Werror
CURL_CFLAGS := $(shell pkg-config --cflags libcurl)
CURL_LIBS := $(shell pkg-config --libs libcurl)

.PHONY: all clean run inspect test-crypto source-ratio

all: $(BINARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/main.o: src/main.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/sha256.o: src/sha256.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/tls_record.o: src/tls_record.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/driver.o: adapter/driver.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CURL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/secure_transport.o: adapter/secure_transport.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CURL_CFLAGS) -c $< -o $@

$(BINARY): $(OBJECTS)
	$(CC) -no-pie -Wl,-z,noexecstack -o $@ $(OBJECTS) $(CURL_LIBS)

$(CRYPTO_TEST_OBJECT): tests/sha256_vector.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(CRYPTO_TEST): $(CRYPTO_TEST_OBJECT) $(BUILD_DIR)/sha256.o $(BUILD_DIR)/tls_record.o
	$(LD) -static -z noexecstack -o $@ $(CRYPTO_TEST_OBJECT) $(BUILD_DIR)/sha256.o $(BUILD_DIR)/tls_record.o

test-crypto: $(CRYPTO_TEST)
	./$(CRYPTO_TEST)

run: $(BINARY)
	PORT=8080 BRIDGE_WEBSOCKET_AUTH_TOKEN=dev-bridge PANEL_ACCESS_TOKEN=dev-panel ./$(BINARY)

inspect: $(BINARY)
	file $(BINARY)
	ldd $(BINARY)

source-ratio:
	@asm=$$(find src -name '*.asm' -print0 | xargs -0 cat | wc -l); \
	c=$$(find adapter -name '*.c' -print0 | xargs -0 cat | wc -l); \
	total=$$((asm + c)); \
	printf 'NASM: %s lines (%.1f%%)\nC adapter: %s lines (%.1f%%)\n' $$asm "$$(awk "BEGIN {print 100 * $$asm / $$total}")" $$c "$$(awk "BEGIN {print 100 * $$c / $$total}")"

clean:
	rm -rf $(BUILD_DIR)
