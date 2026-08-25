NASM ?= nasm
LD ?= ld
BUILD_DIR := build
BINARY := $(BUILD_DIR)/val0x04-asm
OBJECTS := $(BUILD_DIR)/main.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/tls_record.o
CRYPTO_TEST := $(BUILD_DIR)/crypto-vectors
CRYPTO_TEST_OBJECT := $(BUILD_DIR)/crypto-vectors.o

.PHONY: all clean run inspect test-crypto

all: $(BINARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/main.o: src/main.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/sha256.o: src/sha256.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/tls_record.o: src/tls_record.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BINARY): $(OBJECTS)
	$(LD) -static -z noexecstack -o $@ $(OBJECTS)

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
	readelf -d $(BINARY) || true

clean:
	rm -rf $(BUILD_DIR)
