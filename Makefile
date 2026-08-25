NASM ?= nasm
LD ?= ld
BUILD_DIR := build
BINARY := $(BUILD_DIR)/val0x04-asm
OBJECTS := $(BUILD_DIR)/main.o $(BUILD_DIR)/sha256.o
SHA256_TEST := $(BUILD_DIR)/sha256-vector
SHA256_TEST_OBJECT := $(BUILD_DIR)/sha256-vector.o

.PHONY: all clean run inspect test-crypto

all: $(BINARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/main.o: src/main.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BUILD_DIR)/sha256.o: src/sha256.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BINARY): $(OBJECTS)
	$(LD) -static -z noexecstack -o $@ $(OBJECTS)

$(SHA256_TEST_OBJECT): tests/sha256_vector.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(SHA256_TEST): $(SHA256_TEST_OBJECT) $(BUILD_DIR)/sha256.o
	$(LD) -static -z noexecstack -o $@ $(SHA256_TEST_OBJECT) $(BUILD_DIR)/sha256.o

test-crypto: $(SHA256_TEST)
	./$(SHA256_TEST)

run: $(BINARY)
	PORT=8080 BRIDGE_WEBSOCKET_AUTH_TOKEN=dev-bridge PANEL_ACCESS_TOKEN=dev-panel ./$(BINARY)

inspect: $(BINARY)
	file $(BINARY)
	readelf -d $(BINARY) || true

clean:
	rm -rf $(BUILD_DIR)
