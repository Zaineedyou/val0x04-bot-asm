NASM ?= nasm
LD ?= ld
BUILD_DIR := build
BINARY := $(BUILD_DIR)/val0x04-asm
OBJECT := $(BUILD_DIR)/main.o

.PHONY: all clean run inspect

all: $(BINARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OBJECT): src/main.asm | $(BUILD_DIR)
	$(NASM) -f elf64 -g -F dwarf $< -o $@

$(BINARY): $(OBJECT)
	$(LD) -static -z noexecstack -o $@ $<

run: $(BINARY)
	PORT=8080 BRIDGE_WEBSOCKET_AUTH_TOKEN=dev-bridge PANEL_ACCESS_TOKEN=dev-panel ./$(BINARY)

inspect: $(BINARY)
	file $(BINARY)
	readelf -d $(BINARY) || true

clean:
	rm -rf $(BUILD_DIR)
