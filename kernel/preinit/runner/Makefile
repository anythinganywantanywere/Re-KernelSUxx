CC = zig cc
SRC = runner.c
TARGET = runner_binary
DUMP = runner_xxd.h

ZIG_VER := $(shell zig version)

CFLAGS += -target aarch64-linux -std=gnu2y
CFLAGS += -Oz -flto -s -static
CFLAGS += -fno-unwind-tables -fmerge-all-constants
CFLAGS +=  -fno-builtin-memcpy
CFLAGS += -Wl,--entry=__start
CFLAGS += -s -Wl,--gc-sections,-z,norelro
# 33cca775 (tiann #3933): pin max page size + contiguous segments so the
# runner's PT_LOAD stays page-aligned on 4K/16K kernels (elf_map() rejects
# unaligned p_offset, PID 1 would panic "Attempted to kill init").
CFLAGS += -Wl,-z,max-page-size=0x10000,-z,noseparate-code
CFLAGS += -Wno-int-conversion -Wno-unknown-attributes -Wno-macro-redefined

CFLAGS += -DZIG_VERSION=\"$(ZIG_VER)\"

all: $(TARGET) $(DUMP)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@
	@if command -v sstrip >/dev/null 2>&1; then sstrip $(TARGET); fi
#	@if command -v upx >/dev/null 2>&1; then upx --ultra-brute $(TARGET); fi

$(DUMP): $(TARGET)
# maybe in 10 years C23 #embed will be the norm
# for now not a big deal for a < 15kb binary.
	xxd -i $(TARGET) > $@
	tail -n1 $@
	rm -f $(TARGET)

clean:
	rm -f $(TARGET) > /dev/null 2>&1
	rm -f $(DUMP) > /dev/null 2>&1

.PHONY: all clean
