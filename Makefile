# Start with empty flags
CFLAGS  :=
LDFLAGS :=

ifeq ($(LTO),y)
CFLAGS  += -flto
LDFLAGS += -flto
endif

# There is a 64k total limit, so optimise for size.  The binary may be loaded
# at an arbitray location, so build it as position independent, but link as
# non-pie as all relocations are internal and there is no dynamic loader to
# help.
CFLAGS  += -Os -g -MMD -MP -mno-sse -mno-mmx -fpie -fomit-frame-pointer
CFLAGS  += -Iinclude -ffreestanding -Wall
LDFLAGS += -nostdlib -no-pie -Wl,--build-id=none

# Derive AFLAGS from CFLAGS
AFLAGS := -D__ASSEMBLY__ $(filter-out -std=%,$(CFLAGS))

# Collect objects for building.  For simplicity, we take all ASM/C files
ASM := $(wildcard *.S)
SRC := $(wildcard *.c)
OBJ := $(ASM:.S=.o) $(SRC:.c=.o)

.PHONY: all
all: lz_header.bin

-include Makefile.local

# Generate a flat binary
#
# As a sanity check, look for the LZ UUID at its expected offset in the binary
# image.  One reason this might fail is if the linker decides to put an
# unreferenced section ahead of .text, in which case link.lds needs adjusting.
lz_header.bin: lz_header Makefile
	objcopy -O binary -S --pad-to 0x10000 $< $@
	@od --format=x8 --skip-bytes=4 --read-bytes=16 $@ | \
		grep "0000004 e91192048e26f178 02ccc4765bc82a83" > /dev/null || \
		{ echo "ERROR: LZ UUID missing or misplaced in $@" >&2; false; }

lz_header: link.lds $(OBJ) Makefile
	$(CC) -Wl,-T,link.lds $(LDFLAGS) $(OBJ) -o $@

%.o: %.c Makefile
	$(CC) $(CFLAGS) -o $@ -c $<

%.o: %.S Makefile
	$(CC) $(AFLAGS) -c $< -o $@

# Helpers for debugging.  Preprocess and/or compile only.
%.E: %.c Makefile
	$(CC) $(CFLAGS) -E $< -o $@
%.S: %.c Makefile
	$(CC) $(CFLAGS) -S $< -o $@

.PHONY: cscope
cscope:
	find . -name "*.[hcsS]" > cscope.files
	cscope -b -q -k

.PHONY: clean
clean:
	rm -f lz_header.bin lz_header *.d *.o cscope.*

# Compiler-generated header dependencies.  Should be last.
-include $(OBJ:.o=.d)
