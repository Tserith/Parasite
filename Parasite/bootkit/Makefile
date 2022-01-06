EXPORT_START = --redefine-sym _binary_build_bootkit_bin_start=BootkitStart
EXPORT_END = --redefine-sym _binary_build_bootkit_bin_end=BootkitEnd

all: build/bootkit.obj

build/bootkit.obj: build/bootkit.bin
	objcopy -O pe-x86-64 -I binary -B i386:x86-64 $(EXPORT_START) $(EXPORT_END) $< $@

build/%.bin: build/%.exe
	objcopy -O binary -j .text.* $< $@

build/bootkit.exe: build/mbr16.obj build/idt32.obj build/idt64.obj
	ld -o $@ -T link.ld

build/%.obj: %.asm | build
	nasm -f win64 $< -o $@

build:
	mkdir build

clean:
	rm -f build/*.bin
	rm -f build/*.exe
	rm -f build/*.obj