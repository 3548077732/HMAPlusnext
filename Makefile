TARGET_COMPILE=./arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
KP_DIR = ./KernelPatch

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := HMA++.o

all: HMA++.kpm

HMA++.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
# 清理目标
clean:; $(MAKE) -C $(KERNELDIR) M=$(PWD) clean; rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions; echo "✅ 清理完成！"

.PHONY: all clean
