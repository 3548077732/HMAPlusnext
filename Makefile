TARGET_COMPILE=./arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
KP_DIR = ./KernelPatch

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

CFLAGS = -I$(AP_INCLUDE_PATH) $(INCLUDE_FLAGS) -Wall -Ofast -fno-PIC -fno-asynchronous-unwind-tables -fno-stack-protector -fno-unwind-tables -fno-semantic-interposition -U_FORTIFY_SOURCE -fno-common -fvisibility=hidden

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
                -nostdinc -fno-common \
                -Wno-implicit-function-declaration \
                -Wno-incompatible-pointer-types \

# 模块编译规则（无缩进，语法零错误）
obj-m += $(OBJ_NAME)
$(OBJ_NAME): $(MODULE_NAME).c; $(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=arm64 CC=$(CC) LD=$(LD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

# 构建目标（产物重命名）
all: $(KO_NAME); mv $(KO_NAME) $(KPM_NAME); echo "✅ 编译完成！产物：$(KPM_NAME)"

# 清理目标
clean:; $(MAKE) -C $(KERNELDIR) M=$(PWD) clean; rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions; echo "✅ 清理完成！"

.PHONY: all clean
