# HMA++ Next 终极 Makefile（无缩进，零语法错误）
MODULE_NAME := HMA++
OBJ_NAME := $(MODULE_NAME).o
KO_NAME := $(MODULE_NAME).ko
KPM_NAME := $(MODULE_NAME).kpm

# 工具链配置
NDK_ROOT ?= ./android-ndk-r25c
TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
CC := $(TOOLCHAIN)/bin/aarch64-linux-android24-clang
LD := $(TOOLCHAIN)/bin/ld.lld
KERNELDIR := $(NDK_ROOT)/sysroot

# 头文件+编译选项（一行到底）
INCLUDES := -I./kernel-headers -I./kernel-headers/arch-arm64 -I./kernel-headers/arch-arm64/asm -I./kernel-headers/linux -I./kernel-headers/asm-generic -I./kernel-headers/uapi -I$(KERNELDIR)/usr/include -I$(KERNELDIR)/usr/include/aarch64-linux-android
EXTRA_CFLAGS := $(INCLUDES) -target aarch64-linux-android -DKERNEL_5_15 -D__KERNEL__ -DMODULE -Wall -O2 -fPIC -w -fno-pie -fno-asynchronous-unwind-tables -mgeneral-regs-only -march=armv8-a -nostdinc -fno-common -Wno-implicit-function-declaration -Wno-incompatible-pointer-types

# 模块编译规则（无缩进，用 ; 连接命令）
obj-m += $(OBJ_NAME)
$(OBJ_NAME): $(MODULE_NAME).c; $(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=arm64 CC=$(CC) LD=$(LD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

# 构建目标（无缩进，用 ; 连接）
all: $(KO_NAME); mv $(KO_NAME) $(KPM_NAME); echo "✅ 编译完成！产物：$(KPM_NAME)"

# 清理目标（无缩进，用 ; 连接）
clean:; $(MAKE) -C $(KERNELDIR) M=$(PWD) clean; rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions; echo "✅ 清理完成！"

# 伪目标声明
.PHONY: all clean
