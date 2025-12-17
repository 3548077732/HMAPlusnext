# 纯手动编译 Makefile（修复 NDK sysroot 路径，适配 Android 13-5.15+）
MODULE_NAME := HMA++
OBJ_NAME := $(MODULE_NAME).o
KO_NAME := $(MODULE_NAME).ko
KPM_NAME := $(MODULE_NAME).kpm

# 工具链配置（从 GitHub Actions 环境变量读取，路径修正）
NDK_ROOT ?= ./android-ndk-r25c
TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
CC := $(TOOLCHAIN)/bin/aarch64-linux-android24-clang
LD := $(TOOLCHAIN)/bin/ld.lld
# 关键修正：sysroot 在工具链目录下，而非 NDK 根目录
KERNELDIR := $(TOOLCHAIN)/sysroot

# 头文件路径（基于修正后的 sysroot，覆盖所有依赖）
INCLUDES := -I./kernel-headers \
            -I./kernel-headers/arch-arm64 \
            -I./kernel-headers/arch-arm64/asm \
            -I./kernel-headers/linux \
            -I./kernel-headers/asm-generic \
            -I./kernel-headers/uapi \
            -I$(KERNELDIR)/usr/include \
            -I$(KERNELDIR)/usr/include/aarch64-linux-android \
            -I$(NDK_ROOT)/sysroot/usr/include \
            -I$(NDK_ROOT)/sysroot/usr/include/aarch64-linux-android

# 编译选项（适配 5.15+ 内核 + LLVM，添加 KPM 头文件路径）
EXTRA_CFLAGS := $(INCLUDES) \
                -target aarch64-linux-android \
                -DKERNEL_5_15 \
                -D__KERNEL__ \
                -DMODULE \
                -Wall -O2 -fPIC -w \
                -fno-pie -fno-asynchronous-unwind-tables \
                -mgeneral-regs-only -march=armv8-a \
                -nostdinc -fno-common \
                -Wno-implicit-function-declaration \
                -Wno-incompatible-pointer-types \
                -I./kernel-headers/kpm  # 适配 KPM 头文件

# 模块编译规则（无缩进，语法零错误）
obj-m += $(OBJ_NAME)
$(OBJ_NAME): $(MODULE_NAME).c; $(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=arm64 CC=$(CC) LD=$(LD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

# 构建目标（产物重命名）
all: $(KO_NAME); mv $(KO_NAME) $(KPM_NAME); echo "✅ 编译完成！产物：$(KPM_NAME)"

# 清理目标
clean:; $(MAKE) -C $(KERNELDIR) M=$(PWD) clean; rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions; echo "✅ 清理完成！"

.PHONY: all clean
