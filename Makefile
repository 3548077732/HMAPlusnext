# ==============================================
# HMA++ Next KPM 模块 Makefile（语法修复版）
# 适配：Android 13 5.15 内核 | arm64 架构 | NDK r25c
# 产物：HMA++.kpm（内核模块 .ko 重命名）
# ==============================================

# -------------------------- 基础配置 --------------------------
MODULE_NAME := HMA++
OBJ_NAME    := $(MODULE_NAME).o
KO_NAME     := $(MODULE_NAME).ko
KPM_NAME    := $(MODULE_NAME).kpm

# -------------------------- 工具链配置 --------------------------
NDK_ROOT ?= ./android-ndk-r25c
TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64
CC        := $(TOOLCHAIN)/bin/aarch64-linux-android24-clang
LD        := $(TOOLCHAIN)/bin/ld.lld
OBJCOPY   := $(TOOLCHAIN)/bin/llvm-objcopy
NM        := $(TOOLCHAIN)/bin/llvm-nm
KERNELDIR := $(NDK_ROOT)/sysroot

# -------------------------- 头文件路径 --------------------------
INCLUDES := -I./kernel-headers \
            -I./kernel-headers/arch-arm64 \
            -I./kernel-headers/arch-arm64/asm \
            -I./kernel-headers/linux \
            -I./kernel-headers/asm-generic \
            -I./kernel-headers/uapi \
            -I$(KERNELDIR)/usr/include \
            -I$(KERNELDIR)/usr/include/aarch64-linux-android

# -------------------------- 编译选项（修复语法：反斜杠后无空格） --------------------------
EXTRA_CFLAGS := $(INCLUDES) \
-DKERNEL_5_15 \
-D__KERNEL__ \
-DMODULE \
-Wall -O2 -fPIC -w \
-fno-pie -fno-asynchronous-unwind-tables \
-mgeneral-regs-only -march=armv8-a \
-nostdinc -fno-common \
-Wno-implicit-function-declaration \
-Wno-incompatible-pointer-types \
-target aarch64-linux-android

# -------------------------- 模块编译规则 --------------------------
obj-m += $(OBJ_NAME)

# 命令行必须以 Tab 缩进（关键！）
$(OBJ_NAME): $(MODULE_NAME).c
	$(MAKE) -C $(KERNELDIR) \
	M=$(PWD) \
	ARCH=arm64 \
	CC=$(CC) \
	LD=$(LD) \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	modules

# -------------------------- 构建目标 --------------------------
all: $(KO_NAME)
	mv $(KO_NAME) $(KPM_NAME)
	@echo "✅ 编译完成！产物：$(KPM_NAME)"

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions
	@echo "✅ 清理完成！"

info:
	@echo "模块名称：$(MODULE_NAME)"
	@echo "目标架构：arm64"
	@echo "内核版本：5.15"
	@echo "NDK 路径：$(NDK_ROOT)"
	@echo "产物路径：$(KPM_NAME)"

.PHONY: all clean info
