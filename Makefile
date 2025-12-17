# ==============================================
# HMA++ Next KPM 模块 Makefile（纯手动编译版）
# 适配：Android 13 5.15 内核 | arm64 架构 | NDK r25c
# 产物：HMA++.kpm（内核模块 .ko 重命名）
# ==============================================

# -------------------------- 基础配置 --------------------------
MODULE_NAME := HMA++
OBJ_NAME    := $(MODULE_NAME).o
KO_NAME     := $(MODULE_NAME).ko
KPM_NAME    := $(MODULE_NAME).kpm

# -------------------------- 工具链配置 --------------------------
# NDK 路径（默认适配 CI 环境，本地编译可手动指定：make NDK_ROOT=/path/to/android-ndk-r25c）
NDK_ROOT ?= ./android-ndk-r25c
TOOLCHAIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64

# 编译器与工具（NDK r25c arm64 专用）
CC        := $(TOOLCHAIN)/bin/aarch64-linux-android24-clang
LD        := $(TOOLCHAIN)/bin/ld.lld
OBJCOPY   := $(TOOLCHAIN)/bin/llvm-objcopy
NM        := $(TOOLCHAIN)/bin/llvm-nm
KERNELDIR := $(NDK_ROOT)/sysroot  # 内核系统根目录

# -------------------------- 头文件路径（关键！解决所有头文件缺失） --------------------------
INCLUDES := \
    -I./kernel-headers \
    -I./kernel-headers/arch-arm64 \
    -I./kernel-headers/arch-arm64/asm \
    -I./kernel-headers/linux \
    -I./kernel-headers/asm-generic \
    -I./kernel-headers/uapi \
    -I$(KERNELDIR)/usr/include \
    -I$(KERNELDIR)/usr/include/aarch64-linux-android

# -------------------------- 编译选项（兼容 5.15 内核 + LLVM） --------------------------
EXTRA_CFLAGS := $(INCLUDES) \
    -target aarch64-linux-android \  # 明确目标架构
    -DKERNEL_5_15 \                 # 标识 5.15 内核
    -D__KERNEL__ \                  # 内核态编译标识
    -DMODULE \                      # 模块编译标识
    -Wall -O2 -fPIC -w \            # 基础优化与警告控制
    -fno-pie -fno-asynchronous-unwind-tables \  # 内核模块兼容
    -mgeneral-regs-only -march=armv8-a \        # arm64 架构适配
    -nostdinc -fno-common \         # 禁用标准库与公共符号
    -Wno-implicit-function-declaration \  # 兼容内核隐式声明
    -Wno-incompatible-pointer-types        # 兼容内核指针类型

# -------------------------- 模块编译规则（标准内核模块流程） --------------------------
# 声明模块目标（obj-m 表示编译为可加载模块）
obj-m += $(OBJ_NAME)

# 编译模块核心逻辑：调用内核 Makefile 编译当前模块
$(OBJ_NAME): $(MODULE_NAME).c
	$(MAKE) -C $(KERNELDIR) \
		M=$(PWD) \                # 当前项目目录
		ARCH=arm64 \              # 目标架构
		CC=$(CC) \                # 指定编译器
		LD=$(LD) \                # 指定链接器
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \  # 附加编译选项
		modules  # 执行内核模块编译

# -------------------------- 构建目标 --------------------------
# 默认目标：编译模块并命名为 HMA++.kpm
all: $(KO_NAME)
	mv $(KO_NAME) $(KPM_NAME)
	@echo "✅ 编译完成！产物：$(KPM_NAME)"

# 清理目标：删除所有编译产物与中间文件
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -rf $(KPM_NAME) *.mod.c *.o .*.cmd Module.symvers modules.order .tmp_versions
	@echo "✅ 清理完成！"

# -------------------------- 辅助目标（可选） --------------------------
# 查看模块信息
info:
	@echo "模块名称：$(MODULE_NAME)"
	@echo "目标架构：arm64"
	@echo "内核版本：5.15"
	@echo "NDK 路径：$(NDK_ROOT)"
	@echo "产物路径：$(KPM_NAME)"

# 伪目标声明（避免与文件重名）
.PHONY: all clean info
