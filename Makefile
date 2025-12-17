# Apatch KPM编译配置（内核5.15+）
obj-m += HMA++.o
KERNELDIR ?= /usr/src/linux-headers-$(shell uname -r)
CROSS_COMPILE ?= aarch64-linux-android-
ARCH ?= arm64
EXTRA_CFLAGS += -Wall -Wextra -DKERNEL_5_15_PLUS

# 强制指定头文件路径（解决缺失问题）
EXTRA_CFLAGS += -I$(PWD) -I$(KERNELDIR)/include -I$(KERNELDIR)/arch/arm64/include

all:
    $(MAKE) -j$(nproc) -C $(KERNELDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
    $(MAKE) -C $(KERNELDIR) ARCH=$(ARCH) M=$(PWD) clean
    rm -rf *.ko *.mod.* *.symvers *.order .tmp_versions
		echo "❌ 错误：KPM 打包失败，未生成 HMA++.kpm"; \
		exit 1; \
	fi
	echo "✅ 构建成功！产物清单："; \
	echo "  - 源码：HMA++.c"; \
	echo "  - 编译产物：HMA++.o、HMA_Next.ko"; \
	echo "  - KPM 模块：HMA++.kpm"; \
	echo "  - 产物路径：$(pwd)/HMA++.kpm"
