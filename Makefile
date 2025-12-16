# 极简KPM模块Makefile（源码文件：HMA++.c）
obj-m += HMA_Next.o
HMA_Next-objs := HMA++.o  # 明确指定源码文件为 HMA++.c（编译后生成 HMA++.o）

# 基础编译参数（兼容所有内核，禁用冗余警告）
EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter
EXTRA_CFLAGS += -O2  # 平衡性能与兼容性
EXTRA_CFLAGS += -DMODULE -D__KERNEL__ -include linux/kconfig.h -include linux/autoconf.h

# 编译目标（默认使用当前内核头文件）
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# 支持指定自定义内核头文件路径
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
modules:
	make -C $(KERNELDIR) M=$(PWD) modules

# 清理产物（包含 KPM 产物和 .o 文件）
clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f .cache.mk .tmp_versions Module.symvers modules.order HMA++.kpm HMA++.o  # 明确清理源码编译产物

# 打包为 KPM 模块（强制产物名：HMA++.kpm，与源码名呼应）
package: all
	# 第一步：校验源码编译产物 HMA++.o 是否存在
	if [ ! -f "HMA++.o" ]; then \
		echo "❌ 错误：源码 HMA++.c 编译失败，未生成 HMA++.o"; \
		exit 1; \
	fi
	# 第二步：校验内核模块 .ko 是否生成
	if [ ! -f "HMA_Next.ko" ]; then \
		echo "❌ 错误：内核模块链接失败，未生成 HMA_Next.ko"; \
		exit 1; \
	fi
	# 第三步：打包 KPM（强制输出为 HMA++.kpm，与源码名一致）
	kpm pack \
		--name $(shell grep KPM_NAME HMA++.c | awk -F '"' '{print $$2}') \
		--version $(shell grep KPM_VERSION HMA++.c | awk -F '"' '{print $$2}') \
		--author $(shell grep KPM_AUTHOR HMA++.c | awk -F '"' '{print $$2}') \
		--license $(shell grep KPM_LICENSE HMA++.c | awk -F '"' '{print $$2}') \
		--description $(shell grep KPM_DESCRIPTION HMA++.c | awk -F '"' '{print $$2}') \
		--input HMA_Next.ko \
		--output HMA++.kpm  # 产物名与源码名保持一致，避免混淆
	# 第四步：校验 KPM 产物是否生成
	if [ ! -f "HMA++.kpm" ]; then \
		echo "❌ 错误：KPM 打包失败，未生成 HMA++.kpm"; \
		exit 1; \
	fi
	echo "✅ 构建成功！产物清单："; \
	echo "  - 源码：HMA++.c"; \
	echo "  - 编译产物：HMA++.o、HMA_Next.ko"; \
	echo "  - KPM 模块：HMA++.kpm"; \
	echo "  - 产物路径：$(pwd)/HMA++.kpm"
