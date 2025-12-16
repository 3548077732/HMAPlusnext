# 极简KPM模块Makefile（无额外依赖，通用所有Linux/Android内核）
objs := HMA++.o  # 对应你的源码文件名

# 基础编译参数（禁用冗余优化，确保兼容性）
EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter
EXTRA_CFLAGS += -O2  # 基础优化，平衡性能与兼容性
EXTRA_CFLAGS += -DMODULE -D__KERNEL__ -include linux/kconfig.h -include linux/autoconf.h

# 编译目标（默认使用当前内核头文件）
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# 支持指定内核头文件路径（适配交叉编译/自定义内核）
# 使用方式：make KERNELDIR=/path/to/kernel-headers
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
modules:
	make -C $(KERNELDIR) M=$(PWD) modules

# 清理编译产物（极简清理，无冗余）
clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f .cache.mk .tmp_versions Module.symvers modules.order

# 打包为KPM模块（调用KPM框架工具，通用打包）
package: all
	kpm pack \
		--name $(shell grep KPM_NAME HMA++.c | awk -F '"' '{print $$2}') \
		--version $(shell grep KPM_VERSION HMA++.c | awk -F '"' '{print $$2}') \
		--author $(shell grep KPM_AUTHOR HMA++.c | awk -F '"' '{print $$2}') \
		--license $(shell grep KPM_LICENSE HMA++.c | awk -F '"' '{print $$2}') \
		--description $(shell grep KPM_DESCRIPTION HMA++.c | awk -F '"' '{print $$2}') \
		--input HMA_Next.ko \
		--output $(shell grep KPM_NAME HMA++.c | awk -F '"' '{print $$2}').kpm
