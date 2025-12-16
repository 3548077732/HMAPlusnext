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
