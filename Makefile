# HMA++ Next KPM Module Makefile
# Author: NightFallsLikeRain
# 适配 Apatch KPM + Android 5.15+ 内核 + NDK r25c

# 模块名称（必须与最终生成的 .ko 文件名一致）
obj-m += HMA++.o

# 模块依赖源码文件（根据你的实际源码调整，比如 main.c、whitelist.c 等）
# 格式：模块名-objs := 源文件1.o 源文件2.o ...（无需写 .c 后缀）
HMA++-objs := main.o whitelist.o file_intercept.o ad_block.o

# 编译规则（命令前必须是 Tab 键，不能用空格！）
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
	rm -f *.mod.c *.mod.o *.o *.ko .*.cmd Module.symvers modules.order .tmp_versions
