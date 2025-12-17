# HMA++ Next KPM Module Makefile
# Author: NightFallsLikeRain
# 适配单源码文件 HMA++.c + Apatch KPM + Android 5.15+ 内核

# 模块名称（与源码文件 HMA++.c 对应，生成 HMA++.ko）
obj-m += HMA++.o

# 编译规则（命令前必须是 Tab 键，不可用空格！）
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
	rm -f *.mod.c *.mod.o *.o *.ko .*.cmd Module.symvers modules.order .tmp_versions
