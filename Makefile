# HMA++ Next KPM Module Makefile
# Author: NightFallsLikeRain
obj-m += HMA++.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean
	rm -f *.mod.c *.mod.o *.o *.ko .*.cmd Module.symvers modules.order .tmp_versions
