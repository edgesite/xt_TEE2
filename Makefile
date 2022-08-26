obj-m = xt_TEE2.o
CFLAGS_xt_TEE2.o := ${CFLAGS}
KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
