TARGET := hook_function
obj-m:=$(TARGET).o
$(TARGET)-objs = module.o hook.o hook_open.o hook_connect.o
KDIR:=/lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
