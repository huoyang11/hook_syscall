TARGET := hook_function
DIR := $(PWD)/../
ccflags-y := -I$(DIR)include 
obj-m:=$(TARGET).o
$(TARGET)-objs = module.o hook.o hook_open.o hook_connect.o
KDIR:=/lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	insmod $(TARGET).ko

unintall:
	rmmod $(TARGET)

clean:
	make -C $(KDIR) M=$(PWD) clean
