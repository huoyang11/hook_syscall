TARGET := build
DIR := /home/yh/hook_syscall

all:$(TARGET)

$(TARGET):
	cd $(DIR)/drive  && $(MAKE)
	cd $(DIR)/app 	 && $(MAKE)

run:
	insmod $(DIR)/drive/hook_function.ko
	cd $(DIR)/bin 	 && ./hook_app

stop:
	rmmod hook_function

clean:
	cd $(DIR)/drive  && $(MAKE) $@
	cd $(DIR)/app 	 && $(MAKE) $@