SRC := $(wildcard *.c)
OBJ := $(patsubst %.c,%.o,$(SRC))
TARGET := hook_app
DIR := $(PWD)/../
CFLAGS := -g
CC     := gcc
INCLUDE := $(DIR)include
LIB	    := -llua -lm -ldl
BIN		:= $(DIR)bin

all:$(TARGET)

$(TARGET):$(OBJ)
	$(CC) $(CFLAGS) -o $(BIN)/$(TARGET) $^ -I$(INCLUDE)  $(LIB)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@ -I$(INCLUDE)

clean:
	rm -rf $(BIN)/$(TARGET) $(OBJ)
