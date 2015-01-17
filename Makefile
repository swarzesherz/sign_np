CC = gcc
CFLAGS = -Wall -I./libkirk

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

TARGET1 = libkirk/libkirk.a
OBJS1 = libkirk/kirk_engine.o libkirk/aes.o libkirk/sha1.o libkirk/amctrl.o libkirk/bn.o libkirk/ec.o

TARGET2 = sign_np
OBJS2 = sign_np.o eboot.o pgd.o isoreader.o tlzrc.o utils.o

all: $(TARGET1)

$(TARGET1): $(OBJS1)
	$(AR) rcs $@ $(OBJS1)

all: $(TARGET2)

$(TARGET2): $(OBJS2)
	$(CC) $(CFLAGS) -o $@ $(OBJS2) -L ./libkirk -lkirk -lz


