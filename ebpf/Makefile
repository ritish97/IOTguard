# Makefile for IoTGuard eBPF / XDP Kernel Program
CC = clang
CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

all: iotguard_xdp.o

iotguard_xdp.o: iotguard_xdp.c
	$(CC) $(CFLAGS) -c $< -o $@

load: iotguard_xdp.o
	@echo "Attaching IoTGuard XDP program to eth0..."
	ip link set dev eth0 xdpgeneric obj iotguard_xdp.o sec xdp

unload:
	@echo "Detaching IoTGuard XDP program from eth0..."
	ip link set dev eth0 xdpgeneric off

clean:
	rm -f iotguard_xdp.o
