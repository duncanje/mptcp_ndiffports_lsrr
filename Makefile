# Taken from Writing Netfilter Modules (Jan Engelhardt, Nicolas Bouliane) rev. July 3, 2012

MODULES_DIR	:= /lib/modules/$(shell uname -r)
KERNEL_DIR	:= ${MODULES_DIR}/build

obj-m += mptcp_ndiffports_lsrr.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
