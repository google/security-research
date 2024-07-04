KDIR := /lib/modules/$(shell uname -r)/build

obj-m += msrscan.o

default:
	$(MAKE) -C $(KDIR) M='$(PWD)' modules

clean:
	$(MAKE) -C $(KDIR) M='$(PWD)' clean
