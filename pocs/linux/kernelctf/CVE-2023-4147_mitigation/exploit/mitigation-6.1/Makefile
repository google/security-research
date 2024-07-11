LIBMNL_DIR = $(realpath ./)/libmnl_build
LIBNFTNL_DIR = $(realpath ./)/libnftnl_build

LIBS = -L$(LIBNFTNL_DIR)/install/lib -L$(LIBMNL_DIR)/install/lib -lnftnl -lmnl
INCLUDES = -I$(LIBNFTNL_DIR)/libnftnl-1.2.5/include -I$(LIBMNL_DIR)/libmnl-1.0.5/include
CFLAGS = -static -s

exploit:
	gcc -o exploit exploit.c $(LIBS) $(INCLUDES) $(CFLAGS)

prerequisites: libnftnl-build

libmnl-build : libmnl-download
	tar -C $(LIBMNL_DIR) -xvf $(LIBMNL_DIR)/libmnl-1.0.5.tar.bz2
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && ./configure --enable-static --prefix=`realpath ../install`
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && make -j`nproc`
	cd $(LIBMNL_DIR)/libmnl-1.0.5 && make install

libnftnl-build : libmnl-build libnftnl-download
	tar -C $(LIBNFTNL_DIR) -xvf $(LIBNFTNL_DIR)/libnftnl-1.2.5.tar.xz
	cp rule.c $(LIBNFTNL_DIR)/libnftnl-1.2.5/src/
	cp rule.h $(LIBNFTNL_DIR)/libnftnl-1.2.5/include/
	cp libnftnl_rule.h $(LIBNFTNL_DIR)/libnftnl-1.2.5/include/libnftnl/rule.h
	cd $(LIBNFTNL_DIR)/libnftnl-1.2.5 && PKG_CONFIG_PATH=$(LIBMNL_DIR)/install/lib/pkgconfig ./configure --enable-static --prefix=`realpath ../install`
	cd $(LIBNFTNL_DIR)/libnftnl-1.2.5 && C_INCLUDE_PATH=$(C_INCLUDE_PATH):$(LIBMNL_DIR)/install/include LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(LIBMNL_DIR)/install/lib make -j`nproc`
	cd $(LIBNFTNL_DIR)/libnftnl-1.2.5 && make install

libmnl-download :
	mkdir $(LIBMNL_DIR)
	wget -P $(LIBMNL_DIR) https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2

libnftnl-download :
	mkdir $(LIBNFTNL_DIR)
	wget -P $(LIBNFTNL_DIR) https://netfilter.org/projects/libnftnl/files/libnftnl-1.2.5.tar.xz

run:
	./exploit

clean:
	rm -f exploit
	rm -rf $(LIBMNL_DIR)
	rm -rf $(LIBNFTNL_DIR)
