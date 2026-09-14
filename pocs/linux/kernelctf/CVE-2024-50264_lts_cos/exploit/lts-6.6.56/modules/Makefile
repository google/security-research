# https://github.com/qwerty-po/kernel_exploit_modules

# define complier type
CC = gcc
# compile options setting
CFLAGS = -O2 -static
# library link & option setting

msg_msg.o: msg_msg.c
	$(CC) $(CFLAGS) -c $^

helper.o: helper.c
	$(CC) $(CFLAGS) -c $^

xattr.o: xattr.c
	$(CC) $(CFLAGS) -c $^

LDFLAGS = -lkeyutils
keyring.o: keyring.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $^

pipe.o: pipe.c
	$(CC) $(CFLAGS) -c $^

all: msg_msg.o helper.o xattr.o keyring.o pipe.o

clean:
	rm -f *.o