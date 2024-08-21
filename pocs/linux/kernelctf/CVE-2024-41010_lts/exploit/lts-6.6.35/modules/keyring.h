#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/syscall.h>

#ifndef MODULES_KEYRING
#define MODULES_KEYRING

typedef int32_t key_serial_t;

#ifndef MODULES_RCU_CALLBACK_HEAD
#define MODULES_RCU_CALLBACK_HEAD
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};
#endif

struct user_key_payload {
	struct callback_head rcu;
	short unsigned int datalen;
	char data[];
};

struct keyring_ret {
	uint64_t size;
	char *data;
};

#define KEYRING_TYPE_USER "user"
#define KEYRING_TYPE_KEYRING "keyring"
#define KEYRING_TYPE_LOGON "logon"
#define KEYRING_TYPE_BIGKEY "big_key"

#define USER_KEY_PAYLOAD_SIZE (sizeof(struct user_key_payload))
#define KEYRING_KMALLOC_32 (0x20 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_64 (0x40 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_128 (0x80 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_256 (0x100 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_512 (0x200 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_1k (0x400 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_2k (0x800 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_4k (0x1000 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_8k (0x2000 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_16k (0x4000 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_32k (0x8000 - USER_KEY_PAYLOAD_SIZE)
#define KEYRING_KMALLOC_64k (0x10000 - USER_KEY_PAYLOAD_SIZE)

key_serial_t create_keyring(char *type, char *description, char *payload, uint64_t objectsz, key_serial_t ringid);
key_serial_t create_spec_keyring(char *type, char *description, char *payload, uint64_t objectsz);
key_serial_t create_simple_keyring(char *payload, uint64_t objectsz);

struct keyring_ret *read_keyring(key_serial_t ringid, uint64_t sz);
void update_keyring(key_serial_t ringid, char *payload, uint64_t objectsz);
void remove_keyring(key_serial_t ringid);

struct user_key_payload *fake_keyring(void *rcu_next, void *func, uint16_t datalen, char *data);
#endif