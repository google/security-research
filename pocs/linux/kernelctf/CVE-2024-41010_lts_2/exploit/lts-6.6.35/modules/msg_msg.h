#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/ipc.h>

#ifndef MODULES_LIST_HEAD
#define MODULES_LIST_HEAD
struct list_head {
    struct list_head *next, *prev;
};
#endif

#ifndef MODULES_MSG_MSG
#define MODULES_MSG_MSG
struct msg_msg{
    struct list_head m_list;
    int64_t m_type;
    int m_ts;
    struct msg_msgseg *next;
    void *security;
    char m_text[];
};

struct msg_msgseg {
    struct msg_msgseg *next;
    char m_text[];
};

struct msg {
    int64_t m_type;
    char m_text[];
};

#define MSG_HEADER_SIZE sizeof(struct msg)
#define MSG_MSG_HEADER_SIZE sizeof(struct msg_msg)
#define MSG_MSGSEG_HEADER_SIZE sizeof(struct msg_msgseg)

#define MSG_MSG_KMALLOC_CG_64 (0x40 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_128 (0x80 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_192 (0xc0 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_256 (0x100 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_512 (0x200 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_1k (0x400 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_2k (0x800 - MSG_MSG_HEADER_SIZE)
#define MSG_MSG_KMALLOC_CG_4k (0x1000 - MSG_MSG_HEADER_SIZE)

#define MSG_MSGSEG_KMALLOC_CG_16 (0x10 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_32 (0x20 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_64 (0x40 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_128 (0x80 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_192 (0xc0 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_256 (0x100 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_512 (0x200 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_1k (0x400 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_2k (0x800 - MSG_MSGSEG_HEADER_SIZE)
#define MSG_MSGSEG_KMALLOC_CG_4k (0x1000 - MSG_MSGSEG_HEADER_SIZE)

int alloc_msg_queue(void);

void insert_msg_msg(int msqid, int64_t mtype, uint64_t objectsz, uint64_t msgsz, char *mtext);
char *read_msg_msg(int msqid, int64_t mtype, uint64_t msgsz);
void release_msg_msg(int msqid, int64_t mtype);

void insert_msg_msgseg(int msqid, int64_t mtype, uint64_t objectsz, uint64_t msgsz, char *mtext);
char *read_msg_msgseg(int msqid, int64_t mtype, uint64_t msgsz);
void release_msg_msgseg(int msqid, int64_t mtype);

struct msg_msg *fake_msg_msg(struct list_head *list_next, struct list_head *list_prev, int64_t mtype, int m_ts, void *next, char *mtext, uint64_t datalen);
struct msg_msgseg *fake_msg_msgseg(struct msg_msgseg *next, char *mtext, uint64_t datalen);
#endif