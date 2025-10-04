#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

#include <sys/types.h>

#ifndef MODULES_PIPE
#define MODULES_PIPE

struct pipe_inode_info {
	struct pipe_buffer *bufs;
	unsigned long nrbufs, curbuf;
};

struct pipe_buffer;
struct pipe_buf_operations {
	/*
	 * ->confirm() verifies that the data in the pipe buffer is there
	 * and that the contents are good. If the pages in the pipe belong
	 * to a file system, we may need to wait for IO completion in this
	 * hook. Returns 0 for good, or a negative error value in case of
	 * error.  If not present all pages are considered good.
	 */
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * When the contents of this pipe buffer has been completely
	 * consumed by a reader, ->release() is called.
	 */
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Attempt to take ownership of the pipe buffer and its contents.
	 * ->try_steal() returns %true for success, in which case the contents
	 * of the pipe (the buf->page) is locked and now completely owned by the
	 * caller. The page may then be transferred to a different mapping, the
	 * most often used case is insertion into different file address space
	 * cache.
	 */
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);

	/*
	 * Get a reference to the pipe buffer.
	 */
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private_v;
};

struct pipeio {
	struct {
		int readfd, writefd;
	} pipe;
	bool is_ops_activated;
};

#define PIPE_BUFFER_KMALLOC_CG_64 (PAGE_SIZE)
#define PIPE_BUFFER_KMALLOC_CG_192 (PAGE_SIZE * 4)
#define PIPE_BUFFER_KMALLOC_CG_512 (PAGE_SIZE * 8)
#define PIPE_BUFFER_KMALLOC_CG_1k (PAGE_SIZE * 16)
#define PIPE_BUFFER_KMALLOC_CG_2k (PAGE_SIZE * 32)
#define PIPE_BUFFER_KMALLOC_CG_4k (PAGE_SIZE * 64)
#define PIPE_BUFFER_KMALLOC_CG_8k (PAGE_SIZE * 128)
#define PIPE_BUFFER_KMALLOC_CG_16k (PAGE_SIZE * 256)
#define PIPE_BUFFER_KMALLOC_CG_32k (PAGE_SIZE * 512)
#define PIPE_BUFFER_KMALLOC_CG_64k (PAGE_SIZE * 1024)

struct pipeio *create_pipeio(void);

void activate_ops(struct pipeio *pipe);
void resize_pipe(struct pipeio *pipe, uint64_t objectsz);
void read_pipe(struct pipeio *pipe, char *buf, uint64_t size);
void write_pipe(struct pipeio *pipe, char *buf, uint64_t size);
void release_pipe(struct pipeio *pipe);

void trigger_ops_release(struct pipeio *pipe);

struct pipe_buffer *fake_pipe_buffer(struct page *page, uint32_t offset, uint32_t len, void *ops, uint32_t flags, unsigned long private_v);
struct pipe_buf_operations *fake_pipe_buf_ops(void *release);
#endif