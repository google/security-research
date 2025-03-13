# kernelCTF exploit submission style guide

Note: this is a draft version of our style guide. Feel free to give feedback and improvement ideas on [Discord](https://discord.gg/ECS5VnJZys).

## High-level exploit structure

### Functions and their naming conventions

Structure the exploit's source code into separate functions based on what they do (see categories below), especially if it is a complex exploit.

The goal of this is to make it easy for the reader get a good understanding on how the exploit works just by reading the `main()` function alone (which should not be too long). Then the separate functions can be read for further details if needed.

If implementation of a function would be trivial (1-4 lines) then you don't have to put them into a separate function, but it should be clear what they do or commented accordingly.

Feel free to choose a structure which you deem the most readable, but there are a recommendations below, which we think helps to make the exploit more structured, easier to read and faster to review:

Using the following prefixes for your functions:

  * Setting up the environment.

    * `setup_` - generic functions which setup the environment (e.g. userns, CPU affinity, network interfaces)

  * Triggering a vulnerability.

    * `vuln_` - vulnerability related functions

    * `vuln_setup` - prepare victim structures before corruption

    * `vuln_trigger` - triggering vulnerability, making the initial corruption
      * Comment what type of corruption is happening (UAF, OOB, etc) in which objects (e.g. `drr_class`) and in which cache (e.g. `kmalloc-cg-1k`).

    * `race_` - functions helping to win a race (e.g. epoll)

  * Spraying or grooming the heap.

    * `spray_` - spraying related functions
      * For example: `spray_msg_msg_kmalloc_cg_1k`.
      * Make it clear what type object is sprayed and into which cache (e.g. `kmalloc-cg-1k`).

    * `fake_` - for creating fake objects which can be sprayed later
      * For example: `fake_msg_msg_for_oob_read` or `fake_msg_msg` in a more generic case.
      * Make it clear what type object is created, which fields are sets and in a more specialized case, what side-effect is achieved via this (e.g. primitive transfer into OOB read, arbitrary free, RIP control, etc).

  * Executing cross-cache attack.

    * `spray_cross_cache_` - cross-cache related functions

  * Leaking information (e.g. heap pointer, kASLR base address).

    * `leak_` - functions related for leaking
    * `leak_kaslr_` - leaking kASLR
    * `leak_heap_` - leaking heap address

  * Getting RIP control.

    * `rop_` - ROP-related functions (e.g. which create a ROP chain)
    * `rip_` - other RIP control primitives

Generic utility functions, which are not strictly related to this specific exploit, do not have to prefixed, but if you prefer, you can use the `util_` prefix or you can move them into separate `.h` files (e.g. `util.h`).

  * This category can include e.g. a generic `msgrcv` wrapper to make it easier to call the kernel API, but if you are using for spraying (e.g. in case of `msg_msg` just putting inside a for loop), then we would prefer it be prefixed with `spray_` instead.

### Exploit steps and connection to the writeup

Make sure that it's easy to understand which part of the exploit is described in which part of the writeup and vice versa.

You can make it very explicit by using one of the following comments:

  * `// @step(1)` - in case you are using numbered steps in your writeup
  * `// @step(name="Triggering the Vulnerability")` - where the name parameter matches one of the Markdown header titles (the text after one of the `#`, `##`, `###`, ... headers)

Although we prefer the above (it's more declarative), you can also use free-text comments as long as it makes it easier to understand.

## Sprayed and leaked structures

For structures which are used for spraying and for "fake objects" which are created in buffers, we recommend two approaches:

### Approach #1

Declare the whole structure in your exploit and cast the buffer pointer to a structure pointer and set the fields.

This works better if the whole or majority of the structure is used and if the structure does not contain too much not used fields.

<style>
    pre { padding: 3px 0 !important; border: none }
    .highlight { background-color: initial !important; }
    .markdown-body .highlight { margin-bottom: 5px }
    .markdown-body table { display: table; }
    .markdown-body td { width: 50%; }
    .markdown-body pre { padding: 0; background:none; border:none }
    .highlight .err { color: initial; background-color: initial }
    td p { font-size: 0.9em; margin:5px 0 10px 0 !important }
</style>

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05); background:rgba(255,0,0,0.05)">

```c
*(u64*)&msg[0x8] = prev;
*(u64*)&msg[0x10] = next;
*(u64*)&msg[0x18] = 0x42424242;
*(u64*)&msg[0x20] = 0x1d0;
*(u64*)&msg[0x28] = 0;
*(u64*)&msg[0x30] = 0;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
struct msg_msg {
  uint64_t m_list_next;
  uint64_t m_list_prev;
  uint64_t m_type;
  uint64_t m_ts;
  uint64_t next;
  uint64_t security;
};

…

msg_msg* msg = (msg_msg*)&buf[0x8];
msg->m_list_next = next;
msg->m_list_prev = prev;
msg->m_type = 0x42424242;
msg->m_ts = 0x1d0;
msg->next = 0;
msg->security = 0;
```
</td>
    </tr>
</table>

### Approach #2

If you need to only use a few fields from a structure, use `#define` for those offsets and name them as `<struct_name>_OFFS_<field_name>`. For example: `#define PIPE_BUFFER_OFFS_OPS 0x10`.

Make sure there are no typos in `<struct_name>` and `<field_name>`, so they can automatically parsed, and replaced if needed.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
*(size_t *)&rop[0x10] = rop_addr + 0x20;
*(size_t *)&rop[0x28] = PIVOT3;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define PIPE_BUFFER_OFFS_OPS 0x10
#define PIPE_BUF_OPS_OFFS_RELEASE 0x08

…

const int ops_offset = 0x20;

// struct pipe_buffer
char* fake_pipe = &buf[0];
*(uint64_t *)&fake_pipe[PIPE_BUFFER_OFFS_OPS] =
    buf_addr + ops_offset;

// struct pipe_buf_operations
char* fake_ops = &buf[ops_offset];
*(uint64_t *)&fake_ops[PIPE_BUF_OPS_OFFS_RELEASE] =
    PUSH_RSI_JMP_RSI_0x39;
```
</td>
    </tr>
</table>

Sizes should be defined as `<struct_name>_SIZE`.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
struct pipe_buffer *pbuf = (struct pipe_buffer *)
    &msg.mtext[0x1000 - 0x30 - 0x8];
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define PAGE_SIZE 0x1000
#define MSG_MSG_SIZE 0x30
#define MSG_MSGSEG_SIZE 0x8

…

struct pipe_buffer *pbuf = (struct pipe_buffer *)
    &msg.mtext[PAGE_SIZE - MSG_MSG_SIZE - MSG_MSGSEG_SIZE];
```
</td>
    </tr>
</table>

## Name and/or comment numeric constants

Numeric constants should be named whenever possible and/or their purpose should be explained in a comment.

Use exported enum values for kernel APIs (e.g. syscalls, ioctls) by including the appropriate header files. Locally `#define` non-exported one in your exploit.

Also use `#define`s for those values which could change depending on the target or which may require finetuning (including but not limited to):

  * structure sizes and field offsets
  * ROP gadget, stack pivot offsets, kernel symbols
  * memory addresses
  * spraying rounds

Comment other non-trivial constants and explain their usage (including but not limited to):

  * If they are used to satisfy a check within the kernel (e.g. in case they are part of a fake object) then comment there what check they need to satisfy.

  * If their value influences which cache the object gets into.

(You can also use comments instead of `#define`s if it is impractical to use `#define`.)

### Example: Kernel API enums

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
int sp = socket(0x10ul, 3ul, 0xc);
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
int sp = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
```
</td>
    </tr>
</table>

### Example: Kernel symbols, structure field offsets

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
kbase = *(size_t *)&msg.mtext[0x1000 -
    0x30 + 0x10 - 8] - 0x1a1cf80;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define ANON_PIPE_BUF_OPS 0x1a1cf80
#define PIPE_BUFFER_OFFS_OPS 0x10

…
char* pipe_leak = &msg.mtext[PAGE_SIZE -
    MSG_MSG_SIZE - MSG_MSGSEG_SIZE];

kbase = *(size_t*)pipe_leak[PIPE_BUFFER_OFFS_OPS] -
    ANON_PIPE_BUF_OPS;
```
</td>
    </tr>
</table>

### Example: Memory addresses

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
*(size_t*)&payload[0x60] = 0xfffffe000003df58;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define CPU_ENTRY_AREA_BASE(cpu) \
    (0xfffffe0000001000ull + (u64)cpu * 0x3b000)

// Address of cpu_entry_area's entry_stack_page where
// the payload is pushed in the error_entry function
#define CEA_PAYLOAD_LOCATION(cpu) \
    (CPU_ENTRY_AREA_BASE(cpu) + 0x1f58)

…

fake_drr_class->qdisc = CEA_PAYLOAD_LOCATION(0);
```
</td>
    </tr>
</table>

### Example: Non-trivial constant values

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
*(unsigned long*) &key_data[0] = 0xb000001010a;
*(unsigned long*) &key_data[8] = 6;

*(unsigned long*) &key_end_data[0] = 0x1400ff02010a;
*(unsigned long*) &key_end_data[8] = 17;

if(*(unsigned long *)&key_data == 0x3300000a050a) {
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// Explaination what the value "0xb000001010a"
// means in this context.
// What would happen if we would change it to
// something else?
// Would the exploit stop working or any other
// value work as well?
*(unsigned long*) &key_data[0] = 0xb000001010a;
…
```
</td>
    </tr>
</table>

### Example: Fake object values

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
data[i++] = 0x100;
data[i++] = 0x100;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// nft_rule_blob.size > 0
data[i++] = 0x100;
// nft_rule_blob.dlen > 0
data[i++] = 0x100;
```

</td>
    </tr>
</table>

### Example: Constant influences the used cache

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
mnl_attr_put_u32(nlh, …, htonl(-0x35));
```

</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// map size depend on map =
// ip_set_alloc(sizeof(*map) + elements * set->dsize);
// IPSET_FLAG_WITH_COMMENT cause set->dsize == 0x8
// 0x35*0x8 + sizeof(*map) is under kmalloc-cg-1024
mnl_attr_put_u32(nlh, …, htonl(-0x35));
```

</td>
    </tr>
</table>

## Naming conventions

Use descriptive names for including but not limited to: variables, functions, defines.

Make sure that the name is not misleading.

#### Example #1

Issue #1: Too generic function name (`foo`) which does not describe the purpose of the function which is saving data into the CPU Entry Area.

Issue #2: Misleading name (`rop`) from which the reader assumes that a ROP chain is written, while actually it contains a fake `pipe_buffer_ops` structure instead.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
foo(rop);
```

</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
write_to_cpu_entry_area(fake_pipe_buffer_ops);
```
</td>
    </tr>
</table>

#### Example #2

Avoid using one-character variable names (except for the iterator in a non-nested for loop).

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
char *z = "zzlol1994";
```

</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// Needs to be 9 characters long. Sprayed 1994 times.
char* spray_content = "pad__1994";
```
</td>
    </tr>
</table>

#### Example #3

Issue: too generic name (`payment`) which does not describe the purpose of the variable or where it will be used (it is a filter descriptor coded as bytes for setting up a `ctnetlink_filter`).

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
size_t payment[] = {
    0x0201010100000024, … };
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// ... comment describing what the payload contains ...
size_t ctnetlink_filter_payload[] = {
    0x0201010100000024, … };
```
</td>
    </tr>
</table>

#### Example #4

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
size_t rop[0x10] = {};
rop[0] = 0xffffffffcc000000 - 0x800;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define SPRAYED_EBPF_JIT_ADDR 0xffffffffcc000000 - 0x800
…
struct Qdisc {
    // int (*enqueue)(struct sk_buff *, 
    //   struct Qdisc *, struct sk_buff * *);
    uint64_t enqueue; // 0x00 - 0x08
}

…

char fake_qdisc_buf[80];
Qdisc* fake_qdisc = (Qdisc*) &fake_qdisc_buf;
fake_qdisc->enqueue = SPRAYED_EBPF_JIT_ADDR;
```
</td>
    </tr>
</table>

#### Example #5

The name of two variables (`buf` and `buffer`) are too similar and they are also too generic, it's easy to confuse the two. Use names which more precisely express the purpose of the variable, function, etc.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
char buf[0x1000];

void some_func()
{
    char buffer[0x1000];
    …
    for (...) {
        …
        ssize_t bytes_written = write(fd1,
            buffer, sizeof(buffer));
        ssize_t bytes_read = read(fd2,
            buffer, sizeof(buffer));
        …
        read(stopfd[0], buf, 1);
    }
    …
    read(stopfd[1], buf, 0x50);
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
char tmp_sync_buf[0x1000];

void some_func()
{
    char socket_payload_4k[0x1000];
    …
    for (…) {
        …
        ssize_t bytes_written = write(fd1,
            socket_payload_4k, sizeof(socket_payload_4k));
        ssize_t bytes_read = read(fd2,
            socket_payload_4k, sizeof(socket_payload_4k));
        …
        read(stopfd[0], tmp_sync_buf, 1);
    }
    …
    read(stopfd[1], tmp_sync_buf, 0x50);
}
```
</td>
    </tr>
</table>

## ROP chains

We prefer collecting target related details like symbol, ROP gadget and stack pivot offsets and structure sizes as `#define`s at the top of the file with descriptive names.

The exact kernel symbols names should be used which could be found in the kernel.

The full ROP / stack pivot gadget (e.g. `0xffffffff815282e1 : cmp rdx, 1 ; jne 0xffffffff8152831d ; pop rbp ; ret`) should be mentioned as a comment above or next to the gadget's `#define`.

In ROP chains, the `*rop++` approach is prefered over absolute addressing (`&rop[0x18]`) which makes the code easier to read and makes the ROP chain easier to move if needed.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
*(uint64_t *)&rop[0x78] = kernel_off +
    0xFFFFFFFF83B64120;//last type

//ROP gadget
*(uint64_t *)&rop[0x00] = kernel_off +
    0xffffffff8101a345;//pop rdi; ret
*(uint64_t *)&rop[0x08] = kernel_off +
    0xFFFFFFFF83876960;//init_cred
*(uint64_t *)&rop[0x10] = kernel_off +
    0xFFFFFFFF811C55A0;//commit_creds;
```

Note that `last type` is not a valid kernel symbol name.
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
// 0xffffffff81089250 : pop rdi ; ret
#define POP_RDI_RET 0x89250
#define FIND_TASK_BY_VPID 0xBFBC0

…

// switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)
*rop++ = kbase + POP_RDI_RET;
*rop++ = 1; // RDI
*rop++ = kbase + FIND_TASK_BY_VPID;
*rop++ = kbase + POP_RCX_RET;
*rop++ = 4; // RCX
```
</td>
    </tr>
</table>

## Unused code

Remove unused code parts (including variables, functions, globals, defines, includes, etc) from the source code.

Compiling your code with `-Wall` or `-Wunused` can help you track down these issues.

Make sure that the code is actually useful, for example if you are just setting a variable, but never read it, then it can be removed.

If the code cannot be removed for some reason, for example due to a non-trivial side-effect, then this needs to be clearly commented.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
#include "unused_include.h"

#define UNUSED_MACRO(x) (x + ...)

int unused_global_variable;

void unused_function() { … }

void used_function()
{
    int unused_local_variable = 42;
    …
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">
Unused code is removed.

```c
int used_global_variable;

void used_function()
{
    used_global_variable = 5;
    …
}

void main()
{
    used_function();
}
```
</td>
    </tr>
</table>

## Variable shadowing

Make sure you are not shadowing existing variables (neither global or local ones), choose a unique name for your variable, so you are not confusing the reader which variable is being referenced.

#### Example #1

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
int tfd; // global variable

void some_func()
{
    if (some_condition) {
        // local variable, shadow the global one
        int tfd;
        …
        // sets the local variable
        tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        …
    } else {
        // local variable, conflicts with
        // the other local one
        int tfd;
        …
        // sets a different local variable
        tfd = timerfd_create(CLOCK_MONOTONIC, 0);
        …
    }
}

void main()
{
    // sets the global variable
    tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    …
    some_func();
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
int global_tfd;

void some_func()
{
    if (some_condition) {
        int tfd_for_reason_X;
        …
        tfd_for_reason_X = timerfd_create(CLOCK_MONOTONIC, 0);
        …
    } else {
        int tfd_for_reason_Y;
        …
        tfd_for_reason_Y = timerfd_create(CLOCK_MONOTONIC, 0);
        …
    }
}

void main()
{
    global_tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    …
    some_func();
}
```

</td>
    </tr>
</table>

#### Example #2

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
char buf[0x1000]; // global variable

int uses_local_buf()
{
    // local variable, shadows the global one
    char buf[0x100] = {};
    read(fd1, buf, sizeof(buf));
    …
}

void main()
{
    …
    if(some_condition)
    {
        // another local variable, shadows the global one
        char buf[0x100] = {};
        read(fd2, buf, sizeof(buf));
    }

    // uses the global variable
    generate_rop_chain(buf);
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
char rop_buf[0x1000];

int check_core()
{
    char core_pattern_buf[0x100] = {};
    read(fd1, core_pattern_buf, sizeof(core_pattern_buf));
    …
}

void main()
{
    …
    if(some_condition) {
        char leak_buf[0x100] = {};
        read(fd2, leak_buf, sizeof(leak_buf));
    }

    generate_rop_chain(rop_buf);
}
```

</td>
    </tr>
</table>

## Commented out code

Remove code lines which are not used anymore from the source code or make them useful and optionally usable via command line arguments or `#ifdef` macros.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
// hexprint(received, size);
…
// debug();
…
// sleep(1);
…
// getchar();
…
// system("unshare -Urm");
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

Unused lines are removed. If they were used for debugging then they can be converted to conditionally executed code:
```c
bool debug_mode = contains(argv, "--debug")
…
if (debug_mode)
    hexprint(received, size);
```

Comments like this explaining the context are okay and should not be removed:
```c
// msleep(0x10000);
ROP(i++) = POP_RDI;
ROP(i++) = 0x10000;
ROP(i++) = MSLEEP;
```
</td>
    </tr>
</table>

## Sleeping & waiting

Add a comment to every `sleep()` and other non-trivial waiting functions (e.g. `membarrier`) what you are waiting for.

In case you are waiting for something to be happening in the kernel (GC, RCU, worker thread, etc), explicitly mention the name of the kernel function you are waiting for to be run.

Use the comment `// @sleep(kernel_func="<name_of_the_function>", desc="...")` if possible, which helps us automating this part later.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
del_chain(trig_chain_name);
usleep(300*1000);
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
del_chain(trig_chain_name);

// @sleep(kernel_func="nft_commit_release",
//        desc="wait for victim chain (trig_chain_name) to be freed")
usleep(300*1000);
```
</td>
    </tr>
</table>

## Generated code (e.g. Syzkaller)

Convert tool generated, less readable code into an easily human readable source code you write otherwise (and which is compliant with the other parts of the style guide).

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
mmap(0x20000000ul, 0x1000000ul, 7ul, 0x32ul, -1, 0ul);

res = socket(0x10ul, 3, 0);
if (res != -1)
    sock1 = res;

*(uint64_t*)0x20000040 = 0;
*(uint32_t*)0x20000048 = 0;
*(uint64_t*)0x20000050 = 0x20000100;
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
char kind[] = "tcindex";
netlink_attr(&nlmsg, TCA_KIND, &kind, sizeof(kind));

int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
if (sock == -1) {
    perror("netlink sock");
    exit(1);
}
```
</td>
    </tr>
</table>

_Note: the code on the left and right-side are not equivalent, they are just demonstrating the different coding styles._

## Explain duplicated lines

#### Example 1

Explain why `netlink_write_noerr(nl_sock_fd, &new_qfq_qdisc)` is called twice, otherwise it looks like a copy-paste mistake.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
init_qfq_qdisc_msg(&new_qfq_qdisc);
netlink_write_noerr(nl_sock_fd, &new_qfq_qdisc);
printf("[*] Triggering ROP chain\n");
netlink_write_noerr(nl_sock_fd, &new_qfq_qdisc);
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
init_qfq_qdisc_msg(&new_qfq_qdisc);

// This call creates a new QFQ object as it does
// not exist yet. The vulnerability is within the
// modification code, this creation path won't
// trigger the vuln.
netlink_write_noerr(nl_sock_fd, &new_qfq_qdisc);

printf("[*] Triggering ROP chain\n");
// We can use the same payload again to trigger
// the vulnerability as now the object already
// exists and now the payload will trigger the
// modification code path which contains the vuln.
netlink_write_noerr(nl_sock_fd, &new_qfq_qdisc);
```
</td>
    </tr>
</table>

#### Example 2

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
spray_sendmsg();
spray_sendmsg();
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
spray_sendmsg();
// Reuse the existing function to spray
// twice the number of objects.
spray_sendmsg();
```
</td>
    </tr>
</table>

## Match iteration count for allocation, creation and usage

Make sure you are allocating arrays for the same amount of objects you are actually creating and then you are using all of those objects (or if you are not make a comment about why not).

This makes your intentions clear for readers.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
struct nftnl_set * set_elem_triggers[0x200];

for(int i = 1 ; i <= 20; i++)
    for (int j = 1 ; j <= 20; j++)
        set_elem_triggers[(i-1) * 20 + (j-1)] =
            set_elem_trigger;

for(int i = 0 ; i < 200; i++)
    nftnl_set_elems_nlmsg_build_payload(nlh,
        set_elem_triggers[i]);
```

The code above:
 * allocates an array with `0x200` == `512` slots for the objects
 * actually creates `20` * `20` == `400` objects
 * uses `200` objects

It's not clear for the reader whether these are typos and bugs in the exploit (hex `0x200` != decimal `200`) or it is intentional.
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
#define SPRAY_DIM_X 20
#define SPRAY_DIM_Y 20
#define SPRAY_COUNT (SPRAY_DIM_X * SPRAY_DIM_Y)

struct nftnl_set * set_elem_triggers[SPRAY_COUNT];

for(int i = 1 ; i <= SPRAY_DIM_X; i++)
    for (int j = 1 ; j <= SPRAY_DIM_Y; j++)
        set_elem_triggers[(i-1) * SPRAY_DIM_Y + (j-1)] =
            set_elem_trigger;

for(int i = 0 ; i < SPRAY_COUNT; i++)
    nftnl_set_elems_nlmsg_build_payload(nlh,
        set_elem_triggers[i]);
```
</td>
    </tr>
</table>

## Language

Use English in your exploits (including but not limited to comments, variable names and strings).

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
__u64 value;         // 카운터 값
__u64 time_enabled;  // 활성화된 시간
__u64 time_running;  // 실제 카운팅한 시간
__u64 id;            // 이벤트 ID
__u64 lost;          // 잃어버린 이벤트 수
```

</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
__u64 value;         // Value of the counter
__u64 time_enabled;  // Active time
__u64 time_running;  // Actual time running
__u64 id;            // Event ID
__u64 lost;          // Number of lost events
```
</td>
    </tr>
</table>

## Miscellaneous notes

### Code duplication

Don't copy-paste big block of codes into separate places. Instead of that, create helper functions which contains the shared code blocks and call them instead.

Otherwise it can take a lot of time for the reader to understand the exact differences between the code duplicates.

You can always add arguments and simple branches to the helper functions if needed. Make them reusable.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
void vuln_trigger()
{
    struct nlmsghdr *nlh = mnl_nlmsg_create_header();

    … 15 lines of setting of the structure …

    … 2 lines unique for vuln_trigger …
}

void spray_nlmsg()
{
    struct nlmsghdr *nlh = mnl_nlmsg_create_header();

    … same 15 lines of code like previously …

    … 2 lines unique for spray_nlmsg …
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

```c
struct nlmsghdr *util_nlmsg_create(/* args */)
{
    struct nlmsghdr *nlh = mnl_nlmsg_create_header();

    … 15 lines of setting of the structure …
}

void vuln_trigger()
{
    struct nlmsghdr *nlh = util_nlmsg_create();

    … 2 lines unique for vuln_trigger …
}

void spray_nlmsg()
{
    struct nlmsghdr *nlh = util_nlmsg_create();

    … 2 lines unique for spray_nlmsg …
}
```
</td>
    </tr>
</table>

### Usage of global variables instead of local ones

Only use global variables if you really must to. Prefer using local variables instead. Otherwise the reader has to keep in mind that a global variable can chance at any time and it is harder to understand what a code does which uses a global variable. Questions like "Does the variable still contain the value which was set by another function?" or "Could another thread change this variable meanwhile?" can arise.

<table width="100%">
    <tr>
        <td width="50%">❌ Code to be improved</td>
        <td width="50%">✅ Expected code quality</td>
    </tr>
    <tr>
<td valign="top" markdown="1" style="background:rgba(255,0,0,0.05)">

```c
// global variable, never used outside of race_do_epoll_enqueue
int timefds[0x1000];

static void race_do_epoll_enqueue(int fd, int f)
{
    …
    for (int i = 0; i < 0x100; i++)
        timefds[i] = SYSCHK(dup(fd));
    …
            epoll_ctl_add(epfds[i], timefds[j], 0);
}
```
</td>
<td valign="top" markdown="1" style="background:rgba(0,255,0,0.05)">

The `timefds` variable was moved inside the `race_do_epoll_enqueue` function.

(Also, the array size now matches actual usage - `0x100` instead of `0x1000`.)

```c
static void race_do_epoll_enqueue(int fd, int f)
{
    int timefds[0x100];
    …
    for (int i = 0; i < 0x100; i++)
        timefds[i] = SYSCHK(dup(fd));
    …
            epoll_ctl_add(epfds[i], timefds[j], 0);
}
```
</td>
    </tr>
</table>

### Indentation

We prefer 4 spaces.
