# CVE-2024-27397

Exploit for CVE-2024-27397 against the mitigation-v3-6.1.55 instance.
This exploit is based on my previous exploit against [CVE-2023-6817](https://github.com/google/security-research/blob/499284a767851f383681ea68e485a0620ccabce2/pocs/linux/kernelctf/CVE-2023-6817_mitigation/docs/exploit.md)
My goal was to re-use as much as possible, therefor the only differing bits will be in the initial setup to trigger CVE-2024-27397.
The rest of the original writeup will be recited for completeness sake.

## Abusing the vulnerability

Similar to CVE-2023-6817, the bug behind CVE-2024-27397 resides in the nftables subsystem.
(If you are unfamiliar, you may want to briefly read the
[docs](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes))

To recap, the goal of the original exploit was to create a setup like so:
- a table `T` containing:
    - a set `S`, which contains
        - an `NFT_JUMP` verdict to chain `B`
    - a base chain `A`, which contains
        - a rule with an `NFT_JUMP` verdict to chain `B`
    - a chain `B`, which contains
        - a rule with an `NFT_RETURN` verdict
        - a few junk rules

The idea behind the setup is to eventually drop the `NFT_JUMP` verdict in `S` twice in order
to lose one reference count leading to a use-after-free on `B`.

How do we create a similar setup using CVE-2024-27397?
In order to trigger the delay in the abort path, we need many junk operation to run.
I decided to go with the following idea (all within a single transaction, otherwise we cannot trigger the bug):
1) to existing set `S` add `NFT_JUMP` verdict to chain `B` with a very short expiration time (increment use count of `B`)
2) immediately delete set `S` (decrements use count of `B` because of verdict added in 1) which is not expired yet)
3) fill with junk operations, causing element added in 1) to expire
4) add an invalid operation causing the whole transaction to abort

With the transaction being aborted the steps are undone in reverse order.
We are most interested in step 2: Because the verdict of 1) expired during the transaction, the
use count decrement is _not_ undone and we successfully lost a reference count to chain `B`:
```c

// i) transaction aborts (nf_tables_api.c):
static int __nf_tables_abort(struct net *net, enum nfnl_abort_action action)
{
// ...
case NFT_MSG_DELSET:
			nft_use_inc_restore(&trans->ctx.table->use);
			nft_clear(trans->ctx.net, nft_trans_set(trans));
			if (nft_trans_set(trans)->flags & (NFT_SET_MAP | NFT_SET_OBJECT))
				nft_map_activate(&trans->ctx, nft_trans_set(trans));              // our set is re-activated

			nft_trans_destroy(trans);
			break;
// ...
}

// ii) set is re-activated, performs a walk on the set
static void nft_map_activate(const struct nft_ctx *ctx, struct nft_set *set)
{
	struct nft_set_iter iter = {
		.genmask	= nft_genmask_next(ctx->net),
		.fn		= nft_mapelem_activate,
	};

	set->ops->walk(ctx, set, &iter);
// ...
}

// iii) follow a walk, f.e. nft_set_rbtree.c:
static void nft_rbtree_walk(/* ... */)
{
// ...

	// iter all elements
	for (node = rb_first(&priv->root); node != NULL; node = rb_next(node)) {
		rbe = rb_entry(node, struct nft_rbtree_elem, node);
		// ...

		// check if the element expired: Uses the system time for comparison: oh-oh
		if (nft_set_elem_expired(&rbe->ext))
			goto cont; // whoops. element is expired thus we miss the re-activation below
		if (!nft_set_elem_active(&rbe->ext, iter->genmask))
			goto cont;

		elem.priv = rbe;

		// activate the element again
		iter->err = iter->fn(ctx, set, iter, &elem);
	}
// ...
}
```

To prepare for the malicious transaction, we thus create the following setup:
- table `T` containing:
  - set `S` (initially empty, prepared for timeout elements and verdict data)
  - chain `J` (junk, used for transaction stalls)
  - set `SJ_i` with (n number of sets, junk, also used for transaction stalls)
    - m times: verdict `NFT_JUMP` chain `J`
  - chain A (basechain)
    - `NFT_JUMP` chain B (1 use initially)
  - chain B
    - `NFT_RETURN`
    - a few junk rules

In order to satisfy step 3) from above, I decided to delete _n_ junk sets,
each containing _m_ elements, which introduces a sufficiently large delay with
sane parameters _n_ and _m_. The exploit uses 50 and 50000 respectively.

With the specific setup out of the way, the following is taken from the original
writeup of the exploit for CVE-2023-6817:

With the chain `B` use count decremented an additional time, the chain can
now be deleted even though chain `A` still contains an `NFT_JUMP` to it.

When chain `A` is triggered the following code is reached:
```c
// in net/netfilter/nf_tables_core.c
unsigned int
nft_do_chain(struct nft_pktinfo *pkt, void *priv)
{
	const struct nft_chain *chain = priv, *basechain = chain;
	const struct nft_rule_dp *rule, *last_rule;
	const struct nft_expr *expr, *last;
	struct nft_regs regs = {};
	struct nft_rule_blob *blob;
	/* ... snip ... */

do_chain:
	if (genbit)
		blob = rcu_dereference(chain->blob_gen_1);                  // [2.1]
	else
		blob = rcu_dereference(chain->blob_gen_0);

	rule = (struct nft_rule_dp *)blob->data;
	last_rule = (void *)blob->data + blob->size;                    // [2.2]
next_rule:
	regs.verdict.code = NFT_CONTINUE;
	for (; rule < last_rule; rule = nft_rule_next(rule)) {          // [2.3]
		nft_rule_dp_for_each_expr(expr, last, rule) {
			/* ... snip ... */
			if (expr->ops != &nft_payload_fast_ops ||
				 !nft_payload_fast_eval(expr, &regs, pkt))          // [2.4]
				expr_call_ops_eval(expr, &regs, pkt);               // [2.5]

			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		/* ... snip ... */

		break;
	}

	/* ... snip ... */

	switch (regs.verdict.code) {
	case NFT_JUMP:
		if (WARN_ON_ONCE(stackptr >= NFT_JUMP_STACK_SIZE))
			return NF_DROP;
		jumpstack[stackptr].chain = chain;
		jumpstack[stackptr].rule = nft_rule_next(rule);
		jumpstack[stackptr].last_rule = last_rule;
		stackptr++;
		fallthrough;
	case NFT_GOTO:
		chain = regs.verdict.chain;                                 // [2.6]
		goto do_chain;
	case NFT_CONTINUE:
	case NFT_RETURN:
		break;
	default:
		WARN_ON_ONCE(1);
	}

	/* ... snip ... */

	return nft_base_chain(basechain)->policy;
}
```

Since chain `A` contains a jump to chain `B`, the (now freed) chain pointer
to `B` is used as the current chain ([2.6]) and the `do_chain` loop is repeated.

While all the rules in the chain, and expressions in the rule are iterated
([2.3]), eventually the `expr->ops->eval()` function pointer is called in
`expr_call_ops_eval` ([2.5]).
This leaves us with a good candidate for gaining RIP control because we have full
control over the chain object since we freed it earlier.

## Mitigation Notes

We are targeting the mitigation instance, thus we have to take care of the extra
hardening options. Specifically we are interested in the following:
- `CONFIG_SLAB_VIRTUAL`
- `CONFIG_KMALLOC_SPLIT_VARSIZE`
- `CONFIG_RANDOM_KMALLOC_CACHES`

We will acknowledge `CONFIG_SLAB_VIRTUAL` assuming it is a sane mitigation against
cross cache attacks.
Therefor we have to find our way around the other two.

Looking at the allocation sites for the `struct nft_chain` object, we can
observe typicall calls to `kzalloc(sizeof(*chain), GFP_KERNEL_ACCOUNT)` leaving
the object subject to any of the `kmalloc-128-cg-X` caches (X being one of
the random ones).
This is hard to deal with, therefor we are looking for a way to pivot into one
of the `dyn-*` caches (`CONFIG_KMALLOC_SPLIT_VARSIZE`).
Luckily the `struct nft_chain` object contains plenty of pointers to other objects.
Additionally, when the chain object is destroyed, none of the pointers are cleared
(see `nf_tables_chain_destroy()` in `net/netfilter/nf_tables_api.c`).
Therefor we have access to additional objects, following all the freed helper
objects referenced by the original chain object.
We will focus on objects which are referenced during a chain walk in
`nft_do_chain`, other objects may be suitable for double-free scenarios but
we will not try to do that.

Thanks to the `CONFIG_RANDOM_KMALLOC_CACHES` hardening, the noise level in
the individual caches is extremely low.
Therefor we can assume that none of the original pointers will be corrupted when
we try to prepare the nested use-after-free.

```c
struct nft_chain {
	struct nft_rule_blob		__rcu *blob_gen_0;
	struct nft_rule_blob		__rcu *blob_gen_1;
	struct list_head		rules;
	struct list_head		list;
	struct rhlist_head		rhlhead;
	struct nft_table		*table;
	u64				handle;
	u32				use;
	u8				flags:5,
					bound:1,
					genmask:2;
	char				*name;
	u16				udlen;
	u8				*udata;
	struct nft_rule_blob		*blob_next;
};
```
The main pointers we are interesting in are the `blob_gen_{0,1}` members.
Each one is pointing to the current rule "generation" depending on the
`genmask` bits.
These rule blobs are allocated using `nf_tables_chain_alloc_rules`:
```c
static struct nft_rule_blob *nf_tables_chain_alloc_rules(unsigned int size)
{
	struct nft_rule_blob *blob;

	/* .. snip .. */

	blob = kvmalloc(size, GFP_KERNEL_ACCOUNT);

	/* .. snip .. */
	return blob;
}
```
Fortunate for us, blobs move into the `dyn-kmalloc-SIZE-cg-X` caches.

Still, we have to defeat `CONFIG_RANDOM_KMALLOC_CACHES` in order to find a
suitable object which can be used to reclaim the freed blob objects.
In order to achieve that, we will abuse a minor implementation issue of the random
kmalloc caches hardening.

Peeking at the generated code for the `kvmalloc()` call, we will notice that
it is inlined to a call to `kvmalloc_node()`:

```objdump
ffffffff813715f0 <kvmalloc_node>:
ffffffff813715f0:       e8 cb 5a da ff          call   ffffffff811170c0 <__fentry__>
ffffffff813715f5:       41 54                   push   %r12
ffffffff813715f7:       41 89 d4                mov    %edx,%r12d
ffffffff813715fa:       55                      push   %rbp
ffffffff813715fb:       48 89 fd                mov    %rdi,%rbp
ffffffff813715fe:       53                      push   %rbx
ffffffff813715ff:       89 f3                   mov    %esi,%ebx
ffffffff81371601:       48 81 ff 00 10 00 00    cmp    $0x1000,%rdi
ffffffff81371608:       77 09                   ja     ffffffff81371613 <kvmalloc_node+0x23>
ffffffff8137160a:       5b                      pop    %rbx
ffffffff8137160b:       5d                      pop    %rbp
ffffffff8137160c:       41 5c                   pop    %r12
ffffffff8137160e:       e9 dd cc 00 00          jmp    ffffffff8137e2f0 <__kmalloc_node>        [3.1]
ffffffff81371613:       89 f0                   mov    %esi,%eax
ffffffff81371615:       81 ce 00 20 01 00       or     $0x12000,%esi
ffffffff8137161b:       80 cc 20                or     $0x20,%ah
ffffffff8137161e:       f6 c7 40                test   $0x40,%bh
ffffffff81371621:       0f 45 f0                cmovne %eax,%esi
ffffffff81371624:       81 e6 ff 7f ff ff       and    $0xffff7fff,%esi
ffffffff8137162a:       e8 c1 cc 00 00          call   ffffffff8137e2f0 <__kmalloc_node>        [3.2]
...
```

As you can see in the snippet above, the call to `__kmalloc_node` is a proper
tail call when the size is smaller than `PAGE_SIZE` ([3.1]).
Otherwise the call will be explicit ([3.2]).

This is problematic because `__kmalloc_node` will use the return address as
the seed to derive the *random* cache to use.
Since all calls to `kvmalloc_node` will use the same seed when the size is large,
the hardening is rendered completely pointless.
Therefor our goal will be to increase the allocation size such that we hit the
`dyn-kmalloc-8192-cg` cache.

## Heap Spray

To recap, our setup consists of a chain `A` with a jump to a freed "chain" `B`.
We want to target the `blob_gen_{0,1}` members of type `struct nft_rule_blob` of
this freed object.

A `struct nft_rule_blob` is basically a flat binary blob of `struct nft_rule_dp`(s)
which are flat binary blobs of `struct nft_expr`:
```c
struct nft_expr {
	const struct nft_expr_ops	*ops;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(u64))));
};

struct nft_rule_dp {
	u64				is_last:1,
					dlen:12,
					handle:42;	/* for tracing */
	unsigned char			data[]
		__attribute__((aligned(__alignof__(struct nft_expr))));
};

struct nft_rule_blob {
	unsigned long			size;
	unsigned char			data[]
		__attribute__((aligned(__alignof__(struct nft_rule_dp))));
};
```

In order to increase the size of the blobs we can simply add many rules, each
containing a few expressions so that the size increases.

Now we only need an object which can be used to spray a controlled payload
using the same allocation primitive.
The most convenient object is `struct xt_table_info`:
```c
struct xt_table_info {
	unsigned int size;                                              // [4.1]
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[NF_INET_NUMHOOKS];
	unsigned int underflow[NF_INET_NUMHOOKS];
	unsigned int stacksize;
	void ***jumpstack;

	unsigned char entries[] __aligned(8);
};

// in net/netfilter/x_tables.c
struct xt_table_info *xt_alloc_table_info(unsigned int size)
{
	struct xt_table_info *info = NULL;
	size_t sz = sizeof(*info) + size;

	if (sz < sizeof(*info) || sz >= XT_MAX_TABLE_SIZE)
		return NULL;

	info = kvmalloc(sz, GFP_KERNEL_ACCOUNT);
	if (!info)
		return NULL;

	memset(info, 0, sizeof(*info));
	info->size = size;                                              // [4.2]
	return info;
}

static int
do_replace(struct net *net, sockptr_t arg, unsigned int len)
{
	int ret;
	struct ipt_replace tmp;
	struct xt_table_info *newinfo;
	void *loc_cpu_entry;
	struct ipt_entry *iter;

	if (copy_from_sockptr(&tmp, arg, sizeof(tmp)) != 0)
		return -EFAULT;

	/* .. snip .. */

	newinfo = xt_alloc_table_info(tmp.size);                        // [4.3]
	if (!newinfo)
		return -ENOMEM;

	loc_cpu_entry = newinfo->entries;
	if (copy_from_sockptr_offset(loc_cpu_entry, arg, sizeof(tmp),   // [4.4]
			tmp.size) != 0) {
		ret = -EFAULT;
		goto free_newinfo;
	}

	/* .. snip .. */

 free_newinfo:
	xt_free_table_info(newinfo);
	return ret;
}
```

Revisiting the code which is triggered during an nftables chain evaluation,
we need to have a sane `blob->size` member initialized ([2.2]), otherwise
individual rules in the blob would not be iterated.
This filters objects which have pointers or zeros as the first member, but
the `struct xt_table_info.size` member fits perfectly ([4.1]).

As seen on the `struct xt_table_info` allocation site, the whole structure is
cleared to zero on allocation and the size is set to the user provided value ([4.2]).
Eventually the full user provided payload is copied into the allocated buffer
prior to any sanitization ([4.4]).
In order to skip the sanitization step, we can simply force a fault during the
user copy.
Though this immediately frees our payload again, the content we care about is
written, and free list randomization will ensure that we can exhaust the full
cache with our fake objects.

Note that there is a `60` bytes hole between the payload and the size member.
These bytes are all zero, which fits the iteration in `nft_do_chain` perfectly.
Inspecting the macro expansion of the expression iteration (see [2.3]), we can see
that the loop exits before the first iteration because `rule->dlen` is zero:
```c
for ((expr) = (struct nft_expr *)&rule->data[0],
    (last) = (struct nft_expr *)&rule->data[rule->dlen];
     (expr) != (last); (expr) = ((void *)expr) + expr->ops->size)
{ /* .. */ }
```

Since the verdict is initialized to `NFT_CONTINUE` we continue iterating
rules until our actual payload is hit.

## Payload Considerations

When our payload is triggered in `expr_call_ops_eval()` the following arguments
are provided (in RDI, RSI, RDX respectively):
```c
	expr->ops->eval(expr, regs, pkt);
```

In order to resolve the pointer indirection required for dereferencing
`expr->ops->eval` we will utilize the deterministically known location of the
exception stacks in the CPU entry area. This issue is not fixed in the targeted
LTS release, thus useable for us.  This technique is well known and has been
documented several times (CVE-2023-0597).

We have full control over `expr` (the payload we sprayed) and limited control
over `regs` (the registers used by the nftables evaluation machine, which can be
read / written through expressions) and limited control over `pkt` which
contains data from the packet that we send to trigger the evaluation.

At the point of evaluation we are in an interrupt context, thus we have to be
more careful in order maximize the reliability.
I chose to restore execution directly at the end of the `nft_do_chain` function
call.

Since there are better jump gadgets using `rsi` we will setup a simple stack
pivot to `rdi` while using gadget pointers in the `regs` buffer.
In order to control the `regs` buffer we will utilize the fast paths for
expression evaluation, specifically the `nft_payload_fast_eval` call ([2.4]).
Through the creation of fake `struct nft_payload` expressions we can copy
data from the packet into the registers `regs`.

With a stack pivot setup into the fully controllable `expr` buffer, a
privilege escalation payload can be assembled trivially.

Finally, we only need to restore the stack to the previous state and eventually
jump into the `nft_do_chain` function trailer:
```objdump
ffffffff81e51380 <nft_do_chain>:
ffffffff81e51380:       e8 3b 5d 2c ff          call   ffffffff811170c0 <__fentry__>
ffffffff81e51385:       41 57                   push   %r15
...
ffffffff81e5139a:       48 81 ec 20 02 00 00    sub    $0x220,%rsp
ffffffff81e513a1:       65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
ffffffff81e513aa:       48 89 84 24 18 02 00    mov    %rax,0x218(%rsp)
ffffffff81e513b2:       48 8b 47 08             mov    0x8(%rdi),%rax
ffffffff81e513b6:       4c 8d 64 24 48          lea    0x48(%rsp),%r12                 [5.1]

...

ffffffff81e517e4:       48 81 c4 20 02 00 00    add    $0x220,%rsp
ffffffff81e517eb:       89 d0                   mov    %edx,%eax                       [5.2]
ffffffff81e517ed:       5b                      pop    %rbx
ffffffff81e517ee:       5d                      pop    %rbp
ffffffff81e517ef:       41 5c                   pop    %r12
ffffffff81e517f1:       41 5d                   pop    %r13
ffffffff81e517f3:       41 5e                   pop    %r14
ffffffff81e517f5:       41 5f                   pop    %r15
ffffffff81e517f7:       e9 84 34 5b 00          jmp    ffffffff82404c80 <__x86_return_thunk>
```

Looking at the beginning of the function, we can see that a pointer to the original
stack pointer is preserved in `r12`.
By selecting gadgets which do not clobber `r12` we will use this as a way
to restore the stack pointer.
Since we do control a lot of space in the CPU entry area, we can easily setup
a few jump gadgets which pivot the stack back from `expr` to the pointer in`r12`.
Eventually we will jump to the function trailer ([5.2]) and set the
return value to `NF_DROP` to make sure that we are not being called again.

## KASLR Bypass

We will use a `prefetch` timing side channel to bypass KASLR reliably.
The code for that is adapted from [here](https://github.com/IAIK/prefetch/blob/master/cacheutils.h).
We use a 7-trials majority vote for our final result.

Since this does not work on the AMD EPYC CPU used by the CI reproduction runner,
we use a slightly different approach when running the reproduction (use
`make real_exploit` for the real exploit which captured the flag).

It can be observed that the prefetch timings on the AMD CPU are significantly
larger when the memory is mapped by the kernel (contrary to the Intel CPU where
the timings are significantly lower for such memory).
We therefor "inverse" our timing logic and choose a region of contiguously mapped
memory that looks like the kernel text region.
When such a region is found, we assume it as base for KASLR.

## Reliability

The exploit should be close to 100% reliable as long as the KASLR leak is correct.
KASLR success chances varied from 90%-100% during local testing.
