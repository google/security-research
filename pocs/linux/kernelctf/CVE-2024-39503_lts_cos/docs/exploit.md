# CVE-2024-39503

Exploit Documentation for CVE-2024-39503 against lts-6.6.30 / cos-109-17800.218.20 instance.

## Stage 1: Triggering the vulnerability

As described in the vulnerability documentation, we are targeting a race condition in the ip set
subsystem. A successful trigger would result in a user-after-free on a `struct ip_set` in
`kmalloc-192`.
```c
/* A generic IP set */
struct ip_set {
	/* For call_cru in destroy */
	struct rcu_head rcu;
	/* The name of the set */
	char name[IPSET_MAXNAMELEN];
	/* Lock protecting the set data */
	spinlock_t lock;
	/* References to the set */
	u32 ref;
	/* References to the set for netlink events like dump,
	 * ref can be swapped out by ip_set_swap
	 */
	u32 ref_netlink;
	/* The core set type */
	struct ip_set_type *type;
	/* The type variant doing the real job */
	const struct ip_set_type_variant *variant;
	/* The actual INET family of the set */
	u8 family;
	/* The type revision */
	u8 revision;
	/* Extensions */
	u8 extensions;                                        // [0.1]
	/* Create flags */
	u8 flags;
	/* Default timeout value, if enabled */
	u32 timeout;
	/* Number of elements (vs timeout) */
	u32 elements;
	/* Size of the dynamic extensions (vs timeout) */
	size_t ext_size;
	/* Element data size */
	size_t dsize;
	/* Offsets to extensions in elements */
	size_t offset[IPSET_EXT_ID_MAX];                      // [0.2]
	/* The type specific data */
	void *data;                                           // [0.3]
};
```

A successful trigger could result from a scenario which looks like this:
```
  CPU 0                  CPU 1
// cleanup_net()
synchronize_rcu();       ...

                         GC runs, list_set_del [1.1]

ip_set_net_exit [1.2]
< GC is cleaned up >
ip_set_destroy_set [1.3]
< set is free now >      ...

[ spray window ]

                         < rcu clean up runs >
                         __list_set_del_rcu [1.4]
                          ==> use-after-free
```

The general setup for this will be seperated into three processes:
- main: this is the root process which will spawn the spray process and repeat on failure
- spray: spawns the bug trigger process and will perform the heap spray
- bug: sets up the bug trigger in its own namespace which will exit when the process exits
    and thus performs one try at hitting the race.

Because our bug requires interaction with multiple namespaces such "complex" process
structure is sadly required.

Let's look at each process in more detail.
The main process is not really important for now, its main purpose is to provide a
retry loop.

The spray process is arguably the most important one.
It runs once for each try of hitting the race.
In the initial stage it will do the following things in order:
1. Prepare the bug trigger process in a new usernamespace
2. Prepare spraying primitives and other post-trigger required setup
3. Signal the bug trigger process to perform one try
4. Wait for the bug trigger process to exit
5. Perform the heap spray and check for success.

By timing the delay between 4. and 5. in a "good" way, the heap spray will
run concurrently to the namespace cleanup triggered by the bug process.
Special care is taken to assign the CPU cores in order to ensure that the spray
runs on the same core as the trigger. Additionally the cleanup has to run on
another core so that they can run truly concurrently.

If the bug was triggered successfully _and_ the spray successfully reclaimed one of
the freed sets in time, the `__list_set_del_rcu` cleanup path in [1.4] will
use our sprayed payload and we proceed to the next stage.

The bug process will try to prepare good conditions for a positive race outcome.
Specifically it will do the following:
Prepare 10 list sets (which introduce the vulnerability), each with a garbage
collector that runs after a 1 second timeout (+- some jiffies).
To each of those sets we add the same one element with a short timeout.
(We choose `bitmap:port` as the element set, for no specific reason)
We do not send this payload straight away, rather pack it into one large netlink
message which will be send all at once to increase control over the timings.
At this point we wait for the signal to trigger the bug.

With the signal ready, we setup a timer in our process which triggers after a certain
timeout close to 1 second to match the garbage collector.
With the timer setup, we send the full netlink payload actually creating all the
sets and their elements.
We then wait for the timer to expire and exit the process as it happens.

This way, we force the namespace cleanup to run approximately at the same time
as the garbage collector will run.
The larger number of sets increases our likelyhood of hitting the race for one of
them.

### Stage 1 Payload Considerations

Stage 1 is basically a one-shot scenario: We only have a brief time window where
we can reclaim the freed object with a payload in `kmalloc-192`.
Therefore some special considerations are required for the payload.

Luckily, the RCU callback proves to be very helpful:
```c
static void
__list_set_del_rcu(struct rcu_head * rcu)
{
	struct set_elem *e = container_of(rcu, struct set_elem, rcu);
	struct ip_set *set = e->set;  // [2.1]

	ip_set_ext_destroy(set, e); // [2.2]
	kfree(e);
}

#define ext_comment(e, s)	\
((struct ip_set_comment *)(((void *)(e)) + (s)->offset[IPSET_EXT_ID_COMMENT]))

static inline void
ip_set_ext_destroy(struct ip_set *set, void *data)
{
	/* Check that the extension is enabled for the set and
	 * call it's destroy function for its extension part in data.
	 */
	if (SET_WITH_COMMENT(set)) {
		struct ip_set_comment *c = ext_comment(data, set);  // [2.3]

		ip_set_extensions[IPSET_EXT_ID_COMMENT].destroy(set, c);
	}
}
```

Note that we are spraying a fake set, specifically our payload will correspond
to the set pointer fetched at [2.1].
Following the call chain [2.2] to `ip_set_ext_destroy` we can modify the set
to contain a comment extension ([0.1]) which will result in the "comment" being
freed. For the `list:set` type, extensions live on the element itself
(i.e. `struct set_elem`) and are referred to by an offset value ([0.2]) which is
stored in the owning set (i.e. our payload). Therefor we can set arbitrary
offsets here and essentially cause an arbitrary free.
To better understand the primitive have a closer look at the comment destroy function:
```c
struct ip_set_comment_rcu {
	struct rcu_head rcu;
	char str[];
};

struct ip_set_comment {
	struct ip_set_comment_rcu __rcu *c;
};

static void
ip_set_comment_free(struct ip_set *set, void *ptr)
{
	struct ip_set_comment *comment = ptr;
	struct ip_set_comment_rcu *c;

	c = rcu_dereference_protected(comment->c, 1);  // [2.4]
	if (unlikely(!c))
		return;
	set->ext_size -= sizeof(*c) + strlen(c->str) + 1; // [2.5]
	kfree_rcu(c, rcu);  // [2.6]
	rcu_assign_pointer(comment->c, NULL);
}
```

It will read the actual comment pointer from offset we specified ([2.4]) and,
given that it is not `NULL`, run a `kfree_rcu` on it ([2.6]).
This means, by choosing the offset in such a way that it adds to a location with
a useful pointer value, we can free that (possibly arbitrary) object.

The simplest victim object to choose for this is the `*set` itself, as it is
already present on the `struct set_elem` object at offset 32:
```c
/* Member elements  */
struct set_elem {
	struct rcu_head rcu;
	struct list_head list;
	struct ip_set *set;	/* Sigh, in order to cleanup reference */
	ip_set_id_t id;
} __aligned(__alignof__(u64));
```

Remember that this set pointer is a pointer to the fake object which we sprayed.
This means we can convert our first stage racy use-after-free into a (possibly)
more stable one.

Considering all of this, the most versatile payload to perform the stage 1 spray,
seems to be the well known `struct user_key_payload`:

```c
struct user_key_payload {
	struct rcu_head	rcu;		/* RCU destructor */
	unsigned short	datalen;	/* length of this data */
	char		data[] __aligned(__alignof__(u64)); /* actual data */
};
```

(It even has a proper RCU head at the correct offset)
To summarize, we spray a `struct user_key_payload` which "looks like" a set with
a comment extension. This extension points to the `*set` member of `struct set_elem`
which in turn points back to the sprayed payload.

Since the set is modified when the comment is actually deleted ([2.5]), we can
easily detect whether the race was successful by reading back the key.
When this is the case, we continue to stage 2, with a reasonably stable
use-after-free on our key payload.

## Stage 2: Use-After-Free on Key Payload

To leverage the use-after-free I chose to simply re-claim the freed key object
with another `struct ip_set` object.
Specifically we will choose a `bitmap:port` set for this.
There are many good reasons for this:
- An ip set has many pointers as members. Since we control a key object we can leak a lot of data.
	Specifically this allows us to bypass KASLR via the `type` member.
- It has (indirect) function pointer members, making it a prime candidate for RIP control
- *But most importantly*, by slightly corrupting the original set, we can construct a very simple arbitrary memory write primitive that is much more useful than any RIP control primitive in the first place.

To better understand the arbitrary write primitive let's have a closer look at
the bitmap ip set type:
```c
/* Type structure */
struct bitmap_port {
	unsigned long *members;	/* the set members */
	u16 first_port;		/* host byte order, included in range */
	u16 last_port;		/* host byte order, included in range */
	u32 elements;		/* number of max elements in the set */
	size_t memsize;		/* members size */
	struct timer_list gc;	/* garbage collection */
	struct ip_set *set;	/* attached to this ip_set */
	unsigned char extensions[]	/* data extensions */
		__aligned(__alignof__(u64));
};
```

The general setup for a set consists of the generic `struct ip_set` structure
that contains type specific function templates and a `data` member ([0.3]).
For the `bitmap:port` type, this data member points to a `struct bitmap_port`
structure.
The elements are, as the name suggests, a simple bitmap in the `members` member.
Since elements are merely bits (contrary to the `list:set`) extensions are
directly stored on the type structure (see `extensions` member).
When an element is added to the set, the corresponding bit is set and the
extensions are stored at the given index.
The index for the (port) bitmap is determined by `(port to insert) - first_port`.

Knowing this, we construct our primitive like so:
1) Create a `bitmap:port` with a 16 byte extension that we can fully control
2) Add a single element to the bitmap as the first member. This allows us to fake
	another `struct bitmap_port` header (specifically the `members`, `first_port`
	and `last_port` fields) at `offsetof(struct bitmap_port, extensions) == 72`
3) Using our UaF, read the original `struct ip_set` leaking the `data` member
4) Again using our UaF, write back the `struct ip_set`, modifying the `data` member
	by adding the offset (i.e. `72`)

Now we have an bit-level arbitrary read/write primitive through set element
add/remove operations.
(As a side note, an even better choice for this would be something like
`bitmap:ip` since it would allow a broader range compared to the limited `u16`
port type)

Additionally, step 3) contains an implicit oracle to whether we reclaimed the
key object successfully. The `set->name` member overlaps with the `key.len` member.
By making this "length" longer than the original key, we can observe failure
and deduce a successful spray.
Same thing applies to step 4). Since the set name is modified on success, we can
observe the set not being found when triggering any operations if the following
spray failed.

With the primitive in place we only need a target to overwrite.
We will use the `core_pattern`, setting it to `|/proc/%P/exe`.
A following segmentation fault in our exploit process will then invoke our exploit
again as the core dump handler which is a straight way out of the jail and to root.

## Reliability

The exploit is relatively stable. By default, there is no "comment extension"
(see stage 1), this means if our spray did not succeed we are unlikely to corrupt
anything through the RCU cleanup down the way.
Still, we are targeting a race condition which has its quirks. Specifically
success chances degrade over time as we are trashing the heap more and more.
In my local experiments the exploit was successful ~70-80% though this may vary
depending on the underlying CPU speed, noise, etc.
