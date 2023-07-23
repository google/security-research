---
title: 'Apple: Heap-based Buffer Overflow in libresolv'
severity: Critical
ghsa_id: GHSA-6cjw-q72j-mh57
cve_id: null
weaknesses:
- id: CWE-122
  name: Heap-based Buffer Overflow
products:
- ecosystem: n/a
  package_name: libresolv
  affected_versions: '68'
  patched_versions: ''
cvss: null
credits:
- github_user_id: Maximus-
  name: Max
  avatar: https://avatars.githubusercontent.com/u/628527?s=40&v=4
---

### Summary
There's a handful of vulnerabilities in libresolv's DNS packet handler. The bugs range from heap out-of-bounds write, to infinite-loop denial of service. We've indicated here the ones that I've encountered but there might be more. Everything documented here has associated repros and sample code.

#### Fuzzing Setup
The simplest setup is:
```c
#include <dns_util.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
 	if (size < 2) return 0;
 	dns_reply_t *reply = dns_parse_packet((const char *)data, size); 
 	free(reply);
 	return 0;
}
```

```bash
clang fuzzer.c -lresolv -fsanitize=address,fuzzer
```

libresolv was built from https://github.com/apple-oss-distributions/libresolv.git to make fuzzing a bit easier, and then the bugs were tested with libgmalloc to make sure the macOS version didn’t differ too much.

#### Vulnerabilities

##### Vulnerability 1 [Critical] Heap out-of-bounds write - remote code execution, denial of service

In <code>_dns_parse_domain_name @ [dns_util.c:265](https://github.com/apple-oss-distributions/libresolv/blob/main/dns_util.c#L265):</code>


```
if (dlen > 0) {
		len += dlen;
		name = realloc(name, len);
}
```


There's an integer overflow here with `len += dlen`, that can result in a smaller allocation happening. This will eventually lead to a heap overflow in the two uses of `name` below. 

On `realloc @ dns_util.c:297`, since `len` is only incremented by one, the overflow will make `len` zero, causing `realloc(..., 0)` to return `NULL`, leading `NULL` ptr deref later in the function.

Although this vulnerability is marked as Critical, it will be hard to get remote code execution, as the attacker would likely need an information disclosure to successfully pull off. Obtaining an information disclosure here would probably require another bug, as this is likely a one-shot thing (i.e. no back-and-forth comm.).


##### Vulnerability 2 [High] Heap out-of-bounds read - info disclosure, denial of service


`_dns_parse_domain_name` isn't reporting the proper remaining after parsing out a name, which leads to out of bounds reads. The function does however advance the buffer pointer, causing callers to expect that there's more buffer available. Possible impact could be remote heap info disclosure, or just a crash (denial of service). This issue manifests in the many places where _dns_parse_domain_name is called, like _dns_parse_resource_record_internal, which will often read out-of-bounds on dns_parse_uint* calls that follow. One of the most extreme cases is as a length-controlled out-of-bounds heap memmove @ `_dns_parse_resource_record_internal:723`


This severity here is High, as it’s relatively easy for an attacker to pull off as a denial of service. While the easiest scenario for this vulnerability is as a denial of service, there is some possibility of it being used as an information disclosure, since it’s copying large amounts of out-of-bounds heap data as DNS record info. 


##### Vulnerability 3 [Medium] Integer underflow - denial of service

In _dns_parse_resource_record_internal, `rdlen` is parsed out of the untrusted packet contents on `dns_util.c:346`. 


```
size = rdlen - 5;
	r->data.WKS->maplength = size * 8;
	r->data.WKS->map = NULL;
	if (size == 0) break;

  [1] r->data.WKS->map = (uint8_t *)calloc(1, r->data.WKS->maplength);
	mi = 0;
  [2] for (bx = 0; bx < size; bx++) {
		byte = _dns_parse_uint8(x);
		for (i = 128; i >= 1; i = i/2) {
			if (byte & i) r->data.WKS->map[mi] = 0xff;
			else r->data.WKS->map[mi] = 0;
			mi++;
		}
	}
	break;
```


In the case of `rdlen < 5`, size will underflow, causing `calloc` to make a massive allocation[1]. If the allocation fails, there’ll be a `NULL` pointer dereference in the next few lines. If the allocation succeeds, the following loop[2] will read out of bounds of the original buffer, and in the case of `rdlen = 4`, eventually also write out of bounds of `r->data.WKS->map`, if the read doesn’t cause a crash first.

The severity is Medium here as it’s possible to have an uncontrolled out-of-bounds heap write, although it’s more likely `calloc` will fail and just be a null pointer dereference. 


##### Vulnerability 4 [Low] Logic bug - denial of service

There's an infinite loop in `_dns_parse_domain_name` that's caused by the domain name compression support, which provides a “pointer” to another place in the same buffer. When handling this path in` _dns_parse_domain_name:232`, it’s possible to create a “compressed” name cycle where the compressed name offset points to another compressed name, causing a cycle. The check should probably be something like: 


```
if ((dlen & 0xc0) == 0xc0) && !compressed) …
```


The severity is Low here as it’s a non-crashing denial of service.

### Timeline
**Date reported**: March 1, 2022
**Date fixed**: May 16, 2022
**Date disclosed**: June 15, 2022