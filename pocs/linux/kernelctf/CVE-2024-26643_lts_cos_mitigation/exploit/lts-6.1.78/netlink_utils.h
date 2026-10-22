/*
 *	Utils used to communicate with the kernel via Netlink.
 *	Useful for static linking.
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/pkt_sched.h>

#define PAGE_SIZE 0x1000
#define NL_AUTO_SEQ	0
#define NL_AUTO_PID	0

void *nlmsg_tail(const struct nlmsghdr *msg)
{
	return (unsigned char *)msg + NLMSG_ALIGN(msg->nlmsg_len);
}

void *nlmsg_data(const struct nlmsghdr *msg)
{
	return NLMSG_DATA(msg);
}

int nlmsg_datalen(const struct nlmsghdr *msg)
{
	return msg->nlmsg_len - NLMSG_HDRLEN;
}

struct nlmsghdr *nlmsg_alloc(void)
{
	struct nlmsghdr *msg;

	msg = calloc(1, 0x1000);
	if (!msg)
		return NULL;

	msg->nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(0));
	return msg;
}

struct nlmsghdr *nlmsg_init(int type, int flags)
{
	struct nlmsghdr *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	msg->nlmsg_type  = type;
	msg->nlmsg_flags = flags;
	msg->nlmsg_seq   = NL_AUTO_SEQ;
	msg->nlmsg_pid   = NL_AUTO_PID;

	return msg;
}

void nlmsg_free(struct nlmsghdr *msg)
{
	free(msg);
}

int nl_init_request(int type, struct nlmsghdr **msg, int flags)
{
	int sk;
	struct nlmsghdr *n;

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0)
		return -1;

	n = nlmsg_init(type, flags);
	if (!n) {
		close(sk);
		return -1;
	}

	*msg = n;
	return sk;
}

void *nlmsg_reserve(struct nlmsghdr *msg, size_t len, int pad)
{
	char *data = (char *)msg;
	size_t tlen;

	tlen = NLMSG_ALIGN(len);
	data += msg->nlmsg_len;
	msg->nlmsg_len += tlen;

	if (tlen > len)
		memset(data + len, 0, tlen - len);

	return data;
}

int nlmsg_append(struct nlmsghdr *msg, void *data, size_t len, int pad)
{
	void *tmp;

	tmp = nlmsg_reserve(msg, len, pad);
	if (tmp == NULL)
		return -1;

	memcpy(tmp, data, len);
	return 0;
}

int nl_sendmsg(int sk, struct nlmsghdr *msg)
{
	struct iovec iov = {};
	struct msghdr hdr = {};

	if (sk < 0)
        	return -1;

	iov.iov_base = (void *)msg;
        /*
	 *	Here add NLMSG_GOODSIZE (0xec0) to the total message length
	 *	to be sure the msg in netlink_alloc_large_skb() is allocated using vmalloc():
         *      https://elixir.bootlin.com/linux/v6.1/source/net/netlink/af_netlink.c#L1190
	 *	Useful to reduce noise in kmalloc-512 slabs.
	 */
	iov.iov_len = msg->nlmsg_len + 0xec0;

	hdr.msg_name = NULL;
	hdr.msg_namelen = sizeof(struct sockaddr_nl);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	return sendmsg(sk, &hdr, 0);
}

int nl_complete_request(int sock, struct nlmsghdr *msg)
{
	int ret;

	ret = nl_sendmsg(sock, msg);
	nlmsg_free(msg);
	close(sock);

	return ret;
}

void *nla_data(const struct nlattr *nla)
{
	return (char *)nla + NLA_HDRLEN;
}

int nla_attr_size(int payload)
{
	return NLA_HDRLEN + payload;
}

int nla_total_size(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload));
}

int nla_padlen(int payload)
{
	return nla_total_size(payload) - nla_attr_size(payload);
}

struct nlattr *nla_reserve(struct nlmsghdr *msg, int attrtype, int attrlen)
{
	struct nlattr *nla;

	nla = (struct nlattr *)nlmsg_tail(msg);
	nla->nla_type = attrtype;
	nla->nla_len = nla_attr_size(attrlen);

	memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

	msg->nlmsg_len = NLMSG_ALIGN(msg->nlmsg_len) + nla_total_size(attrlen);
	return nla;
}

int nla_put(struct nlmsghdr *msg, int attrtype, int datalen, const void *data)
{
	struct nlattr *nla;

	nla = nla_reserve(msg, attrtype, datalen);
	if (!nla)
        	return -1;

	memcpy(nla_data(nla), data, datalen);
	return 0;
}

int nla_put_u32(struct nlmsghdr *msg, int attrtype, uint32_t value)
{
	return nla_put(msg, attrtype, sizeof(uint32_t), &value);
}

int nla_put_string(struct nlmsghdr *msg, int attrtype, const char *str)
{
	return nla_put(msg, attrtype, strlen(str) + 1, str);
}

int nla_put_nested(struct nlmsghdr *msg, int attrtype, const struct nlmsghdr *nested)
{
	return nla_put(msg, attrtype, nlmsg_datalen(nested), nlmsg_data(nested));
}

struct nlattr *nla_nest_start(struct nlmsghdr *msg, int attrtype)
{
	struct nlattr *start = (struct nlattr *)nlmsg_tail(msg);

	if (nla_put(msg, NLA_F_NESTED | attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

int nla_nest_end(struct nlmsghdr *msg, struct nlattr *start)
{
	size_t pad, len;

	len = (char *)nlmsg_tail(msg) - (char *)start;
	start->nla_len = len;

	pad = NLMSG_ALIGN(msg->nlmsg_len) - msg->nlmsg_len;
	if (pad > 0) {
		if (!nlmsg_reserve(msg, pad, 0))
            return -1;
	}
	return 0;
}
