// SPDX-License-Identifier: GPL-2.0
// A narrow ingress redirect for Nyxr's raw IPv4 SYN scanner. All unrelated
// traffic stays on the ordinary kernel networking path.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define bswap16(x) __builtin_bswap16(x)

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 128);
	__type(key, __u32);
	__type(value, __u32);
} xsks SEC(".maps");

struct scan_filter {
	__u32 source_ip;
	__u16 source_port;
	__u16 enabled;
};

struct nyxr_vlan_hdr {
	__u16 tci;
	__u16 encapsulated_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scan_filter);
} filter SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_redirect_map)(void *, __u32, __u64) = (void *)BPF_FUNC_redirect_map;

SEC("xdp")
int nyxr_redirect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	struct scan_filter *scan = bpf_map_lookup_elem(&filter, &zero);
	if (!scan || !scan->enabled)
		return XDP_PASS;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;
	__u16 proto = eth->h_proto;
	void *cursor = eth + 1;
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bswap16(ETH_P_8021Q) && proto != bswap16(ETH_P_8021AD))
			break;
		struct nyxr_vlan_hdr *vlan = cursor;
		if ((void *)(vlan + 1) > end)
			return XDP_PASS;
		proto = vlan->encapsulated_proto;
		cursor = vlan + 1;
	}
	if (proto != bswap16(ETH_P_IP))
		return XDP_PASS;
	struct iphdr *ip = cursor;
	if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5 || ip->daddr != scan->source_ip)
		return XDP_PASS;
	if (bswap16(ip->frag_off) & 0x3fff)
		return XDP_PASS;
	cursor = (void *)ip + ip->ihl * 4;
	if (cursor > end)
		return XDP_PASS;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = cursor;
		if ((void *)(tcp + 1) > end || tcp->dest != scan->source_port)
			return XDP_PASS;
		if (!tcp->ack || !(tcp->rst || tcp->syn))
			return XDP_PASS;
	} else if (ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = cursor;
		if ((void *)(icmp + 1) > end || icmp->type != ICMP_DEST_UNREACH)
			return XDP_PASS;
		struct iphdr *quoted = (void *)(icmp + 1);
		if ((void *)(quoted + 1) > end || quoted->version != 4 || quoted->ihl < 5 ||
		    quoted->saddr != scan->source_ip || quoted->protocol != IPPROTO_TCP)
			return XDP_PASS;
		void *quoted_tcp = (void *)quoted + quoted->ihl * 4;
		if ((__u8 *)quoted_tcp + 4 > (__u8 *)end)
			return XDP_PASS;
		if (*(__u16 *)quoted_tcp != scan->source_port)
			return XDP_PASS;
	} else {
		return XDP_PASS;
	}
	return bpf_redirect_map(&xsks, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
