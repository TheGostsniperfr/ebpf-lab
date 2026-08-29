//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// LRU so a scan from an unrelated host can't grow this map without bound.
// Trade-off: once full, a new source IP evicts the least-recently-used
// entry, which can silently drop a counter you still cared about.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   // ip->saddr, raw network-byte-order bytes
	__type(value, __u64); // packet count
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_count_pkts(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	__u32 src_ip = ip->saddr;

	__u64 *count = bpf_map_lookup_elem(&pkt_count, &src_ip);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 init = 1;
		// Racy against a concurrent first packet from the same source on
		// another CPU (both take this branch, one update wins). Fine for a
		// demo; a production counter would retry the lookup after a failed
		// BPF_NOEXIST update.
		bpf_map_update_elem(&pkt_count, &src_ip, &init, BPF_ANY);
	}

	return XDP_PASS;
}
