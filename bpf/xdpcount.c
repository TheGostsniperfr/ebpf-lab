//go:build ignore
// The line above is for Go's own tooling (go build, go vet, gopls), not for
// clang: without cgo, Go refuses to even look at a .c file inside a package
// directory. This file is never compiled by `go build` — only by bpf2go
// (which shells out to clang, targeting BPF bytecode) via `go generate`.

#include <linux/bpf.h>      // kernel UAPI: XDP return codes, map type enum, ...
#include <linux/if_ether.h> // kernel UAPI: struct ethhdr (Ethernet header layout)
#include <linux/ip.h>       // kernel UAPI: struct iphdr (IPv4 header layout)
#include <bpf/bpf_helpers.h> // libbpf: the SEC() macro, bpf_map_*() helpers
#include <bpf/bpf_endian.h>  // libbpf: bpf_htons() and friends

// SEC("license") plus this exact variable is how the verifier learns this
// program's license at load time: some BPF helper functions are restricted
// to GPL-compatible programs, and this is the string the kernel checks.
char __license[] SEC("license") = "Dual MIT/GPL";

// LRU so a scan from an unrelated host can't grow this map without bound.
// Trade-off: once full, a new source IP evicts the least-recently-used
// entry, which can silently drop a counter you still cared about.
//
// This struct-of-__uint()/__type() shape (rather than a plain integer-keyed
// bpf_map_def) is libbpf's BTF-backed way to declare a map: the compiler
// embeds enough type information that the Go loader (bpf2go, via the
// generated xdpcountObjects/xdpcountMaps types) can read the key/value
// types back out on its own, instead of you hand-writing matching Go structs.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   // ip->saddr, raw network-byte-order bytes
	__type(value, __u64); // packet count
} pkt_count SEC(".maps");

// SEC("xdp") marks this function as an XDP program: attaching it with
// link.AttachXDP() on the Go side hooks it into a network interface's
// receive path. `ctx` hands you the raw packet as a [data, data_end) byte
// range — there's no parsed "packet" object here, you read the bytes
// yourself, which is exactly what the rest of this function does.
SEC("xdp")
int xdp_count_pkts(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Every raw-pointer read below is preceded by a check like this one.
	// That's not defensive-programming taste — the verifier statically
	// proves every memory access stays inside [data, data_end) before it
	// will load the program at all. Skip a check and the load is rejected
	// outright; the program never runs against a single real packet.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	// h_proto is stored in network byte order on the wire. bpf_htons()
	// converts our host-order constant (ETH_P_IP) to match it for the
	// comparison, rather than converting the packet's bytes — same result,
	// cheaper, and it's the packet's bytes we still need untouched below.
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	__u32 src_ip = ip->saddr;

	// The map lookup/update pair below is the only way this program talks
	// to the outside world: bump the existing counter for this source IP,
	// or create it at 1 if this is the first packet we've seen from it.
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

	// XDP_PASS: let the packet continue up the normal networking stack
	// unmodified. This program only observes — XDP_DROP/XDP_TX/XDP_REDIRECT
	// exist for programs that also want to act on the packet, not just
	// count it.
	return XDP_PASS;
}
