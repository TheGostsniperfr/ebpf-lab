# Exercises

Five small checks that you actually understood the mechanism explained in
the [README](../README.md) and [docs/netfilter-packet-flow.md](netfilter-packet-flow.md),
not just skimmed it. Each one: read it, try to answer/do it yourself
*before* opening the hint, and definitely before opening the solution.
There's no autograder here — the point is catching it yourself when your
answer doesn't match, not getting a green checkmark.

GitHub Flavored Markdown doesn't have a `:::` collapsible syntax; the
`<details>`/`<summary>` HTML tags below are the actual mechanism it
supports, and they render as click-to-expand on GitHub, same idea.

Exercises 2 and 3 modify `bpf/xdpcount.c` — do them on a throwaway copy or
just be ready to `git checkout -- bpf/xdpcount.c` afterward to get the
original back before continuing to use the repo.

---

## Exercise 1 — picking the right map type (no coding)

Say you're extending this demo to count packets by **destination port**
instead of source IP. You know there are at most a few dozen ports you
actually care about (this box only ever serves a handful of services), and
losing a counter silently would be a real problem for what you're building
— you'd rather the program refuse a genuinely new port than quietly forget
an old one.

Would you declare that map as `BPF_MAP_TYPE_HASH` or
`BPF_MAP_TYPE_LRU_HASH`? Why?

<details>
<summary>Hint</summary>

Re-read section 4.1 of the README — specifically the sentence describing
what a *plain* hash map does once it's full, versus what the LRU variant
does. Which of those two failure modes matches "I'd rather it refuse than
forget" in this scenario?

</details>

<details>
<summary>Solution</summary>

Plain [`BPF_MAP_TYPE_HASH`](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/),
sized comfortably above the "few dozen ports" you expect (e.g.
`max_entries = 256`). Since the key space is small and bounded, you'll
realistically never hit "full," so the plain hash map's downside
(silently rejecting new keys once full) never actually triggers — and you
get its upside instead: it never *evicts* a counter you already had,
which the scenario says matters more here than gracefully absorbing
unexpected new keys.
[`BPF_MAP_TYPE_LRU_HASH`](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LRU_HASH/)
is the right call in the *opposite* scenario (this repo's actual one): an
open-ended key space like arbitrary source IPs, where you can't bound how
many distinct keys you'll ever see.

</details>

---

## Exercise 2 — count by destination instead of source

Right now, `pkt_count` is keyed by `ip->saddr` — packets *coming from*
each address. Modify `bpf/xdpcount.c` so it counts packets *going to* each
address instead (keyed by destination), then rebuild
(`go generate ./cmd/xdpcount && go build ./...` inside `nix develop`) and
confirm it still builds.

<details>
<summary>Hint</summary>

Look at section 4.2/4.3 of the README. Exactly one line reads a field off
`ip` into `src_ip`. `struct iphdr` (from `<linux/ip.h>`) has both a
`saddr` and a `daddr` field — same type, same size, different meaning.

</details>

<details>
<summary>Solution</summary>

```c
__u32 dst_ip = ip->daddr;

__u64 *count = bpf_map_lookup_elem(&pkt_count, &dst_ip);
if (count) {
	__sync_fetch_and_add(count, 1);
} else {
	__u64 init = 1;
	bpf_map_update_elem(&pkt_count, &dst_ip, &init, BPF_ANY);
}
```

Only the field read changes (`saddr` → `daddr`); everything else — the
bounds checks, the map itself, the lookup/update logic — stays identical,
because the map was always just "counter, keyed by a 4-byte IPv4 address,"
with no assumption baked in about which address. Renaming `src_ip` to
`dst_ip` isn't required for it to work, only for the code to keep meaning
what it says.

Running this, `main.go`'s output now tells you which addresses are
*receiving* the most traffic through this interface, rather than which
addresses are *sending* it — useful, for example, to spot which of your
own local IPs is the busiest.

</details>

---

## Exercise 3 — predict a verifier rejection, then cause one

Section 4.2 claims the bounds check right before `struct iphdr *ip = (void
*)(eth + 1);` is used is *mandatory* — that removing it gets the program
rejected, not just made unsafe. Before touching anything: where exactly
does that rejection happen — when you compile the C file, or when you run
the program?

Then, if you have a Linux box with root and a spare network interface to
test on: delete the second bounds check —

```c
struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)   // delete this line and the one below it
	return XDP_PASS;
```

— rebuild, and try `sudo ./xdpcount -iface <your-iface>`.

<details>
<summary>Hint</summary>

`go generate` runs clang, which only checks that your C is syntactically
valid C — it has no idea what the BPF verifier's rules are, because the
verifier isn't a compiler pass, it's a kernel-side check. So: does
`go generate`/`go build` even have the information needed to catch this?

</details>

<details>
<summary>Solution</summary>

Compiling succeeds without complaint — clang is only checking C syntax and
producing BPF bytecode; it doesn't know or care about the verifier's
rules. The rejection happens later, at **load time**, which for this repo
means the moment `loadXdpcountObjects` runs inside `sudo ./xdpcount`. The
kernel refuses to attach the program at all, and you'd see an error
surfaced from that call along the lines of `invalid access to packet` or
`R#` (register number) `invalid mem access`, naming the exact instruction
where it lost track of whether the read was still inside bounds. Nothing
about `ip->saddr` runs even once — the whole program is rejected as a
unit, before a single packet reaches it. That's the concrete meaning of
"the verifier proves it before running it" from README section 2.

Put the deleted check back afterward — this repo's code should always
build *and* load cleanly.

</details>

---

## Exercise 4 — will the byte-order bug bite you on your own machine?

Without changing or running anything: based on the "byte order" paragraph
at the end of README section 4.4, would the address-printing bug it
describes actually show up if you ran this demo on the machine you're
reading this on right now?

Then check: run `uname -m` and see if your guess holds.

<details>
<summary>Hint</summary>

The bug only shows up on a **big-endian** machine. Which architectures
does the README name as the (rare) big-endian case, and which does it name
as what "essentially every modern CPU" actually is?

</details>

<details>
<summary>Solution</summary>

Almost certainly not — unless `uname -m` printed something unusual like
`s390x`, you're on `x86_64` or `aarch64`/`arm64`, both little-endian, which
is exactly the case the README says this code handles correctly. The bug
is real, but it's the kind of thing that survives in demo code for years
specifically because almost nobody's day-to-day hardware ever exercises
it.

</details>

---

## Exercise 5 — same mechanism, different point in the pipeline

The README (section 6, the Cilium bullet) mentions a *different* eBPF hook
than this demo uses: one attached to a socket's `connect()` call, letting
Cilium pick a Service's real backend before a packet is even built.

Using [docs/netfilter-packet-flow.md](netfilter-packet-flow.md): is that
`connect()` hook positioned *earlier* than this demo's XDP hook, *later*,
or is "earlier/later" not really the right question here? Explain why.

<details>
<summary>Hint</summary>

Re-read docs/netfilter-packet-flow.md section 1. XDP only ever sees
packets arriving from the network. What section of that pipeline does a
socket's `connect()` call belong to instead — and does a packet even exist
yet at that point?

</details>

<details>
<summary>Solution</summary>

"Earlier/later" isn't quite the right frame, because they're not on the
same path at all. This demo's XDP hook sits at the very start of the
**INPUT/FORWARD** side — packets arriving *from the network*. A
`connect()` hook fires when a *local process* starts a new outgoing
connection, which is the very beginning of the **OUTPUT** path — before a
packet has even been constructed, let alone left the machine. One handles
traffic coming in; the other intercepts traffic about to go out, before it
exists as a packet at all. Cilium uses both kinds of hooks, for different
jobs, not one after the other in a single pipeline.

</details>
