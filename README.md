# ebpf-lab

A minimal, real, runnable eBPF program: an XDP hook that counts packets per
source IPv4 address in an in-kernel hash map, loaded and read from a small Go
program. Built to understand eBPF by shipping something, not by reading slides.

```
kernel                                   userspace
┌─────────────────────────────┐          ┌──────────────────────┐
│ NIC driver rx path           │          │ cmd/xdpcount/main.go │
│  └─ XDP hook (bpf/xdpcount.c)│◄── attach─┤  link.AttachXDP()    │
│      └─ pkt_count (BPF map) │◄── read ──┤  Map.Iterate()       │
└─────────────────────────────┘          └──────────────────────┘
```

## Quickstart

Requires Linux (obviously) and either the Nix flake devShell or a manual
toolchain (clang with BPF target, libbpf headers, kernel uapi headers).

```console
$ nix develop
$ go generate ./cmd/xdpcount   # recompiles bpf/xdpcount.c -> .o + Go bindings (only needed if you edit the .c)
$ go build ./...
$ sudo ./xdpcount -iface eth0  # needs CAP_BPF + CAP_NET_ADMIN, root is simplest
```

The generated `xdpcount_bpfel.go` / `xdpcount_bpfel.o` (and `_bpfeb` twins) are
committed to the repo. This is deliberate, not an oversight: it means anyone
cloning this repo can `go build` it with a stock Go toolchain and *no* BPF
compiler at all — you only need clang/libbpf/kernel-headers (i.e. `nix
develop`) when you're changing the eBPF C source itself. That split between
"build the userspace loader" and "recompile the kernel-side program" is the
same one every real eBPF-based Go project (Cilium, Tetragon, Hubble) makes.

## What eBPF actually is

eBPF lets you load small programs into the kernel that run at defined hook
points (a syscall entry, a tracepoint, a network device's rx path, a cgroup
boundary, ...) without writing a kernel module. Loading one still typically
needs `CAP_BPF`/`CAP_NET_ADMIN` (often root, in practice — Cilium's own
agent runs privileged) — the verifier doesn't remove that requirement, it
changes what a bug in the loaded code can do to the box. Three things make
that possible:

- **The verifier.** Before a program is attached, the kernel walks every
  possible execution path and rejects the load if it finds unbounded loops,
  out-of-bounds memory access, uninitialized reads, or a stack frame over
  512 bytes. Until Linux 5.2 this verification was also capped at 4096
  instructions total; 5.2 raised the *complexity* budget explored by the
  verifier to 1,000,000, but that 4096-instruction ceiling is still enforced
  for programs loaded by processes without `CAP_BPF`/`CAP_SYS_ADMIN` — i.e.
  the "unprivileged" path is deliberately kept far more restricted than what
  root can load. Bounded loops (a loop the verifier can prove terminates)
  have only been allowed since 5.3; before that, every loop had to be
  manually unrolled at compile time.
- **JIT compilation.** The verified bytecode is JITed to native machine code
  before it runs — this is not an interpreted VM in the hot path (an
  interpreter still exists as a fallback for when JIT is disabled or
  unavailable on the target architecture).
- **Maps**, not shared memory: the *only* way in or out of a running BPF
  program is through typed key/value stores (`BPF_MAP_TYPE_HASH`,
  `_ARRAY`, `_LRU_HASH`, `_PERF_EVENT_ARRAY`, `_RINGBUF`, ...) that both the
  kernel program and a userspace process can read/write concurrently. This
  demo's `pkt_count` map is exactly that: the kernel side writes counts, the
  Go side polls them with `Map.Iterate()`.

**CO-RE** (Compile Once – Run Everywhere) is the other piece that made eBPF
practical outside of "recompile against this exact kernel's headers." A
program compiled with BTF (BPF Type Format) debug info embedded — which is
what `-g` plus a BTF-enabled kernel (`CONFIG_DEBUG_INFO_BTF`) gives you —
carries enough type information that libbpf can patch struct-offset-dependent
instructions at *load* time against whatever kernel it's actually running on,
instead of at compile time. This demo doesn't use CO-RE (no `vmlinux.h`, no
`BPF_CORE_READ`) because it only touches stable UAPI structs
(`struct ethhdr`, `struct iphdr`) that don't need it — but it's the reason
tools like Falco or Cilium ship one binary that works across kernel versions
instead of a matrix of kernel-module builds.

## What this demo's code actually does

`bpf/xdpcount.c` is an XDP program: it runs on every incoming packet, as
early as the NIC driver's rx path. It parses just enough of the Ethernet + IP
headers to pull out `saddr`, bumps a counter in `pkt_count`, and returns
`XDP_PASS` to let the packet continue up the stack unmodified — this program
observes, it never drops or redirects.

XDP's pre-`sk_buff` performance pitch only holds in **native (driver) mode**,
where the NIC driver itself calls into the XDP hook before building an
`sk_buff`. Not every driver implements that; `link.AttachXDP` in this repo
doesn't force a mode, so on a driver without native XDP support the kernel
silently falls back to **generic/SKB mode**, running the same program *after*
`sk_buff` allocation — functionally correct, but with none of the performance
benefit being claimed. Check the mode you actually got with
`ip -d link show dev <iface>` (`xdp` vs `xdpgeneric` in the output) before
trusting a benchmark.

Two subtleties worth calling out because they're exactly the kind of thing
that's obvious once you've been bitten by it and invisible otherwise (both
are also flagged as comments in the code):

- `pkt_count` is a *LRU* hash map, not a plain hash map. A plain hash map
  with a fixed `max_entries` starts rejecting `bpf_map_update_elem` calls
  once full — silently dropping visibility into new source IPs — the moment
  someone port-scans the box or you're behind NAT with high source churn.
  LRU trades "always accept new keys" for "may silently evict a key you
  still cared about." Pick your poison at map-definition time, deliberately.
- The Go side reinterprets the raw 4 bytes of `ip->saddr` (already
  network-byte-order) as a `uint32` and writes it back out with
  `binary.LittleEndian`. That round-trip only reproduces the original bytes
  on a little-endian host (x86_64, aarch64 — i.e. every realistic target
  today). It is *not* portable to a big-endian host, and it's the kind of
  bug that won't show up until someone runs this on s390x.

## eBPF vs. the alternatives

| Approach | Runs where | Safety model | What it's actually good at | Where it loses |
|---|---|---|---|---|
| **eBPF (this repo)** | In-kernel, JITed | Static verification at load time, no kernel source/rebuild | Line-rate packet/syscall visibility & light mutation, one binary across kernel versions (CO-RE) | Verifier rejects genuinely complex control flow; no general-purpose heap (constrained allocators like `bpf_obj_new` exist since ~6.1 for opted-in program types); Linux-only |
| **iptables/nftables** | In-kernel (netfilter) | Kernel-maintained, well-audited, decades of hardening | L3/L4 filtering with a stable, scriptable CLI everyone already knows | Legacy iptables walks rules linearly (`O(n)`); kube-proxy's IPVS mode already fixes that with `O(1)` hash-based lookups without any eBPF. Cilium's real edge over IPVS isn't the lookup complexity — it's connect-time load balancing (skipping NAT/DNAT entirely via a cgroup hook) and programmable policy that a rule/rule-set model can't express |
| **Kernel module (LKM)** | In-kernel, native | None — a bug is a kernel panic or a rootkit-grade backdoor, at the module's discretion | Anything eBPF's verifier would reject: real data structures, full instruction set, arbitrary syscalls | Every kernel version/config combination is a new build target; a crash takes the whole box down; no built-in observability into what it's doing |
| **DTrace / SystemTap / ptrace** | In-kernel (compiled probe) or via syscall interception | SystemTap compiles to a kernel module (same panic risk); ptrace is userspace-safe but stops the tracee on every event | Ad hoc, exploratory tracing; ptrace-based tools (strace) need zero kernel-side setup | SystemTap: same fragility as any LKM. ptrace: `PTRACE_SYSCALL`'s stop-on-every-call model makes it too slow for always-on production tracing — this is precisely the gap Falco's eBPF probe fills |
| **DPDK (kernel bypass)** | Entirely in userspace, polling the NIC | No kernel involvement at all — you own the bugs | Higher raw throughput than XDP for a dedicated packet-processing box (no kernel handoff at all) | Takes exclusive ownership of the NIC — the machine can't also use that interface for ordinary networking; needs huge-page-backed poll-mode drivers; XDP gets you 80% of the win while the box still functions as a normal host |
| **Sidecar proxy (Envoy/service mesh)** | Userspace, one hop per pod | Regular process — normal crash/restart semantics, easy to reason about | L7-aware routing, retries, mTLS — protocol semantics eBPF's verifier has no business trying to parse | Extra hop = extra latency per request, an extra container per pod, and a second config plane; this is exactly why Cilium's own service mesh mode pushes L4 into eBPF and keeps a sidecar (or sidecar-less proxy) only for the L7 slice that actually needs it |

## Why it's eaten so much infrastructure since ~2018

- **Cilium** replaces kube-proxy's datapath with eBPF hash maps for
  Kubernetes Service resolution — O(1) lookup regardless of Service count,
  plus features a rule-based dataplane structurally cannot do, like
  intercepting a socket's `connect()` via the `BPF_CGROUP_INET4_CONNECT`
  cgroup sock-addr hook, so load-balancing happens *before* a packet is even
  built (no NAT hop at all for pod-to-Service traffic). Cilium separately
  uses `BPF_PROG_TYPE_SOCK_OPS` + sockmap for a local pod-to-pod fast path,
  and supports DSR (direct server return) so response traffic skips the
  load balancer on the way back.
- **Falco** moved from a custom kernel module to an eBPF probe for the same
  reason SystemTap never fit always-on production use: a `sinsp`-style
  syscall tracer needs to run permanently, on every node, and a verifier-
  checked probe that can't panic the box is the difference between "runtime
  security tool" and "the thing ops distrusts and disables."
- **Katran** (Meta) is a Layer 4 load balancer that runs entirely as an XDP
  program — packet-in to forwarding-decision without the kernel ever
  allocating an `sk_buff` or walking the normal netfilter/routing stack,
  which is why it handles millions of connections per box at a CPU cost
  regular kernel-stack forwarding can't match.
- **Continuous profilers** (Parca, and the profiling half of Grafana's
  stack) use `perf_event_open`-triggered eBPF programs to walk stacks and
  uprobes/USDT to hook language runtimes, giving fleet-wide always-on
  profiling without recompiling or restarting a single target process —
  the alternative (sampling profilers attached per-process, or
  instrumenting each service's code) doesn't scale past a handful of
  polyglot services. Pixie leans on the same eBPF/uprobe toolbox but its
  core value is protocol-level tracing (auto-capturing HTTP/gRPC/SQL
  traffic), with profiling as one feature alongside that, not the headline.

The pattern across all four: something used to require either a fragile
kernel module, a slow syscall-interception shim, or an extra network hop —
and eBPF collapsed it into a verifier-checked program that lives where the
work already happens.

## Where this is headed

- **`sched_ext`** (merged in Linux 6.12) lets you implement and hot-swap CPU
  schedulers as BPF programs — no kernel rebuild, no reboot to try a
  different scheduling policy. This is the same "verifier instead of trust"
  bet extended to a subsystem people used to consider untouchable outside
  kernel development.
- **eBPF for Windows** (Microsoft) is *not* a port of the Linux BPF
  subsystem into the NT kernel. It runs the IOVisor **uBPF** userspace VM
  plus the **PREVAIL** verifier inside a Windows driver, exposing
  Linux-compatible eBPF toolchains/APIs (including libbpf/cilium-ebpf-style
  loaders) on top of a completely different execution engine underneath.
  Worth knowing before assuming "eBPF" means the same guarantees on both
  platforms.
- The live debate worth tracking is eBPF vs. **WASM** as the general
  "safely run someone else's code inside my process/kernel/proxy" model —
  Envoy already supports WASM filters, and the pitch for WASM is a
  general-purpose language target and a mature toolchain ecosystem, against
  eBPF's kernel-level hook points and verifier maturity. Expect both to keep
  their niches (eBPF close to the kernel/network fast path, WASM in
  proxies/plugins/app-level sandboxes) rather than one replacing the other.

## When *not* to reach for eBPF

- **You need L7 protocol logic.** The verifier's whole design is "prove this
  terminates and touches only what it's allowed to" — that is fundamentally
  in tension with parsing HTTP/2 or gRPC framing. Even Cilium's L7-aware
  features lean on a userspace proxy for the actually-variable-length,
  stateful parsing; eBPF handles the L3/L4 fast path around it.
- **Your logic doesn't fit the verifier's shape.** No recursion, a 512-byte
  stack, only-recently-allowed bounded loops, and a hard 4096-instruction
  ceiling the moment you're not running as a privileged loader. If the
  logic needs real recursion or dynamic-sized data structures, you're
  fighting the tool.
- **You're targeting old kernels or non-Linux.** Practical CO-RE support
  wants a BTF-enabled kernel; distros vary on how far back they backported
  `CONFIG_DEBUG_INFO_BTF`, but treat "5.8+, ideally newer" as the realistic
  floor for a CO-RE-based tool that doesn't want a kernel-version matrix.
  There's no in-kernel eBPF on macOS/Windows-native (see above re: eBPF for
  Windows running a different engine entirely).
- **You're treating unprivileged eBPF as a hardened sandbox for untrusted
  code.** It was pitched that way for years; the track record disagrees.
  CVE-2021-3490 (ALU32 bounds-tracking bug in bitwise ops — any local,
  unprivileged user who could load a BPF program could turn it into
  out-of-bounds kernel reads/writes and escalate to arbitrary code
  execution) is one of
  several verifier-bypass CVEs that led Ubuntu, and eventually the upstream
  kernel itself (`CONFIG_BPF_UNPRIV_DEFAULT_OFF`), to disable unprivileged
  BPF loading by default. If your threat model includes "untrusted user on
  the box," don't rely on eBPF's verifier as the sandbox boundary — that's
  also why this demo's XDP program requires root/`CAP_BPF`+`CAP_NET_ADMIN`
  rather than pretending unprivileged loading is a safe default.

## Sources

- [BPF Design Q&A — kernel docs](https://docs.kernel.org/bpf/bpf_design_QA.html)
- [Complexity of the BPF Verifier — pchaigno](https://pchaigno.github.io/ebpf/2019/07/02/bpf-verifier-complexity.html)
- [Kubernetes Without kube-proxy — Cilium docs](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/)
- [Open-sourcing Katran — Meta Engineering](https://engineering.fb.com/2018/05/22/open-source/open-sourcing-katran-a-scalable-network-load-balancer/)
- [Tracing System Calls Using eBPF — Falco blog](https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/)
- [Falco kernel event sources docs](https://falco.org/docs/concepts/event-sources/kernel/)
- [Sched_ext Merged For Linux 6.12 — Phoronix](https://www.phoronix.com/news/Linux-6.12-Lands-sched-ext)
- [eBPF for Windows — Microsoft](https://microsoft.github.io/ebpf-for-windows/)
- [CVE-2021-3490 — GitHub Advisory Database](https://github.com/advisories/GHSA-9wfm-q59x-qc3x)
- [Unprivileged eBPF disabled by default — Ubuntu Discourse](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047)
