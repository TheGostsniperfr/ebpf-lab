// Command xdpcount attaches an XDP program to a network interface and
// periodically prints the number of packets seen per source IPv4 address.
//
// Requires CAP_BPF + CAP_NET_ADMIN (or root). See the repo README for setup.
package main

// This line runs on every `go generate ./...`: it compiles bpf/xdpcount.c
// to BPF bytecode via clang, then writes the xdpcount_bpfel.go/_bpfeb.go
// files that define xdpcountObjects, loadXdpcountObjects, and friends,
// used a few lines below. Those generated files aren't in this file — open
// xdpcount_bpfel.go after running `go generate` to see what got produced.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpcount ../../bpf/xdpcount.c

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "", "network interface to attach the XDP program to")
	interval := flag.Duration("interval", 2*time.Second, "how often to print counters")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("must specify -iface (see `ip link` for interface names)")
	}

	// XDP attaches to an interface *index* (an integer), not its name — this
	// lookup just translates the human-readable name you passed on the CLI.
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %v", *ifaceName, err)
	}

	// Kernels older than 5.11 enforce RLIMIT_MEMLOCK against BPF map memory;
	// without this, loading objs below fails with EPERM on those kernels.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	// loadXdpcountObjects (generated, see the go:generate line above) is
	// where the compiled BPF bytecode actually gets handed to the kernel
	// and run through the verifier. objs.XdpCountPkts and objs.PktCount
	// below are now live handles to the program and the map defined in
	// bpf/xdpcount.c.
	objs := xdpcountObjects{}
	if err := loadXdpcountObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	// This is the actual attach step: from here on, every packet arriving
	// on iface runs xdp_count_pkts() in the kernel before anything else
	// touches it.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCountPkts,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach XDP to %s: %v", *ifaceName, err)
	}
	defer l.Close() // detaches on exit — without this, the program stays attached

	log.Printf("counting packets on %s, ctrl-c to stop", *ifaceName)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			dumpStats(objs.PktCount)
		case <-stop:
			log.Println("detaching and exiting")
			return
		}
	}
}

// dumpStats reads every entry currently in the kernel-side map and prints
// it. This is the *only* way this program learns anything about traffic —
// it never sees a single packet itself, only these aggregated counts.
func dumpStats(m *ebpf.Map) {
	var (
		key   uint32
		count uint64
		addr  = make(net.IP, net.IPv4len)
	)

	it := m.Iterate()
	for it.Next(&key, &count) {
		// key holds the raw bytes of ip->saddr (network byte order) copied
		// verbatim into a Go uint32. On a little-endian host, writing it
		// back out with LittleEndian reproduces the original byte order —
		// this round-trip breaks on a big-endian host.
		binary.LittleEndian.PutUint32(addr, key)
		log.Printf("%-15s %d packets", addr.String(), count)
	}
	if err := it.Err(); err != nil {
		log.Printf("iterate pkt_count map: %v", err)
	}
}
