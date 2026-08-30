# The Netfilter packet flow (and where XDP sits in it)

The main [README](../README.md) says XDP runs "before routing decisions,
firewall rules, or connection tracking have touched the packet," without
showing what that pipeline actually looks like. This doc is that picture,
broken down section by section — not to make you a `netfilter` expert, just
enough to see the groups of steps, what each one is *for*, and the order
they run in, so "before all of that" in the main README means something
concrete.

![Packet flow through Netfilter, from XDP at the very left to either a local application at the top or another network interface at the right](images/netfilter-packet-flow.png)

*Diagram by Jan Engelhardt, [CC BY-SA 3.0](https://creativecommons.org/licenses/by-sa/3.0/deed.en),
via [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Netfilter-packet-flow.svg)
(XDP additions by Matteo Croce). Unmodified except resized.*

It looks overwhelming at first. It isn't, once you know what question each
part of it is answering — the diagram is organized two ways at once: left
to right by *which of three paths a packet is on* (section 1), and bottom
to top by *how specific the handling gets* (section 2). Sections 3 and 4
then zoom into one path in detail, and place XDP relative to all of it.

## 1. The three paths a packet can take

Read the diagram left to right. A packet always enters from the left (from
the network) or from the top (from a local process sending data out), and
the kernel has to decide, fairly early, which of three roads it's on:

- **INPUT** — the packet's destination is *this machine itself*. Example: someone
  runs `curl http://your-server/`, and the packet carrying that HTTP request
  needs to reach the web server process running locally.
- **FORWARD** — the packet is just passing through. This machine isn't the
  destination, it's acting as a router or gateway between two networks.
  Example: a home router forwarding your laptop's traffic out to the
  internet, or a Kubernetes node forwarding traffic between pods.
- **OUTPUT** — the packet was *created locally* and is heading out. Example:
  that same web server sending back its HTTP response, or you running
  `curl` yourself and generating the request in the first place.

The fork between INPUT and FORWARD happens at a single decision point
labeled **routing decision** in the diagram: the kernel looks at the
packet's destination address and asks "is that address one of mine?" — yes
sends it up the INPUT column toward a local process, no sends it sideways
into the FORWARD column and back out another interface. OUTPUT is separate
because it never arrives from the network at all — it starts from a local
process, at the top, and works its way down and out.

## 2. The layers (why the diagram has horizontal bands)

The diagram groups steps into horizontal bands, stacked bottom to top,
because a packet is handled at increasingly specific levels of detail as it
moves up through them:

- **Link layer** (bottom band) — Ethernet-level handling: is this machine
  acting as a network *bridge* (forwarding frames between two Ethernet
  segments, the way a virtual switch connecting containers on the same host
  does)? This layer doesn't know or care about IP addresses yet, only
  hardware-level addressing.
- **Network layer** (second band from the bottom) — this is the one most
  people mean when they say "iptables." Everything IP-address-related
  happens here: the actual firewall rules, address translation, and the
  INPUT/FORWARD routing decision from section 1.
- **Protocol layer** (third band) — above network filtering entirely: this
  is where TCP/UDP wrap or unwrap the actual data being sent, sitting
  between the Network layer below and the process using it above.
- **Application layer** (top band) — the actual process: where INPUT's
  packets finally arrive (`local process` in the diagram), and where
  OUTPUT's packets start their journey down and out.

## 3. The steps inside the network layer, in the order they run

Within the network layer, a packet on its way in passes through several
processing steps, always in this order. Most of them are *tables* — a named
place where you (or a tool like `iptables`/`nftables`) can insert your own
rules — but two of the seven, marked below, aren't rule tables at all, just
fixed steps the kernel always does:

1. **raw** — a way to mark specific packets as "don't bother tracking this
   one's connection state at all." Rarely used; the main real-world reason
   is performance, e.g. exempting a high-volume DNS server's traffic from
   connection tracking to save CPU on a busy box.
2. **conntrack** (connection tracking) — *not a rule table.* This is the
   fixed bookkeeping step right after: the kernel records which
   connection this packet belongs to and tags it (a brand new connection?
   part of one already in progress? related to one, like an FTP data
   connection spawned by an existing control connection?). Later tables and
   your own `iptables`/`nftables` rules can then match on that tag (e.g.
   "allow anything that's part of an already-established connection")
   instead of re-evaluating every rule for every single packet.
3. **mangle** — for altering a packet's header fields without changing
   whether it's allowed through. Example: marking packets for a specific
   priority queue — Quality of Service (QoS), scheduling that gives some
   traffic preferential bandwidth over other traffic — so video calls stay
   smooth even while something else on the network is doing a bulk
   download.
4. **nat (prerouting)** — *destination* NAT (DNAT): rewriting where a
   packet is headed before the routing decision sees it. Example: a router
   forwarding all traffic hitting its public IP on port 443 to a specific
   internal server's private IP — "port forwarding."
5. **routing decision** — *not a rule table either.* The fixed fork from
   section 1: is this packet's destination address one of mine (continue up
   to **filter**, below, then INPUT) or someone else's (branch sideways into
   FORWARD instead)?
6. **filter** — the actual allow/deny firewall logic most people picture
   when they hear "iptables rule": block this port, allow that source
   address. This is deliberately positioned *after* NAT, so your filter
   rules see the packet's real, already-rewritten destination.
7. **nat (postrouting)**, on the way back out (OUTPUT/FORWARD side) —
   *source* NAT (SNAT), rewriting where a packet claims to be *from*.
   Example: your home router rewriting every device's private address to
   its single public IP before sending traffic to the internet
   ("masquerading") — without this, replies would have nowhere valid to
   come back to.

Every one of these steps costs CPU time, per packet, every time — and for
the table steps specifically (raw, mangle, nat, filter), that cost is the
kernel walking through your rules one by one looking for a match. More
rules means more to walk through per packet, on every single packet, which
is exactly the scaling problem behind the eBPF-vs-iptables comparison in
the main README.

## 4. Where XDP actually sits

Follow the diagram all the way to the far left: `XDP eBPF` is the very
first thing that happens to an incoming packet — before `alloc_skb` (the
step where the kernel builds its own internal representation of the
packet), before the link layer, before **raw**, before conntrack, before
routing, before every table in section 3. Nothing above has run yet.

That's the entire reason XDP exists: not "eBPF, but for netfilter," but a
hook positioned *before* netfilter's pipeline even starts, for the cases
where paying the cost of that whole pipeline — for a packet you're about to
drop anyway, or one you just want to count — isn't worth it. XDP can
already decide to drop a packet (`XDP_DROP`), pass it on to this normal
pipeline unchanged (`XDP_PASS`, what this repo's demo does), or hand it
straight to a specific user-space program (`XDP_REDIRECT`) — all before
`alloc_skb`, before any of the steps in section 3 run at all.
