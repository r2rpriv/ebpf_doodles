1) This exercise is to try "evesdrop" socket connection, that could be [ip:port] l4 can be any either tcp/udp
-  approach 1) i tried is, to have BPF_ATTACH via setsockopt to fetch packet data either via recv or recvfrom. File socket_basics.c addresses this approach, but for some reason DATA is not copied
  BPF instructions are generated with "tcpdump -dd dst port 8080"
-  approach 2) i tried is, to have same as approach 1 but with eBPF. However, issue i found is sk_buff hooks available as of this writing uses __sk_buff instead of _sk_buff i.e. there is no data buffer access availble.
-  approach 3) hence, best way i thought is to try with XDP, as XDP does have access to data from NIC in "xdp_md" _context, i have some structure for it but due to NIC on mydevel environment doesn't support native mode, and in skb mode endpoint will loss an access.

BPF_MAP _implemented for this exercise is packet buffer array->array of bpf_map(packet buffer)_ both will have port as key, each packet buffer will have spinlock so if it's taken by kernel, userspace can't take it.


so call stack for user-space->check spinlock->ready_to_use->take spinlock->give-to-print->reset_ready_to_use_->release-spinlock
current plan is to have 256 packet queue and map of ports supporting upto max 8 ports monitoring
