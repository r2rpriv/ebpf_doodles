#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include "common.h"

SEC("socket")
int socket_prog(struct __sk_buff *skb) {
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  int l3sz = ((load_byte(skb, ETH_HLEN)&0x0F)<<2);
  int totalsz = load_half(skb, ETH_HLEN + offsetof(struct iphdr, tot_len));
  int l4sz=0;
  uint16_t srcport,dstport,poffset; //src port, dstport and payload offset
  switch (proto){
    case IPPROTO_TCP:
        srcport = load_half(skb, ETH_HLEN + l3sz + offsetof(struct tcphdr, source));
        dstport = load_half(skb, ETH_HLEN + l3sz + offsetof(struct tcphdr, dest));
        l4sz = (((load_byte(skb, ETH_HLEN+l3sz+12)&0xF0)>>4)<<2);;
        break;
    case IPPROTO_UDP:
        srcport = load_half(skb, ETH_HLEN + l3sz + offsetof(struct udphdr, src));
        dstport = load_half(skb, ETH_HLEN + l3sz + offsetof(struct udphdr, dest));
        l4sz = 8;
        break;
  }
  if(l3sz && l4sz)
      poffset = ETH_HLEN + l3sz + l4sz;
  //OOPS: here we got __sk_buff what we needed sk_buff data
  /*
   *  Here, is the main logic
   *  We're copying sk_buff payload for the matching port in bpf_map, we expect to access it via user-space
   *
   * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
   */
  if ((proto == IPPROTO_TCP) && (srcport == port || dstport == port)){
    //take_spinlock
    //snaplen=totalsz-(l3sz+l4sz);
    memcpy(buffer,skb+poffset,totalsz-(l3sz+l4sz));
    //release spinlock
    //update inner and outermap
    //bpf_map_update_elem(&countmap, &proto, el, BPF_ANY);
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
