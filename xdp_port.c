#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#include "rlimit_header.h"
#include "common.h"

SEC("xdp_port")
int xdp_ip_filter(struct xdp_md *ctx) {
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    u32 ip_src;
    u64 offset;
    u16 eth_type;

    struct ethhdr *eth = data;
    offset = sizeof(*eth);

    if (data + offset > end) {
      return XDP_ABORTED;
    }
     /* handle VLAN tagged packet */
    if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
             struct vlan_hdr *vlan_hdr;

          vlan_hdr = (void *)eth + offset;
          offset += sizeof(*vlan_hdr);
          if ((void *)eth + offset > end)
               return false;
          eth_type = vlan_hdr->h_vlan_encapsulated_proto;
    }

    /* let's only handle IPv4 addresses */
    if (eth_type == ntohs(ETH_P_IPV6)) {
        return XDP_PASS;
    }
    struct iphdr *iph = data + offset;
    offset += sizeof(struct iphdr);
    /* make sure the bytes you want to read are within the packet's range before reading them */
    if (iph + offset > end) {
        return XDP_ABORTED;
    }
    ipproto = iph->protocol;
    if(ipproto == IPPROTO_TCP){
      struct tcphdr *tcph = data+offset;
      offset += sizeof(struct tcphdr);
      if (tcph + offset > end) {
          return XDP_ABORTED;
      }
      srcport = tcphdr->source;
      dstport = tcphdr->dest;
    }
    /*
     *  else if(ipproto == IPPROTO_UDP){
     *    struct udphdr *udph = l4start;
     *    offset += sizeof(struct udphdr);
     *    if (udph + offset > end) {
     *        return XDP_ABORTED;
     *    }
     *    srcport = udphdr->src;
     *    dstport = udphdr->dest;
     *  }
     *
    * * * * * * * * * * * * * * * * * * * *
     */
    //now copy buffer

}
