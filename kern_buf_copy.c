#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"
#include "rlimit_header.h"

#define MAX_BUF_SZ 65536 //rlimit setting to 128M should be fine to allocate stack of 64k*8 etc.
#define MAX_THRS   2 //ping-pong so userspace can take some backpressure
/*
 *
 *        ,
 *    /\^/`\   TODO: check pollfd per queue if needed and also for socket
 *   | \/   |  implementation type 1: open socket per queue,
 *   | |    |  implementation type 2: alternate is to have read/write index based map index but that will be spinlock based implementation              jgs
 *   \ \    /                                                                                                                                         _ _
 *    '\\//'                                                                                                                                        _{ ' }_
 *      ||                                                                                                                                         { `.!.` }
 *      ||                                                                                                                                         ',_/Y\_,'
 *      ||  ,                                                                                                                                        {_,_}
 *  |\  ||  |\                                                                                                                                         |
 *  | | ||  | |                                                                                                                                      (\|  /)
 *  | | || / /                                                                                                                                        \| //
 *   \ \||/ /                                                                                                                                          |//
 *    `\\//`   \   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \\   \./    \ \\ |/ /
 *   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 *
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */
struct packet_buffer {
#ifdef _USE_SPINLOCK
  struct bpf_spin_lock slock;//spinlock
#endif
  char buffer[MAX_BUF_SZ];
  bool in_use; //in_use by kernel
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key,  __be16);
  __type(value, struct packet_buffer);
  __uint(max_entries, MAX_THR);
}pbuffer  SEC(".maps");


