#ifndef _COMMON_H
#define _COMMON_H

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define SEC(NAME) __attribute__((section(NAME), used))•

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

static int (*bpf_map_update_elem)(struct bpf_map_def *map, void *key,
                                  void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static void *(*bpf_map_lookup_elem)(struct bpf_map_def *map, void *key) =
    (void *)BPF_FUNC_map_lookup_elem;

unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

#define MAX_BUF_SZ 8192//max MTU is 9000+(GRE/Vxlan offset), but we're keeping page/cache aligned access here
#define MAX_QUEUE  256// packet queue length
#define MAX_NR_PORTS 16//max different ports to monitor

struct packet_buffer {
  struct bpf_spin_lock slock;//spinlock
  char buffer[MAX_BUF_SZ];
  bool ready_to_use;
  uint16_t  packetlen;
};

struct bpf_map_def SEC("maps") packet_buf = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint16_t),
    .value_size = sizeof(struct packet_buffer)
    .max_entries = MAX_QUEUE,
};
struct bpf_map_def SEC("maps") port_buf = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAP,
    .key_size = sizeof(uint16_t),
    .value_size = sizeof(packet_buf)
    .max_entries = MAX_NR_PORTS,
};

#endif //_COMMON_H
