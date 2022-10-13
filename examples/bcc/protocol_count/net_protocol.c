#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

unsigned long long load_byte(void *skb,unsigned long long off) asm("llvm.bpf.load.byte");
BPF_HASH(countmap,u32,u32,32);
int protocol_count(struct __sk_buff *skb) {
    
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  int one = 1;
  
  int *el = countmap.lookup(&proto);
  
  if (el) {
    (*el)++;
  } else {
    el = &one;
  }
  countmap.update(&proto,el);
  
  return 0;
}
