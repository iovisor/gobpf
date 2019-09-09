#ifndef __NETLINK_H
#define __NETLINK_H

#include "bpf.h"

int libbpf_netlink_open(__u32 *nl_pid);
int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);

#endif
