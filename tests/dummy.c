/*
 * Compiled with:
 * clang -O2 -emit-llvm -c dummy.c -o - | llc -march=bpf -filetype=obj -o dummy.o
 */

#define SEC(NAME) __attribute__((section(NAME), used))

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct pt_regs{};

struct bpf_map_def SEC("maps/dummy") dummy_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(unsigned int),
	.max_entries = 128,
};


SEC("kprobe/dummy")
int kprobe__dummy(struct pt_regs *ctx)
{
	return 0;
}

unsigned int _version SEC("version") = 0xFFFFFFFE;
