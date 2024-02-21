#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// func foo(a1, a2, a3 int64, bbbb []byte) (int64, []byte)
SEC("uprobe/foo")
int probe_entry_foo(struct pt_regs *ctx) {
	uint64_t a1 = (uint64_t)(ctx->ax);
	uint64_t a2 = (uint64_t)(ctx->bx);
	uint64_t a3 = (uint64_t)(ctx->cx);
	uint64_t b_data = (char*)(ctx->di);

	bpf_printk("foo entry, a1:%ld, a2:%ld, a3:%ld, b:%s",
		a1, a2, a3, b_data);
}

SEC("uretprobe/foo")
int probe_exit_foo(struct pt_regs *ctx) {
	uint64_t ret0 = (uint64_t)(ctx->ax);
	uint64_t ret1 = (uint64_t)(ctx->bx);

	bpf_printk("foo eixt, ~r0:%ld, ~r1:%s", ret0, ret1);	
}