
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "type.h"
#include "../bpf_map_marcos.h"

// LibreSSL offset info => {key:pid, value: symaddr}
// Key is the Tracee pid (from user space set.)
// Value is the symaddr(BIO, num offset with ssl_st) of the LibreSSL from process.
BPF_HASH(libretls_symaddr_maps, uint32_t, struct libretls_symaddr_t, 1024)

/***********************************************************
 * General helper functions
 ***********************************************************/
int32_t get_tls_fd(void* tls) {
	uint64_t id = bpf_get_current_pid_tgid();
	int32_t pid = id >> 32; 
	struct libretls_symaddr_t* symaddr = bpf_map_lookup_elem(&libretls_symaddr_maps, &pid);
	if(symaddr == NULL) {
		bpf_printk("get_tls_fd can't find symaddr for pid:%d", pid);
		return kInvalidFd;
	}

	if(symaddr->TLS_socket == -1) {
		return kInvalidFd; 
	}
	
	const int socket;
	bpf_probe_read_user(&socket, sizeof(socket), tls + symaddr->TLS_socket);

	return socket;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen);
SEC("uprobe/tls_write")
int probe_entry_tls_write(struct pt_regs *ctx) {
	void* tls_ctx = (void*)PT_REGS_PARM1(ctx);
	const char* buf = (const char*)PT_REGS_PARM2(ctx);
	int fd = get_tls_fd(tls_ctx);
	if(fd == kInvalidFd) {
		bpf_printk("probe_entry_tls_write: get fd fail.");
		return 0;
	}

	struct data_args_t write_args = {};
	write_args.buf = buf;
	write_args.fd = fd;

	uint64_t id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&active_write_args_maps, &id, &write_args, BPF_ANY);
	
	return 0;
}

SEC("uretprobe/tls_write")
int probe_ret_tls_write(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_maps, &id);
	if(write_args != NULL) {
		process_ssl_data(ctx, kSSL_Write, write_args);
	}

	bpf_map_delete_elem(&active_write_args_maps, &id);
	return 0;
}

// ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen);
SEC("uprobe/tls_read")
int probe_entry_tls_read(struct pt_regs *ctx) {
	void* tls_ctx = (void*)PT_REGS_PARM1(ctx);
	const char* buf = (const char*)PT_REGS_PARM2(ctx);
	int fd = get_tls_fd(tls_ctx);
	if(fd == kInvalidFd) {
		bpf_printk("probe_entry_tls_write: get fd fail.");
		return 0;
	}

	struct data_args_t read_args = {};
	read_args.buf = buf;
	read_args.fd = fd;

	uint64_t id = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&active_read_args_maps, &id, &read_args, BPF_ANY);
	
	return 0;
}

SEC("uretprobe/tls_read")
int probe_ret_tls_read(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_maps, &id);
	if(read_args != NULL) {
		process_ssl_data(ctx, kSSL_Read, read_args);
	}

	bpf_map_delete_elem(&active_read_args_maps, &id);
	return 0;
}

// strings 命令查找字符串
// 如果依赖libtls.so 和 libcrypto.so libssl.so
// 说明是libtls.so是对libssl.so的调用
// 如果只有libtls.so 说明libssl.so和libcrypto.so以源码的方式集成
// 此时需要查看strings libtls.so|grep "LibreSSL" 即可确定ssl的offset