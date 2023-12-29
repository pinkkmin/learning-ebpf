//  some codes copy from pixie.

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#include "type.h"
#include "../bpf_map_marcos.h"

// output events to user space
BPF_PERF_OUTPUT(ssl_events, 1024)

// Key is thread ID (from bpf_get_current_pid_tgid) and fd (from ssl_ctx pointer)
// Value is a struct, include  a pointer to the data buffer argument to SSL_read/SSL_write.
BPF_HASH(active_read_args_maps, int32_t, struct data_args_t, 1024)
BPF_HASH(active_write_args_maps, int32_t, struct data_args_t, 1024)

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
BPF_PERCPU_ARRAY(data_buffer_heap, struct ssl_data_event_t, 1)

// LibreSSL offset info => {key:pid, value: symaddr}
// Key is the Tracee pid (from user space set.)
// Value is the symaddr(BIO, num offset with ssl_st) of the LibreSSL from process.
BPF_HASH(libressl_symaddr_maps, uint32_t, struct libressl_symaddr_t, 1024)

/***********************************************************
 * General helper functions
 ***********************************************************/

int32_t get_ssl_fd(void* ssl) {
	uint64_t id = bpf_get_current_pid_tgid();
	int32_t pid = id >> 32; 
	struct libressl_symaddr_t* symaddr = bpf_map_lookup_elem(&libressl_symaddr_maps, &pid);
	if(symaddr == NULL) {
		bpf_printk("get_ssl_fd can't find symaddr for pid:%d", pid);
		return kInvalidFd;
	}

	if(symaddr->SSL_rbio_offset == -1 || symaddr->RBIO_num_offset == -1) {
		return kInvalidFd; 
	}

	const void* rbio_ptr;
	bpf_probe_read_user(&rbio_ptr, sizeof(rbio_ptr), ssl + symaddr->SSL_rbio_offset);
	
	const int rbio_num;
	bpf_probe_read_user(&rbio_num, sizeof(rbio_num), rbio_ptr + symaddr->RBIO_num_offset);

	return rbio_num;
}

/***********************************************************
 * Processing functions
 ***********************************************************/
int process_ssl_data(struct pt_regs *ctx, 
					enum data_event_type type, 
					struct data_args_t* args) {
	if(!args->buf) return 0;

	int len = (int)PT_REGS_RC(ctx);
	if (len <= 0) return 0;

	int kZero = 0;
	struct ssl_data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);
	if(event) {
		bpf_get_current_comm(&event->common, sizeof(event->common));
		event->fd = args->fd;
		event->type = type;
		len &= MAX_DATA_SIZE-1;
		event->data_len = len;
		event->timestamp_ns = bpf_ktime_get_ns();
		uint64_t id = bpf_get_current_pid_tgid();
  		event->pid = id >> 32;

		bpf_probe_read(event->data, len, args->buf);
		bpf_perf_event_output(ctx, &ssl_events , BPF_F_CURRENT_CPU, event, sizeof(struct ssl_data_event_t));
	}
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

//  int SSL_read(SSL *ssl, void *buf, int num);
SEC("uprobe/SSL_read")
int probe_entry_ssl_read(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	void* ssl = (void*)PT_REGS_PARM1(ctx);
	const char* buf = (const char*)PT_REGS_PARM2(ctx);
	// int fd = get_ssl_fd(ssl);
	// if(fd == kInvalidFd) {
	// 	bpf_printk("probe_entry_ssl_read: get fd fail.");
	// 	return 0;
	// }

	struct data_args_t read_args = {};
	read_args.buf = buf;
	// read_args.fd = fd;
	bpf_map_update_elem(&active_read_args_maps, &id, &read_args, BPF_ANY);
	
	return 0;
}

SEC("uretprobe/SSL_read")
int probe_ret_ssl_read(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args_t* read_args = bpf_map_lookup_elem(&active_read_args_maps, &id);
	if(read_args != NULL) {
		process_ssl_data(ctx, kSSL_Read, read_args);
	}

	bpf_map_delete_elem(&active_read_args_maps, &id);
	return 0;
}


SEC("uprobe/SSL_write")
int probe_entry_ssl_write(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	void* ssl = (void*)PT_REGS_PARM1(ctx);
	const char* buf = (const char*)PT_REGS_PARM2(ctx);
	// int fd = get_ssl_fd(ssl);
	// if(fd == kInvalidFd) {
	// 	bpf_printk("probe_entry_ssl_write: get fd fail.");
	// 	return 0;
	// }

	struct data_args_t write_args = {};
	write_args.buf = buf;
	// write_args.fd = fd;
	bpf_map_update_elem(&active_write_args_maps, &id, &write_args, BPF_ANY);
	
	return 0;
}

SEC("uretprobe/SSL_write")
int probe_ret_ssl_write(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args_t* write_args = bpf_map_lookup_elem(&active_write_args_maps, &id);
	if(write_args != NULL) {
		process_ssl_data(ctx, kSSL_Write, write_args);
	}

	bpf_map_delete_elem(&active_write_args_maps, &id);
	return 0;
}

#include "trace_libretls.c"