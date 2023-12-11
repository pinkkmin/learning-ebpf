// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "gotls.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, uint32_t);
  __type(value, struct go_tls_event);
  __uint(max_entries, 1);
} gotls_data_event_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, struct active_args);
    __uint(max_entries, 1024);
} active_read_args_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, struct active_args);
    __uint(max_entries, 1024);
} active_write_args_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, struct go_common_symaddrs_t);
    __uint(max_entries, 1);
} go_common_symaddrs_map SEC(".maps");


#define REQUIRE_SYMADDR(symaddr, retval) \
  if (symaddr == -1) {                   \
    return retval;                       \
  }

static __inline void process_data(void* ctx, enum event_type type, struct active_args *data_args, int ret_val) {
  
  if(ret_val <= 0) return;
  int kZero = 0;
  struct go_tls_event *e = bpf_map_lookup_elem(&gotls_data_event_buffer_heap, &kZero);
  if(!e) return;

  e->fd = data_args->fd;
  e->type = type;
  e->data_len = ret_val;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  ret_val &= 0x1FFF;
  bpf_probe_read(&e->data, ret_val, data_args->buf);

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(struct go_tls_event));
}

static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf,
                                                   const struct go_common_symaddrs_t* symaddrs) {
  REQUIRE_SYMADDR(symaddrs->FD_Sysfd_offset, kInvalidFD);

  // if (conn_intf.type == symaddrs->tls_Conn) 
  {
    REQUIRE_SYMADDR(symaddrs->tlsConn_conn_offset, kInvalidFD);
    bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + symaddrs->tlsConn_conn_offset);
  }

  void* fd_ptr;
  bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

  int64_t sysfd;
  bpf_probe_read(&sysfd, sizeof(int64_t), fd_ptr + symaddrs->FD_Sysfd_offset);

  return sysfd;
}


// c     :8  ax
// b.data:16 bx
// b.len :24 cx
// b.cap :32 di
// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/gotls_read")
int probe_entry_gotls_read(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	
  // extract args
  char *buf = (char*)(ctx->bx);
  int fd = kInvalidFD;

  // args offset
  u32 zero = 0;
  struct go_common_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_common_symaddrs_map, &zero);
  if(symaddrs != NULL) {
    struct go_interface conn_intf;
    conn_intf.ptr = (void*)(ctx->ax);
    fd = get_fd_from_conn_intf_core(conn_intf, symaddrs);
  }

  if(fd == kInvalidFD) return 0;

  // update active read args.
  struct active_args read_args = {};
  read_args.fd = fd;
  read_args.buf = buf;
  bpf_map_update_elem(&active_read_args_heap, &id, &read_args, BPF_ANY);

	return 0;
}

// ~r0(int):   ax
// ~r1(error): bx+cx
SEC("uprobe/gotls_ret_read")
int probe_ret_gotls_read(struct pt_regs *ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
  
  int32_t ret_val0 = (int32_t)(ctx->ax);
  struct go_interface ret_err = {};
  ret_err.type = (int64_t)(ctx->bx);
  ret_err.ptr = (void*)(ctx->cx);
  
  struct active_args *read_args = bpf_map_lookup_elem(&active_read_args_heap, &id);
  if(read_args) {
    if(ret_err.ptr != 0) {
      bpf_printk("probe_ret_gotls_read ERROR, len:%d", ret_val0);
    }
    else {
      bpf_printk("probe_ret_gotls_read len: %d, msg:[%s]", ret_val0, read_args->buf);
      process_data(ctx, kEventRead, read_args, ret_val0);
    }
    bpf_map_delete_elem(&active_read_args_heap, &id);
  } 

	return 0;
}

// c     :8  ax
// b.data:16 bx
// b.len :24 cx
// b.cap :32 di
// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/gotls_write")
int probe_entry_gotls_write(struct pt_regs *ctx) {
  uint64_t id = bpf_get_current_pid_tgid();
	
  // extract args
  char *buf = (char*)(ctx->bx);
  int fd = kInvalidFD;

  // args offset
  u32 zero = 0;
  struct go_common_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_common_symaddrs_map, &zero);
  if(symaddrs != NULL) {
    struct go_interface conn_intf;
    conn_intf.ptr = (void*)(ctx->ax);
    fd = get_fd_from_conn_intf_core(conn_intf, symaddrs);
  }

  if(fd == kInvalidFD) return 0;

  // update active read args.
  struct active_args write_args = {};
  write_args.fd = fd;
  write_args.buf = buf;
  bpf_map_update_elem(&active_write_args_heap, &id, &write_args, BPF_ANY);

	return 0;
}

// ~r0(int):   ax
// ~r1(error): bx+cx
SEC("uprobe/gotls_ret_write")
int probe_ret_gotls_write(struct pt_regs *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
  
  int32_t ret_val0 = (int32_t)(ctx->ax);
  // bpf_probe_read(&ret_val0, sizeof(ret_val0), (void *)(PT_REGS_SP(ctx)+(0x30)));

  struct go_interface ret_err = {};
  ret_err.type = (int64_t)(ctx->bx);
  ret_err.ptr = (void*)(ctx->cx);

  struct active_args *write_args = bpf_map_lookup_elem(&active_write_args_heap, &id);
  if(write_args) {
    if(ret_err.ptr != 0) {
      bpf_printk("probe_ret_gotls_write ERROR!");
    }
    else {
      bpf_printk("probe_ret_gotls_write len:%d, msg:%s", ret_val0, write_args->buf);
      process_data(ctx, kEventWrite, write_args, ret_val0);
    }

    bpf_map_delete_elem(&active_write_args_heap, &id);
  }

	return 0;
}