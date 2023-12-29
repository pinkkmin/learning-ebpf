// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Hengqi Chen */
#ifndef _GOTLS_DEMO_H_
#define _GOTLS_DEMO_H_

#define TASK_COMM_LEN	16
#define kInvalidFD  -1
#define MAX_DATA_SIZE 1024 * 8

enum event_type {
  kEventRead,
  kEventWrite
};

struct go_tls_event {
    uint64_t ts_ns;
    uint32_t pid;
    int32_t fd;
    enum event_type type;
    int32_t data_len;
    char data[MAX_DATA_SIZE];
    char comm[TASK_COMM_LEN];
};

struct active_args {
  int fd;
  char* buf;
};

struct go_interface {
  int64_t type;
  void* ptr;
};

struct go_common_symaddrs_t {
  // ---- itable symbols ----

  // net.Conn interface types.
  int64_t tls_Conn;     // go.itab.*crypto/tls.Conn,net.Conn
  int64_t net_TCPConn;  // go.itab.*net.TCPConn,net.Conn

  // ---- struct member offsets ----

  // Members of internal/poll.FD.
  int32_t FD_Sysfd_offset;  // 16

  // Members of crypto/tls.Conn.
  int32_t tlsConn_conn_offset;  // 0

  // Members of google.golang.org/grpc/credentials/internal.syscallConn
  int32_t syscallConn_conn_offset;  // 0

  // Member of runtime.g.
  int32_t g_goid_offset;  // 152

  // Offset of the ptr to struct g from the address in %fsbase.
  int32_t g_addr_offset;  // -8
};

#endif /* _GOTLS_DEMO_H_ */
