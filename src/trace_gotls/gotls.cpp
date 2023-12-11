// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "gotls.h"
#include "gotls.skel.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define warn(...) fprintf(stderr, __VA_ARGS__)
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
   struct go_tls_event* e = static_cast<struct go_tls_event*>(data);
   if(e->type == kEventRead) {
    printf("GoTLS Read@ task: [%s], length: %d, msg: [\n%s] \n", e->comm, e->data_len, e->data);
   }
   else {
    printf("GoTLS Write@ task: [%s], length: %d, msg: [\n%s] \n", e->comm, e->data_len, e->data);
   }
}

static void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

struct gotls_bpf* obj = NULL;
struct perf_buffer* pb = NULL;

//  3773: 00000000005ab020  1022 FUNC    GLOBAL DEFAULT    1 crypto/tls.(*Conn).Read
bool attach_go_tls_entry_read(const char* binary) {
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, read_opts, 
        .retprobe = false, 
        .func_name="crypto/tls.(*Conn).Read");

    obj->links.probe_entry_gotls_read =
        bpf_program__attach_uprobe_opts(obj->progs.probe_entry_gotls_read, 
                                -1,
                                binary,
                                0,
                                &read_opts
        );

    int err = libbpf_get_error(obj->links.probe_entry_gotls_read);
    if (0 != err) {
        printf("failed to attach attach_go_tls_entry_read: %d\n", err);
        return false;
    }    

    return true;
}

bool attach_go_tls_ret_read(const char* binary) {
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, read_ret_opts, 
        .retprobe = false, 
        .func_name="crypto/tls.(*Conn).Read");
    int offsets[7] = {0x104, 0x131, 0x1b2, 0x2fd, 0x330 ,0x3ad, 0x3cb};
    for(int i= 0;i<7;i++) {
        obj->links.probe_ret_gotls_read =
        bpf_program__attach_uprobe_opts(obj->progs.probe_ret_gotls_read, 
                                -1,
                                binary,
                                offsets[i],
                                &read_ret_opts
        );

        int err = libbpf_get_error(obj->links.probe_ret_gotls_read);
        if (0 != err) {
            printf("failed to attach attach_go_tls_ret_read:%d\n", err);
            return false;
        }
    }

    return true;
}

//  3765: 00000000005a9c20  1925 FUNC    GLOBAL DEFAULT    1 crypto/tls.(*Conn).Write
// crypto/tls.(*Conn).writeRecordLocked
bool attach_go_tls_entry_write(const char* binary) {
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, write_opts, 
        .retprobe = false, 
        .func_name="crypto/tls.(*Conn).Write");
    obj->links.probe_entry_gotls_write =
        bpf_program__attach_uprobe_opts(obj->progs.probe_entry_gotls_write, 
                                -1,
                                binary,
                                0,
                                &write_opts
    );

    int err = libbpf_get_error(obj->links.probe_entry_gotls_write);
    if (0 != err) {
        printf("failed to attach attach_go_tls_entry_write: %d\n", err);
        return false;
    }

    return true;
}

bool attach_go_tls_ret_write(const char* binary) {
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, read_ret_opts, 
        .retprobe = false, 
        .func_name="crypto/tls.(*Conn).Write");
    
    // "crypto/tls.(*Conn).Write" ret inst offsets.
    int offsets[8] = {0x3be,0x558,0x5c8,0x638,0x69a,0x6ea,0x726,0x750};

    for(int i= 0; i<5; i++) {
        obj->links.probe_ret_gotls_write =
        bpf_program__attach_uprobe_opts(obj->progs.probe_ret_gotls_write, 
                                -1,
                                binary,
                                offsets[i],
                                &read_ret_opts
        );

        int err = libbpf_get_error(obj->links.probe_ret_gotls_write);
        if (0 != err) {
            printf("failed to attach attach_go_tls_ret_read:%d\n", err);
            return false;
        }
    }

    return true;
}

bool open_perf_event_buffer() {
    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        int err = -errno;
        warn("failed to open perf buffer: %d\n", err);
        return false;
    }

    return true;
}

bool update_go_symbol_info() {
    const struct go_common_symaddrs_t symbol = {
        .FD_Sysfd_offset = 16,
        .tlsConn_conn_offset = 0,
        .syscallConn_conn_offset = 0,
        .g_goid_offset = 152,
        .g_addr_offset = -8
    }; 

    int fd = bpf_map__fd(obj->maps.go_common_symaddrs_map);
    if(fd < 0) {
        return false;
    }

    uint32_t kZero = 0;
    return 0 == bpf_map_update_elem(fd, &kZero, &symbol, BPF_ANY);
}

int main(int argc, char** argv) {
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = gotls_bpf__open_and_load();
    if (!obj) {
        warn("failed to open BPF object \n");
        return -1;
    }

    const char* binary_path = "../src/testdata/go1_18_1_https_server";

    // attach go_tls read
    if(!attach_go_tls_entry_read(binary_path)) goto cleanup;
    if(!attach_go_tls_ret_read(binary_path)) goto cleanup;

    // attach go_tls write
    if(!attach_go_tls_entry_write(binary_path)) goto cleanup;
    if(!attach_go_tls_ret_write(binary_path)) goto cleanup;

    // open perf buffer.
    if(!open_perf_event_buffer()) goto cleanup;

    // update go symbols 
    if(!update_go_symbol_info()) goto cleanup;

    // poll
    while (true) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }

cleanup:
    if(obj) {
        if(pb) perf_buffer__free(pb);
        gotls_bpf__destroy(obj);
    }

    return err != 0;
}


// TEST/DEBUG
// 
// 1. run go https web
// cd testdata/
// nohup ./go1_18_1_https_server --key=server.key --cert=server.crt &
// 2023/09/18 11:28:39 Starting HTTP service on Port 50100
// 2023/09/18 11:28:39 Starting HTTPS service on Port 50101
// 
// 2. build&run bpf probe
// mkdir build && cd build
// cmake ../src 
// make
// sudo ./gotls
//
// 3. watch bpf printf
// sudo cat /sys/kernel/debug/tracing/trace_pipe
// 
// 4. run curl
//  curl --http1.1 -k https://localhost:50101