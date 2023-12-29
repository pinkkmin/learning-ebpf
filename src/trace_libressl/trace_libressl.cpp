#include <unistd.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <regex>

#include <gflags/gflags.h>

#include "type.h"
#include "trace_libressl.skel.h"

#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100

struct uprobe_t {
    bool ret;
    uint64_t offset;
    int trace_pid;
    std::string binary;
    std::string symbol;
    std::string probe_fn;
};

/***********************************************************
 * Hande callback functions
 ***********************************************************/
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG)
    return 0;
                                                
    return vfprintf(stderr, format, args);
}

static void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    struct ssl_data_event_t* e = static_cast<struct ssl_data_event_t*>(data);
    
    if(e->type == kSSL_Read) {
        printf("Read@ task:[%s], length:[%d], msg:[\n%s]\n", 
            e->common, e->data_len, e->data);
    }
    else {
        printf("Write@ task:[%s], length:[%d], msg:[\n%s]\n",
            e->common, e->data_len, e->data);
    }
}

/***********************************************************
 * Skeleton helper functions
 ***********************************************************/
struct bpf_prog_skeleton* get_bpf_program_by_probename(const struct trace_libressl_bpf * obj, 
    const std::string &name) {
    if(!obj || !obj->skeleton) return NULL;
    struct bpf_object_skeleton *skeleton = obj->skeleton;

    int prog_cnt = skeleton->prog_cnt;
    for(int i = 0; i < prog_cnt; i++) {
        if(0 == strcmp(name.c_str(), skeleton->progs[i].name)) 
            return skeleton->progs + i;
    }

    return NULL;
}

bool attach_uprobe(const struct trace_libressl_bpf * obj, const struct uprobe_t &uprobe) {
    struct bpf_prog_skeleton* prog_skeleton = get_bpf_program_by_probename(obj, uprobe.probe_fn);
    if(!prog_skeleton) return false;

    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts, 
            .retprobe=uprobe.ret,
            .func_name=uprobe.symbol.c_str());

    *(prog_skeleton->link) = bpf_program__attach_uprobe_opts(*(prog_skeleton->prog),
        uprobe.trace_pid, 
        uprobe.binary.c_str(), 
        uprobe.offset, 
        &opts);

    int err = libbpf_get_error(*(prog_skeleton->link));
    if(0!=err) {
        char errmsg[256]{};
        libbpf_strerror(err, errmsg, sizeof(errmsg));
        printf("[Error] %s\n", errmsg);
        return false;
    }

    return true;
}

const std::vector<uprobe_t> kLibreSSLProbes = {
    {
        .ret = false,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "SSL_read",
        .probe_fn = "probe_entry_ssl_read"
    },
    {
        .ret = true,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "SSL_read",
        .probe_fn = "probe_ret_ssl_read"
    },
    {
        .ret = false,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "SSL_write",
        .probe_fn = "probe_entry_ssl_write"
    },
    {
        .ret = true,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "SSL_write",
        .probe_fn = "probe_ret_ssl_write"
    }
};

const std::vector<uprobe_t> kLibreTLSProbes = {
    {
        .ret = false,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "tls_read",
        .probe_fn = "probe_entry_tls_read"
    },
    {
        .ret = true,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "tls_read",
        .probe_fn = "probe_ret_tls_read"
    },
    {
        .ret = false,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "tls_write",
        .probe_fn = "probe_entry_tls_write"
    },
    {
        .ret = true,
        .offset = 0,
        .trace_pid = -1,
        .binary = "",
        .symbol = "tls_write",
        .probe_fn = "probe_ret_tls_write"
    }
};

DEFINE_string(libretls, 
              "", 
              "libretls path, such as `/usr/local/lib/libtls.so.28`");

DEFINE_string(libressl, 
              "", 
              "libressl path, such as `/usr/local/lib/libssl.so.53`");

struct params_t {
    enum type_t {
        LibreSSL,
        LibreTLS
    };
    enum type_t type;
    std::string path;    
};

std::vector<struct params_t> check_params() {
    std::vector<struct params_t> params;

    if(access(FLAGS_libressl.c_str(), F_OK) == 0) {
       struct params_t prm;
       prm.type = params_t::LibreSSL;
       prm.path = FLAGS_libressl;
       params.push_back(prm);
    }

    if(access(FLAGS_libretls.c_str(), F_OK) == 0) {
       struct params_t prm;
       prm.type = params_t::LibreTLS;
       prm.path = FLAGS_libretls;
       params.push_back(prm);
    }

    return params;
}

int main(int argc, char** argv) {
    ::gflags::ParseCommandLineFlags(&argc, &argv, true);
    std::vector<struct params_t> params = check_params();
    if(params.size() == 0) {
        printf("[trace-libretls] usage: \n");
        printf("--libretls /usr/local/lib/libtls.so.28 \n");
        printf("--libressl /usr/local/lib/libssl.so.53 \n");
        return -1;
    }

    // BPF object and perf buffer
    struct trace_libressl_bpf * obj;
    struct perf_buffer* pb = NULL;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Open
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    obj = trace_libressl_bpf__open_opts(&open_opts);
    if (!obj) {
        printf("[trace-libretls] Fail to open BPF object \n");
        return 1;
    }

    // Load
    int err = trace_libressl_bpf__load(obj);
    if (err) {
        printf("[trace-libretls] Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // Open perf event buffer
    pb = perf_buffer__new(bpf_map__fd(obj->maps.ssl_events), 
        PERF_BUFFER_PAGES,
        handle_event, 
        NULL, NULL, NULL);

    if (!pb) {
        int err = -errno;
        printf("failed to open perf buffer: %d\n", err);
        goto cleanup;
    }

    // Attach LibreSSL and LIbreTLS
    for(const auto &param: params) {
        const std::vector<uprobe_t> *probes = nullptr;
        if(param.type == params_t::LibreSSL) {
            probes = &kLibreSSLProbes; 
        }
        else {
            probes = &kLibreTLSProbes; 
        }

        for(const auto &u: *probes) {
            struct uprobe_t uprobe = u;
            uprobe.binary = param.path;
            attach_uprobe(obj, uprobe);
        }
    }

     // Poll data
    while (true) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            printf("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }

cleanup:
    if(obj) {
        if(pb) perf_buffer__free(pb);
        trace_libressl_bpf__destroy(obj);
    }
    return err != 0;
}

// run with root privilege.
// ./trace_libressl /usr/local/lib/libssl.so.53