#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "goabi.skel.h"

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

struct goabi_bpf* obj = NULL;

//  3773: 00000000005ab020  1022 FUNC    GLOBAL DEFAULT    1 crypto/tls.(*Conn).Read
bool attach_go_tls_entry_read(const char* binary) {
    DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, goabi_opts, 
        .retprobe = false, 
        .func_name="main.foo");

    obj->links.probe_entry_foo =
        bpf_program__attach_uprobe_opts(obj->progs.probe_entry_foo, 
                                -1,
                                binary,
                                0,
                                &goabi_opts
        );

    int err = libbpf_get_error(obj->links.probe_entry_foo);
    if (0 != err) {
        printf("failed to attach probe_entry_foo: %d\n", err);
        return false;
    }    

    obj->links.probe_exit_foo =
        bpf_program__attach_uprobe_opts(obj->progs.probe_exit_foo, 
                                -1,
                                binary,
                                0xea,
                                &goabi_opts
        );

    obj->links.probe_exit_foo =
        bpf_program__attach_uprobe_opts(obj->progs.probe_exit_foo, 
                                -1,
                                binary,
                                0x22f,
                                &goabi_opts
        );

    err = libbpf_get_error(obj->links.probe_exit_foo);
    if (0 != err) {
        printf("failed to attach probe_exit_foo: %d\n", err);
        return false;
    }    

    return true;
}

int main(int argc, char** argv) {
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = goabi_bpf__open_and_load();
    if (!obj) {
        warn("failed to open BPF object \n");
        return -1;
    }

    // attach foo
    const char* binary_path = "/home/ohh/dev/learning-ebpf/src/go-abi/main";
    if(!attach_go_tls_entry_read(binary_path)) goto cleanup;

    sleep(10000);
cleanup:
    if(obj) {
        goabi_bpf__destroy(obj);
    }

    return err != 0;
}