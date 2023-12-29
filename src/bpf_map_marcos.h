#ifndef __BPF_MAPS_H__
#define __BPF_MAPS_H__

// copy from tracee-main/pkg/ebpf/c/maps.h

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                \
    struct {                                                                                       \
        __uint(type, _type);                                                                       \
        __uint(max_entries, _max_entries);                                                         \
        __type(key, _key_type);                                                                    \
        __type(value, _value_type);                                                                \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                                      \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries)

#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries)                                  \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, _max_entries)

#define BPF_ARRAY(_name, _value_type, _max_entries)                                                \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries)                                         \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_PROG_ARRAY(_name, _max_entries)                                                        \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define BPF_PERF_OUTPUT(_name, _max_entries)                                                       \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, _max_entries)

#endif // __MAPS_H__