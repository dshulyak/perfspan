#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "perfspan.h"

const MAX_EVENTS = 128;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[MAX_NAME_SIZE]);
    __type(value, __u8);
    __uint(max_entries, 32);
} filter_by_name SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, MAX_EVENTS);
} perf_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

const volatile struct
{
    u32 enabled_events;
} cfg = {
    .enabled_events = 0,
};

SEC("perf_event")
int on_perf_event(struct bpf_perf_event_data *ctx)
{
    u32 event_id = bpf_get_attach_cookie(ctx);
    u64 sample_period = ctx->sample_period;
    u64 *val = bpf_map_lookup_elem(&perf_events, &event_id);
    if (val)
    {
        *val += sample_period;
    }
    else
    {
        bpf_map_update_elem(&perf_events, &event_id, &sample_period, BPF_ANY);
    }
    return 0;
}

__always_inline void write_perf_counters(u8 *cursor)
{
    for (int i = 0; i < cfg.enabled_events; i++)
    {
        u64 *val = bpf_map_lookup_elem(&perf_events, &i);
        if (val)
        {
            *(u64 *)cursor = *val;
        }
        else
        {
            *(u64 *)cursor = 0;
        }
        cursor += 8;
    }
}

static __always_inline void print_byte_array(const char *arr, size_t size) {
    bpf_printk("[");
    for (size_t i = 0; i < size; i++) {
        if (i > 0) {
            bpf_printk(", ");
        }
        bpf_printk("%d", arr[i] & 0xff);
    }
    bpf_printk("]\n");
}

__always_inline int try_submit_event(u8 event_type, u64 span_id, u64 name_size, char *name) {
    __u8 span_name[MAX_NAME_SIZE] = {0};
    if (name_size > MAX_NAME_SIZE) {
        name_size = MAX_NAME_SIZE;
    }
    bpf_probe_read_user(&span_name, name_size, name);
    bpf_printk("span_name: %s size %d\n", span_name, name_size);
    __u8 *name_id = bpf_map_lookup_elem(&filter_by_name, &span_name);
    if (!name_id) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    
    u64 to_reserve = sizeof(struct event) + sizeof(__u64) * cfg.enabled_events;
    void *reserved = bpf_ringbuf_reserve(&events, to_reserve, 0);
    if (!reserved)
    {
        bpf_printk("ringbuf_reserve %d failed\n", to_reserve);
        return 1;
    }

    u8 *cursor = reserved;
    struct event *ev = cursor; 
    ev->type = event_type;
    ev->name_id = *name_id;
    ev->span_id = span_id;
    ev->pid_tgid = pid_tgid;
    ev->timestamp = timestamp;
    cursor += sizeof(struct event);
    
    write_perf_counters(cursor);

    bpf_ringbuf_submit(reserved, 0);
    return 0;
}

SEC("usdt")
int BPF_USDT(perfspan_enter, u64 span_id, u64 name_size, char *name)
{
    return try_submit_event(ENTER, span_id, name_size, name);
}

SEC("usdt")
int BPF_USDT(perfspan_exit, u64 span_id, u64 name_size, char *name)
{
    return try_submit_event(EXIT, span_id, name_size, name);
}

struct event _event = {};

char LICENSE[] SEC("license") = "GPL";