#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

const MAX_EVENTS = 128;
const MAX_NAME_SIZE = 16;

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

enum
{
    ENTER = 0,
    EXIT = 1
};

__always_inline void write_header(u8 *cursor, u8 event_type, u64 thread_id, u64 span_id, u64 timestamp)
{
    *cursor = event_type;
    cursor += 1;
    *(u64 *)cursor = thread_id;
    cursor += 8;
    *(u64 *)cursor = span_id;
    cursor += 8;
    *(u64 *)cursor = timestamp;
    cursor += 8;
}

__always_inline void write_name(u8 *cursor, u64 name_size, void *name)
{   
    u64 limited = name_size > MAX_NAME_SIZE ? MAX_NAME_SIZE : name_size;
    bpf_probe_read_user(cursor, limited, name);
    cursor += MAX_NAME_SIZE;
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

SEC("usdt")
int BPF_USDT(perfspan_enter, u64 span_id, u64 name_size, void *name)
{
    // stream the following data using ring buffer
    // ENTER || thread_id || span_id || timestamp || name          || cfg.enable_events...
    // 1     || 8         || 8       || 8         || MAX_NAME_SIZE || 8 * cfg.enable_events
    u64 thread_id = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    u32 enabled_events = cfg.enabled_events;
    u64 to_reserve = 1 + 8 + 8 + 8 + MAX_NAME_SIZE + 8 * enabled_events;
    u8 *reserved = bpf_ringbuf_reserve(&events, to_reserve, 0);
    if (!reserved)
    {
        bpf_printk("ringbuf_reserve %d failed\n", to_reserve);
        return 1;
    }
    u8 *cursor = reserved;
    bpf_printk("cursor %p\n", cursor);
    write_header(cursor, ENTER, thread_id, span_id, timestamp);
    cursor += 25;
    write_name(cursor, name_size, name);
    // write_perf_counters(cursor);
    bpf_ringbuf_submit(reserved, 0);
    return 0;
}

SEC("usdt")
int BPF_USDT(perfspan_exit, u64 span_id)
{
    // stream the following data using ring buffer
    // EXIT || thread_id || span_id || timestamp || cfg.enable_events...
    // 1    || 8         || 8       || 8         || 8 * cfg.enable_events
    u64 thread_id = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    u32 enabled_events = cfg.enabled_events;
    u64 to_reserve = 1 + 8 + 8 + 8 + 8 * enabled_events;
    void *reserved = bpf_ringbuf_reserve(&events, to_reserve, 0);
    if (!reserved)
    {
        bpf_printk("ringbuf_reserve %d failed\n", to_reserve);
        return 1;
    }
    u8 *cursor = reserved;
    write_header(cursor, EXIT, thread_id, span_id, timestamp);
    cursor += 25;
    write_perf_counters(cursor);
    bpf_ringbuf_submit(reserved, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";