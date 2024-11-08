#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 128);
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
int on_perf_event(struct bpf_perf_event_data *ctx) {
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

#DEFINE ENTER = 0;
#DEFINE EXIT = 1;

__always_inline stream_header(u8 *cursor, u8 event_type, u64 thread_id, u64 span_id, u64 timestamp) {
    *cursor = event_type;
    cursor += 1;
    *(u64 *)cursor = thread_id;
    cursor += 8;
    *(u64 *)cursor = span_id;
    cursor += 8;
    *(u64 *)cursor = timestamp;
    cursor += 8;
}

__always_inline stream_name(u8 *cursor, u16 name_size, void *name) {
    *(u16 *)cursor = name_size;
    cursor += 2;
    bpf_probe_read_user(cursor, name_size, name);
    cursor += name_size;
}

__always_inline stream_perf_events(u8 *cursor) {
    // if this won't be allowed define constant for max number of events
    // and terminate early if i >= cfg.enabled_events
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
int BPF_USDT(perfspan_enter, u64 span_id, u16 name_size, void *name) {
    // stream the following data using ring buffer
    // ENTER || thread_id || span_id || timestamp || name_size || name || cfg.enable_events...
    // 1     || 8         || 8       || 8         || 2         || name || 8 * cfg.enable_events
    u64 thread_id = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    u64 to_reserve = 1 + 8 + 8 + 2 + name_size + 8 + 8 * cfg.enabled_events;
    u8 *cursor = bpf_ringbuf_reserve(&events, to_reserve, 0);
    if !cursor
    {
        bpf_printk("ringbuf_reserve %d failed\n", to_reserve);
        return 1;
    }
    stream_header(cursor, ENTER, thread_id, span_id, timestamp);
    stream_name(cursor, name_size, name);
    stream_perf_events(cursor);
    return 0;
}

SEC("usdt")
int BPF_USDT(perfspan_exit, u64 span_id) {
    // stream the following data using ring buffer
    // EXIT || thread_id || span_id || timestamp || cfg.enable_events...
    // 1    || 8         || 8       || 8         || 8 * cfg.enable_events
    u64 thread_id = bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();
    u64 to_reserve = 1 + 8 + 8 + 8 + 8 * cfg.enabled_events;
    u8 *cursor = bpf_ringbuf_reserve(&events, to_reserve, 0);
    if !cursor
    {
        bpf_printk("ringbuf_reserve %d failed\n", to_reserve);
        return 1;
    }
    stream_header(cursor, EXIT, thread_id, span_id, timestamp);
    stream_perf_events(cursor);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";