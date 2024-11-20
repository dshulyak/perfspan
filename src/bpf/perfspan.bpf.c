#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "perfspan.h"

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
    __uint(max_entries, 8 << 20);
} events SEC(".maps");

const volatile struct
{
    u32 enabled_events;
    u32 filter_tgid;
} cfg = {
    .enabled_events = 0,
    .filter_tgid = 0,
};

SEC("perf_event")
int on_perf_event(struct bpf_perf_event_data *ctx)
{
    u32 cookie = bpf_get_attach_cookie(ctx);
    u64 sample_period = ctx->sample_period;
    u64 *val = bpf_map_lookup_elem(&perf_events, &cookie);
    if (val)
    {
        *val += sample_period;
    }
    else
    {
        bpf_map_update_elem(&perf_events, &cookie, &sample_period, BPF_ANY);
    }
    return 0;
}

__always_inline int try_submit_event(u8 event_type, u64 span_id, u64 name_size, char *name)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (cfg.filter_tgid != 0 && pid_tgid >> 32 != cfg.filter_tgid)
    {
        return 0;
    }

    __u8 span_name[MAX_NAME_SIZE] = {0};
    if (name_size > MAX_NAME_SIZE)
    {
        name_size = MAX_NAME_SIZE;
    }
    bpf_probe_read_user(&span_name, name_size, name);
    __u8 *name_id = bpf_map_lookup_elem(&filter_by_name, &span_name);
    if (!name_id)
    {
        return 0;
    }

    u64 timestamp = bpf_ktime_get_ns();

    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!ev)
    {
        bpf_printk("ringbuf_reserve failed\n");
        return 1;
    }
    ev->type = event_type;
    ev->cpu = bpf_get_smp_processor_id();
    ev->name_id = *name_id;
    ev->span_id = span_id;
    ev->pid_tgid = pid_tgid;
    ev->timestamp = timestamp;
    __u32 captured_i;
    for (u32 i = 0; i < cfg.enabled_events; i++)
    {
        captured_i = i;
        u64 *val = bpf_map_lookup_elem(&perf_events, &captured_i);
        if (val)
        {
            ev->counters[i] = *val;
        }
    }

    bpf_ringbuf_submit(ev, 0);
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