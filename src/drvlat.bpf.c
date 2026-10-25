// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * drvlat: driver-level latency histograms for embedded Linux.
 *
 * Uses only stable tracepoints (no kprobes), so it runs on kernels built
 * without CONFIG_KPROBES, which is common on production embedded images.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "drvlat.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* set by user space before load */
const volatile __u64 threshold_ns = 0;  /* 0 = no outlier events */

#define NR_SOFTIRQS_MAX 16

/* ------------------------------------------------------------------ */
/* Local CO-RE definitions for subsystems that may not be built into   */
/* the build host's kernel. The ___drvlat suffix is ignored by libbpf  */
/* when it matches these against the target kernel's BTF at load time. */

struct trace_event_raw_i2c_write___drvlat {
    int adapter_nr;
    __u16 msg_nr;
    __u16 addr;
} __attribute__((preserve_access_index));

struct trace_event_raw_i2c_read___drvlat {
    int adapter_nr;
    __u16 msg_nr;
    __u16 addr;
} __attribute__((preserve_access_index));

struct trace_event_raw_i2c_result___drvlat {
    int adapter_nr;
    __u16 nr_msgs;
    __s16 ret;
} __attribute__((preserve_access_index));

struct trace_event_raw_spi_message___drvlat {
    int bus_num;
    int chip_select;
    void *msg;
} __attribute__((preserve_access_index));

struct trace_event_raw_spi_message_done___drvlat {
    int bus_num;
    int chip_select;
    void *msg;
} __attribute__((preserve_access_index));

/* ------------------------------------------------------------------ */
/* Maps                                                                */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DRVLAT_MAX_KEYS);
    __type(key, struct drvlat_key);
    __type(value, struct drvlat_hist);
} hists SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* hard IRQ handlers run with interrupts off, so one slot per CPU is enough */
struct irq_start {
    __u64 ts;
    int irq;
    char name[DRVLAT_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct irq_start);
} irq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NR_SOFTIRQS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} softirq_start SEC(".maps");

/* threaded IRQ wake-ups, keyed by thread pid */
struct wake_start {
    __u64 ts;
    char comm[DRVLAT_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct wake_start);
} wake_start SEC(".maps");

/* I2C transfers are synchronous: key by thread id */
struct i2c_start {
    __u64 ts;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct i2c_start);
} i2c_start SEC(".maps");

/* SPI messages may complete asynchronously: key by message pointer */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} spi_start SEC(".maps");

static const struct drvlat_hist zero_hist;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
#pragma unroll
    for (int i = 5; i >= 0; i--) {
        __u32 shift = 1u << i;
        if (v >= (1ull << shift)) {
            v >>= shift;
            r += shift;
        }
    }
    return r;
}

static __always_inline void record(__u32 kind, __u32 id, __u64 dur_ns,
                                   const char *name)
{
    struct drvlat_key key = {.kind = kind, .id = id};
    struct drvlat_hist *h = bpf_map_lookup_elem(&hists, &key);
    if (!h) {
        bpf_map_update_elem(&hists, &key, &zero_hist, BPF_NOEXIST);
        h = bpf_map_lookup_elem(&hists, &key);
        if (!h)
            return;
        if (name)
            __builtin_memcpy(h->name, name, DRVLAT_NAME_LEN);
    }

    __u64 us = dur_ns / 1000;
    __u32 slot = us ? log2_u64(us) + 1 : 0;   /* slot 0 = [0, 1) us */
    if (slot >= DRVLAT_SLOTS)
        slot = DRVLAT_SLOTS - 1;

    __sync_fetch_and_add(&h->slots[slot], 1);
    __sync_fetch_and_add(&h->count, 1);
    __sync_fetch_and_add(&h->total_ns, dur_ns);
    if (dur_ns > h->max_ns)
        h->max_ns = dur_ns;   /* benign race: max is a diagnostic */

    if (threshold_ns && dur_ns >= threshold_ns) {
        struct drvlat_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->ts_ns = bpf_ktime_get_ns();
            e->dur_ns = dur_ns;
            e->kind = kind;
            e->id = id;
            e->cpu = bpf_get_smp_processor_id();
            if (name)
                __builtin_memcpy(e->name, name, DRVLAT_NAME_LEN);
            else
                e->name[0] = '\0';
            bpf_ringbuf_submit(e, 0);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Hard IRQ handler run time                                           */

SEC("tracepoint/irq/irq_handler_entry")
int handle_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
    __u32 zero = 0;
    struct irq_start *s = bpf_map_lookup_elem(&irq_start, &zero);
    if (!s)
        return 0;
    s->ts = bpf_ktime_get_ns();
    s->irq = ctx->irq;
    __u32 off = ctx->__data_loc_name & 0xFFFF;
    bpf_probe_read_kernel_str(s->name, sizeof(s->name), (void *)ctx + off);
    return 0;
}

SEC("tracepoint/irq/irq_handler_exit")
int handle_irq_exit(struct trace_event_raw_irq_handler_exit *ctx)
{
    __u32 zero = 0;
    struct irq_start *s = bpf_map_lookup_elem(&irq_start, &zero);
    if (!s || !s->ts || s->irq != ctx->irq)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - s->ts;
    s->ts = 0;
    record(DRVLAT_HARDIRQ, (__u32)ctx->irq, dur, s->name);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Softirq handler run time                                            */

SEC("tracepoint/irq/softirq_entry")
int handle_softirq_entry(struct trace_event_raw_softirq *ctx)
{
    __u32 vec = ctx->vec;
    if (vec >= NR_SOFTIRQS_MAX)
        return 0;
    __u64 *ts = bpf_map_lookup_elem(&softirq_start, &vec);
    if (ts)
        *ts = bpf_ktime_get_ns();
    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int handle_softirq_exit(struct trace_event_raw_softirq *ctx)
{
    __u32 vec = ctx->vec;
    if (vec >= NR_SOFTIRQS_MAX)
        return 0;
    __u64 *ts = bpf_map_lookup_elem(&softirq_start, &vec);
    if (!ts || !*ts)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - *ts;
    *ts = 0;
    record(DRVLAT_SOFTIRQ, vec, dur, NULL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Threaded IRQ scheduling latency (wake-up -> running)                */

static __always_inline int is_irq_thread(const char *comm)
{
    return comm[0] == 'i' && comm[1] == 'r' && comm[2] == 'q' && comm[3] == '/';
}

static __always_inline int on_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    struct wake_start w = {};
    bpf_probe_read_kernel(w.comm, sizeof(w.comm), ctx->comm);
    if (!is_irq_thread(w.comm))
        return 0;
    __u32 pid = ctx->pid;
    w.ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wake_start, &pid, &w, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    return on_wakeup(ctx);
}

SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    return on_wakeup(ctx);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 pid = ctx->next_pid;
    struct wake_start *w = bpf_map_lookup_elem(&wake_start, &pid);
    if (!w)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - w->ts;
    record(DRVLAT_IRQTHREAD, pid, dur, w->comm);
    bpf_map_delete_elem(&wake_start, &pid);
    return 0;
}

/* ------------------------------------------------------------------ */
/* I2C: first message of a transfer -> i2c_result                      */

static __always_inline int i2c_begin(__u16 msg_nr, __u16 addr)
{
    if (msg_nr != 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct i2c_start s = {.ts = bpf_ktime_get_ns(), .addr = addr};
    bpf_map_update_elem(&i2c_start, &tid, &s, BPF_ANY);
    return 0;
}

SEC("tracepoint/i2c/i2c_write")
int handle_i2c_write(void *ctx)
{
    struct trace_event_raw_i2c_write___drvlat *e = ctx;
    return i2c_begin(BPF_CORE_READ(e, msg_nr), BPF_CORE_READ(e, addr));
}

SEC("tracepoint/i2c/i2c_read")
int handle_i2c_read(void *ctx)
{
    struct trace_event_raw_i2c_read___drvlat *e = ctx;
    return i2c_begin(BPF_CORE_READ(e, msg_nr), BPF_CORE_READ(e, addr));
}

SEC("tracepoint/i2c/i2c_result")
int handle_i2c_result(void *ctx)
{
    struct trace_event_raw_i2c_result___drvlat *e = ctx;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct i2c_start *s = bpf_map_lookup_elem(&i2c_start, &tid);
    if (!s)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - s->ts;
    __u32 adapter = (__u32)BPF_CORE_READ(e, adapter_nr);
    __u32 id = (adapter << 16) | (s->addr & 0x3FF);
    bpf_map_delete_elem(&i2c_start, &tid);
    record(DRVLAT_I2C, id, dur, NULL);
    return 0;
}

/* ------------------------------------------------------------------ */
/* SPI: spi_message_start -> spi_message_done                          */

SEC("tracepoint/spi/spi_message_start")
int handle_spi_start(void *ctx)
{
    struct trace_event_raw_spi_message___drvlat *e = ctx;
    __u64 msg = (__u64)BPF_CORE_READ(e, msg);
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&spi_start, &msg, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/spi/spi_message_done")
int handle_spi_done(void *ctx)
{
    struct trace_event_raw_spi_message_done___drvlat *e = ctx;
    __u64 msg = (__u64)BPF_CORE_READ(e, msg);
    __u64 *ts = bpf_map_lookup_elem(&spi_start, &msg);
    if (!ts)
        return 0;
    __u64 dur = bpf_ktime_get_ns() - *ts;
    __u32 id = ((__u32)BPF_CORE_READ(e, bus_num) << 16) |
               ((__u32)BPF_CORE_READ(e, chip_select) & 0xFFFF);
    bpf_map_delete_elem(&spi_start, &msg);
    record(DRVLAT_SPI, id, dur, NULL);
    return 0;
}
