/* SPDX-License-Identifier: BSD-2-Clause */
/* Types shared between the BPF programs and the user-space loader. */
#ifndef DRVLAT_H
#define DRVLAT_H

#define DRVLAT_SLOTS     32   /* log2 histogram buckets, unit: microseconds */
#define DRVLAT_NAME_LEN  16
#define DRVLAT_MAX_KEYS  1024

enum drvlat_kind {
    DRVLAT_HARDIRQ = 0,   /* hard IRQ handler run time, per IRQ line */
    DRVLAT_SOFTIRQ,       /* softirq handler run time, per vector */
    DRVLAT_IRQTHREAD,     /* threaded IRQ: wake-up to on-CPU latency */
    DRVLAT_I2C,           /* I2C transfer time, per adapter + target address */
    DRVLAT_SPI,           /* SPI message time, per bus + chip select */
    DRVLAT_NR_KINDS,
};

struct drvlat_key {
    unsigned int kind;
    unsigned int id;
};

struct drvlat_hist {
    unsigned long long slots[DRVLAT_SLOTS];
    unsigned long long count;
    unsigned long long total_ns;
    unsigned long long max_ns;
    char name[DRVLAT_NAME_LEN];
};

/* Emitted through the ring buffer when a sample exceeds --threshold. */
struct drvlat_event {
    unsigned long long ts_ns;   /* CLOCK_MONOTONIC (bpf_ktime_get_ns) */
    unsigned long long dur_ns;
    unsigned int kind;
    unsigned int id;
    unsigned int cpu;
    char name[DRVLAT_NAME_LEN];
};

#endif /* DRVLAT_H */
