// SPDX-License-Identifier: BSD-2-Clause
/*
 * drvlat - driver latency histograms for embedded Linux (user-space loader)
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "drvlat.h"
#include "drvlat.skel.h"

static const char *const kind_names[DRVLAT_NR_KINDS] = {
    [DRVLAT_HARDIRQ] = "hardirq",
    [DRVLAT_SOFTIRQ] = "softirq",
    [DRVLAT_IRQTHREAD] = "irqthread",
    [DRVLAT_I2C] = "i2c",
    [DRVLAT_SPI] = "spi",
};

static const char *const kind_titles[DRVLAT_NR_KINDS] = {
    [DRVLAT_HARDIRQ] = "hard IRQ handler run time",
    [DRVLAT_SOFTIRQ] = "softirq handler run time",
    [DRVLAT_IRQTHREAD] = "threaded IRQ wake-up -> on-CPU latency",
    [DRVLAT_I2C] = "I2C transfer time (first message -> result)",
    [DRVLAT_SPI] = "SPI message time (start -> done)",
};

/* tracepoint subsystem each kind needs */
static const char *const kind_tp_dir[DRVLAT_NR_KINDS] = {
    [DRVLAT_HARDIRQ] = "irq",
    [DRVLAT_SOFTIRQ] = "irq",
    [DRVLAT_IRQTHREAD] = "sched",
    [DRVLAT_I2C] = "i2c",
    [DRVLAT_SPI] = "spi",
};

static const char *const softirq_names[] = {
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK",
    "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU",
};

static struct env {
    unsigned int kinds;        /* bitmask of enum drvlat_kind */
    int interval;              /* seconds between reports, 0 = at exit */
    int duration;              /* seconds, 0 = until Ctrl-C */
    unsigned long threshold_us;
    const char *filter;        /* substring match on the row name */
    bool json;
    bool cumulative;
    bool verbose;
} env = {
    .kinds = (1u << DRVLAT_HARDIRQ) | (1u << DRVLAT_IRQTHREAD) |
             (1u << DRVLAT_I2C) | (1u << DRVLAT_SPI),
};

static volatile sig_atomic_t exiting;

const char *argp_program_version = "drvlat 0.1.0";
static const char doc[] =
    "drvlat: driver latency histograms for embedded Linux (eBPF, tracepoints only)\n"
    "\n"
    "Measures hard IRQ and softirq run time, threaded-IRQ scheduling latency,\n"
    "and I2C / SPI transfer time, as log2 histograms in microseconds.\n"
    "\n"
    "EXAMPLES:\n"
    "  drvlat                        # hardirq, irqthread, i2c, spi until Ctrl-C\n"
    "  drvlat -m hardirq,irqthread -n gpio   # GPIO interrupt latency only\n"
    "  drvlat -m i2c -i 5            # I2C histograms every 5 s\n"
    "  drvlat -t 500                 # also log every sample >= 500 us\n"
    "  drvlat -d 10 --json > out.json\n";

static const struct argp_option opts[] = {
    {"modes", 'm', "LIST", 0,
     "Comma list of: hardirq,softirq,irqthread,i2c,spi,all", 0},
    {"interval", 'i', "SEC", 0, "Print every SEC seconds (default: at exit)", 0},
    {"duration", 'd', "SEC", 0, "Stop after SEC seconds", 0},
    {"threshold", 't', "US", 0, "Log each sample at or above US microseconds", 0},
    {"name", 'n', "STR", 0, "Only rows whose name contains STR", 0},
    {"cumulative", 'c', NULL, 0, "Do not clear histograms between intervals", 0},
    {"json", 'j', NULL, 0, "JSON output", 0},
    {"verbose", 'v', NULL, 0, "libbpf debug output", 0},
    {},
};

static unsigned int parse_kinds(const char *arg)
{
    unsigned int mask = 0;
    char *dup = strdup(arg);
    for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
        if (!strcmp(tok, "all")) {
            mask |= (1u << DRVLAT_NR_KINDS) - 1;
            continue;
        }
        int found = 0;
        for (int k = 0; k < DRVLAT_NR_KINDS; k++) {
            if (!strcmp(tok, kind_names[k])) {
                mask |= 1u << k;
                found = 1;
            }
        }
        if (!found) {
            fprintf(stderr, "unknown mode '%s'\n", tok);
            free(dup);
            return 0;
        }
    }
    free(dup);
    return mask;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'm':
        env.kinds = parse_kinds(arg);
        if (!env.kinds)
            argp_usage(state);
        break;
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'd':
        env.duration = atoi(arg);
        break;
    case 't':
        env.threshold_us = strtoul(arg, NULL, 10);
        break;
    case 'n':
        env.filter = arg;
        break;
    case 'c':
        env.cumulative = true;
        break;
    case 'j':
        env.json = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

/* tracefs is not mounted on every minimal image; mount it if we can */
static void ensure_tracefs(void)
{
    if (access("/sys/kernel/tracing/events", F_OK) == 0 ||
        access("/sys/kernel/debug/tracing/events", F_OK) == 0)
        return;
    if (mount("nodev", "/sys/kernel/tracing", "tracefs", 0, NULL) != 0 &&
        env.verbose)
        fprintf(stderr, "note: could not mount tracefs: %s\n", strerror(errno));
}

static bool tracepoints_present(const char *subsys)
{
    static const char *const roots[] = {
        "/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events",
    };
    char path[256];
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", roots[i], subsys);
        if (access(path, F_OK) == 0)
            return true;
    }
    return false;
}

static void row_name(const struct drvlat_key *k, const struct drvlat_hist *h,
                     char *buf, size_t len)
{
    switch (k->kind) {
    case DRVLAT_HARDIRQ:
        snprintf(buf, len, "%u:%.*s", k->id, DRVLAT_NAME_LEN, h->name);
        break;
    case DRVLAT_SOFTIRQ:
        if (k->id < sizeof(softirq_names) / sizeof(softirq_names[0]))
            snprintf(buf, len, "%s", softirq_names[k->id]);
        else
            snprintf(buf, len, "vec%u", k->id);
        break;
    case DRVLAT_IRQTHREAD:
        snprintf(buf, len, "%.*s (pid %u)", DRVLAT_NAME_LEN, h->name, k->id);
        break;
    case DRVLAT_I2C:
        snprintf(buf, len, "i2c-%u @0x%02x", k->id >> 16, k->id & 0xFFFF);
        break;
    case DRVLAT_SPI:
        snprintf(buf, len, "spi%u.%u", k->id >> 16, k->id & 0xFFFF);
        break;
    default:
        snprintf(buf, len, "?");
    }
}

static void slot_range(int slot, unsigned long long *lo, unsigned long long *hi)
{
    /* slot 0 = [0, 1) us, slot n = [2^(n-1), 2^n) us */
    *lo = slot ? (1ull << (slot - 1)) : 0;
    *hi = 1ull << slot;
}

static void print_hist_text(const char *name, const struct drvlat_hist *h)
{
    int last = -1, first = -1;
    unsigned long long peak = 0;
    for (int i = 0; i < DRVLAT_SLOTS; i++) {
        if (h->slots[i]) {
            if (first < 0)
                first = i;
            last = i;
            if (h->slots[i] > peak)
                peak = h->slots[i];
        }
    }
    printf("\n  %s   count %llu   avg %.1f us   max %.1f us\n", name, h->count,
           h->count ? (double)h->total_ns / h->count / 1e3 : 0.0,
           (double)h->max_ns / 1e3);
    if (first < 0)
        return;
    printf("  %22s : %-8s |%-40s|\n", "usecs", "count", "distribution");
    for (int i = first; i <= last; i++) {
        unsigned long long lo, hi;
        slot_range(i, &lo, &hi);
        int stars = peak ? (int)(h->slots[i] * 40 / peak) : 0;
        char bar[41];
        memset(bar, '*', stars);
        bar[stars] = '\0';
        printf("  %10llu -> %-8llu : %-8llu |%-40s|\n", lo, hi - 1,
               h->slots[i], bar);
    }
}

static void print_hist_json(const char *kind, const char *name,
                            const struct drvlat_hist *h, bool *first)
{
    printf("%s{\"kind\": \"%s\", \"name\": \"%s\", \"count\": %llu, "
           "\"avg_us\": %.3f, \"max_us\": %.3f, \"hist_us\": {",
           *first ? "" : ", ", kind, name, h->count,
           h->count ? (double)h->total_ns / h->count / 1e3 : 0.0,
           (double)h->max_ns / 1e3);
    bool f = true;
    for (int i = 0; i < DRVLAT_SLOTS; i++) {
        if (!h->slots[i])
            continue;
        unsigned long long lo, hi;
        slot_range(i, &lo, &hi);
        printf("%s\"%llu-%llu\": %llu", f ? "" : ", ", lo, hi - 1, h->slots[i]);
        f = false;
    }
    printf("}}");
    *first = false;
}

struct row {
    struct drvlat_key key;
    struct drvlat_hist hist;
};

static int cmp_rows(const void *a, const void *b)
{
    const struct row *x = a, *y = b;
    if (x->key.kind != y->key.kind)
        return (int)x->key.kind - (int)y->key.kind;
    return (x->key.id > y->key.id) - (x->key.id < y->key.id);
}

static int report(int map_fd)
{
    static struct row rows[DRVLAT_MAX_KEYS];
    struct drvlat_key key, next;
    struct drvlat_key *prev = NULL;
    int n = 0;

    while (n < DRVLAT_MAX_KEYS && bpf_map_get_next_key(map_fd, prev, &next) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next, &rows[n].hist) == 0) {
            rows[n].key = next;
            n++;
        }
        key = next;
        prev = &key;
    }
    qsort(rows, n, sizeof(rows[0]), cmp_rows);

    char tbuf[32];
    time_t now = time(NULL);
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&now));

    bool first = true;
    unsigned int last_kind = DRVLAT_NR_KINDS;
    if (env.json)
        printf("{\"time\": \"%s\", \"rows\": [", tbuf);
    else
        printf("\n[%s]\n", tbuf);

    for (int i = 0; i < n; i++) {
        char name[64];
        row_name(&rows[i].key, &rows[i].hist, name, sizeof(name));
        if (env.filter && !strstr(name, env.filter))
            continue;
        if (env.json) {
            print_hist_json(kind_names[rows[i].key.kind], name, &rows[i].hist,
                            &first);
            continue;
        }
        if (rows[i].key.kind != last_kind) {
            last_kind = rows[i].key.kind;
            printf("\n== %s ==\n", kind_titles[last_kind]);
        }
        print_hist_text(name, &rows[i].hist);
    }
    if (env.json)
        printf("]}\n");
    else if (n == 0)
        printf("  (no samples yet)\n");
    fflush(stdout);

    if (!env.cumulative) {
        for (int i = 0; i < n; i++)
            bpf_map_delete_elem(map_fd, &rows[i].key);
    }
    return 0;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct drvlat_event))
        return 0;
    const struct drvlat_event *e = data;
    struct drvlat_key k = {.kind = e->kind, .id = e->id};
    struct drvlat_hist h = {};
    memcpy(h.name, e->name, sizeof(h.name));
    char name[64];
    row_name(&k, &h, name, sizeof(name));
    if (env.filter && !strstr(name, env.filter))
        return 0;
    if (env.json)
        printf("{\"event\": \"threshold\", \"kind\": \"%s\", \"name\": \"%s\", "
               "\"cpu\": %u, \"ts_ns\": %llu, \"dur_us\": %.3f}\n",
               kind_names[e->kind], name, e->cpu, e->ts_ns, e->dur_ns / 1e3);
    else
        printf("SLOW %-9s %-24s cpu%-3u %10.1f us\n", kind_names[e->kind], name,
               e->cpu, e->dur_ns / 1e3);
    return 0;
}

static void set_autoload(struct drvlat_bpf *skel, enum drvlat_kind kind, bool on)
{
    switch (kind) {
    case DRVLAT_HARDIRQ:
        bpf_program__set_autoload(skel->progs.handle_irq_entry, on);
        bpf_program__set_autoload(skel->progs.handle_irq_exit, on);
        break;
    case DRVLAT_SOFTIRQ:
        bpf_program__set_autoload(skel->progs.handle_softirq_entry, on);
        bpf_program__set_autoload(skel->progs.handle_softirq_exit, on);
        break;
    case DRVLAT_IRQTHREAD:
        bpf_program__set_autoload(skel->progs.handle_sched_wakeup, on);
        bpf_program__set_autoload(skel->progs.handle_sched_wakeup_new, on);
        bpf_program__set_autoload(skel->progs.handle_sched_switch, on);
        break;
    case DRVLAT_I2C:
        bpf_program__set_autoload(skel->progs.handle_i2c_write, on);
        bpf_program__set_autoload(skel->progs.handle_i2c_read, on);
        bpf_program__set_autoload(skel->progs.handle_i2c_result, on);
        break;
    case DRVLAT_SPI:
        bpf_program__set_autoload(skel->progs.handle_spi_start, on);
        bpf_program__set_autoload(skel->progs.handle_spi_done, on);
        break;
    default:
        break;
    }
}

int main(int argc, char **argv)
{
    static const struct argp argp = {opts, parse_arg, NULL, doc, NULL, NULL, NULL};
    struct ring_buffer *rb = NULL;
    struct drvlat_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    libbpf_set_print(libbpf_print);

    skel = drvlat_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }
    ensure_tracefs();
    skel->rodata->threshold_ns = (unsigned long long)env.threshold_us * 1000ull;

    unsigned int active = 0;
    for (int k = 0; k < DRVLAT_NR_KINDS; k++) {
        bool want = env.kinds & (1u << k);
        bool have = tracepoints_present(kind_tp_dir[k]);
        if (want && !have)
            fprintf(stderr, "note: %s tracepoints not found in this kernel, "
                            "skipping %s\n", kind_tp_dir[k], kind_names[k]);
        set_autoload(skel, k, want && have);
        if (want && have)
            active |= 1u << k;
    }
    if (!active) {
        fprintf(stderr, "nothing to trace\n");
        err = 1;
        goto cleanup;
    }

    err = drvlat_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF programs: %s (run as root?)\n",
                strerror(-err));
        goto cleanup;
    }
    err = drvlat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach: %s\n", strerror(-err));
        goto cleanup;
    }

    if (env.threshold_us) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
                              NULL, NULL);
        if (!rb) {
            err = -errno;
            fprintf(stderr, "failed to create ring buffer\n");
            goto cleanup;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!env.json) {
        fprintf(stderr, "Tracing:");
        for (int k = 0; k < DRVLAT_NR_KINDS; k++)
            if (active & (1u << k))
                fprintf(stderr, " %s", kind_names[k]);
        fprintf(stderr, "%s. Ctrl-C to stop.\n",
                env.threshold_us ? " (with slow-sample log)" : "");
    }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    time_t last_report = start.tv_sec;
    int map_fd = bpf_map__fd(skel->maps.hists);

    while (!exiting) {
        if (rb) {
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "ring buffer poll: %d\n", err);
                break;
            }
        } else {
            usleep(100 * 1000);
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (env.interval && now.tv_sec - last_report >= env.interval) {
            report(map_fd);
            last_report = now.tv_sec;
        }
        if (env.duration && now.tv_sec - start.tv_sec >= env.duration)
            break;
    }
    err = 0;
    if (!env.interval || env.duration)
        report(map_fd);

cleanup:
    ring_buffer__free(rb);
    drvlat_bpf__destroy(skel);
    return err < 0 ? -err : err;
}
