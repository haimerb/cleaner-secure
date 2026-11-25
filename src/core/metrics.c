#include "metrics.h"

#include <stdlib.h>
#include <tlhelp32.h>
#include <psapi.h>

typedef struct {
    uint32_t pid;
    ULONGLONG cpu;
    FILETIME wall;
    IO_COUNTERS io;
    bool has;
} cc_baseline_t;

struct cc_metrics_s {
    cc_baseline_t *items;
    size_t count;
    size_t capacity;
};

static ULONGLONG cc_filetime_value(const FILETIME *ft)
{
    if (ft == NULL) {
        return 0;
    }
    return ((ULONGLONG)ft->dwHighDateTime << 32) | (ULONGLONG)ft->dwLowDateTime;
}

static cc_baseline_t *cc_baseline_find(cc_metrics_t *m, uint32_t pid)
{
    size_t i;

    if (m == NULL) {
        return NULL;
    }
    for (i = 0; i < m->count; i++) {
        if (m->items[i].pid == pid) {
            return &m->items[i];
        }
    }
    return NULL;
}

static const cc_baseline_t *cc_baseline_find_const(const cc_metrics_t *m,
                                                   uint32_t pid)
{
    size_t i;

    if (m == NULL) {
        return NULL;
    }
    for (i = 0; i < m->count; i++) {
        if (m->items[i].pid == pid) {
            return &m->items[i];
        }
    }
    return NULL;
}

static bool cc_baseline_reserve(cc_metrics_t *m, size_t needed)
{
    cc_baseline_t *items;
    size_t capacity;

    if (m == NULL || needed <= m->capacity) {
        return m != NULL;
    }

    capacity = m->capacity == 0 ? 16 : m->capacity;
    while (capacity < needed) {
        if (capacity > ((size_t)-1) / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    if (capacity > ((size_t)-1) / sizeof(*items)) {
        return false;
    }

    items = (cc_baseline_t *)realloc(m->items, capacity * sizeof(*items));
    if (items == NULL) {
        return false;
    }
    m->items = items;
    m->capacity = capacity;
    return true;
}

static uint32_t cc_thread_count(uint32_t pid)
{
    HANDLE snap;
    THREADENTRY32 entry;
    uint32_t count = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid) {
                count++;
            }
        } while (Thread32Next(snap, &entry));
    }

    CloseHandle(snap);
    return count;
}

cc_metrics_t *cc_metrics_create(void)
{
    return (cc_metrics_t *)calloc(1, sizeof(cc_metrics_t));
}

void cc_metrics_destroy(cc_metrics_t *m)
{
    if (m == NULL) {
        return;
    }
    free(m->items);
    free(m);
}

bool cc_metrics_sample(cc_metrics_t *m, uint32_t pid, cc_proc_metrics_t *out)
{
    HANDLE proc;
    FILETIME create_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    FILETIME wall_now;
    PROCESS_MEMORY_COUNTERS_EX memory;
    IO_COUNTERS io;
    DWORD handles = 0;
    ULONGLONG cpu_now;
    cc_baseline_t *baseline;

    if (m == NULL || out == NULL || pid == 0) {
        return false;
    }
    ZeroMemory(out, sizeof(*out));

    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (proc == NULL) {
        return false;
    }
    if (!GetProcessTimes(proc, &create_time, &exit_time, &kernel_time,
                         &user_time)) {
        CloseHandle(proc);
        return false;
    }

    ZeroMemory(&memory, sizeof(memory));
    if (GetProcessMemoryInfo(proc, (PROCESS_MEMORY_COUNTERS *)&memory,
                             sizeof(memory))) {
        out->working_set = (uint64_t)memory.WorkingSetSize;
        out->private_bytes = (uint64_t)memory.PrivateUsage;
    }

    ZeroMemory(&io, sizeof(io));
    if (GetProcessIoCounters(proc, &io)) {
        out->io_read_bytes = (uint64_t)io.ReadTransferCount;
        out->io_write_bytes = (uint64_t)io.WriteTransferCount;
    }

    if (GetProcessHandleCount(proc, &handles)) {
        out->handle_count = (uint64_t)handles;
    }
    out->thread_count = cc_thread_count(pid);
    CloseHandle(proc);

    cpu_now = cc_filetime_value(&kernel_time) + cc_filetime_value(&user_time);
    GetSystemTimeAsFileTime(&wall_now);

    baseline = cc_baseline_find(m, pid);
    if (baseline != NULL && baseline->has) {
        ULONGLONG cpu_delta = 0;
        ULONGLONG wall_delta = 0;
        ULONGLONG wall_value = cc_filetime_value(&wall_now);
        ULONGLONG wall_previous = cc_filetime_value(&baseline->wall);
        double cpu_percent = 0.0;

        if (cpu_now > baseline->cpu) {
            cpu_delta = cpu_now - baseline->cpu;
        }
        if (wall_value > wall_previous) {
            wall_delta = wall_value - wall_previous;
        }
        if (wall_delta > 0) {
            cpu_percent = (double)cpu_delta * 100.0 / (double)wall_delta;
        }
        if (cpu_percent < 0.0) {
            cpu_percent = 0.0;
        }
        out->cpu_percent = cpu_percent;
    }

    if (baseline == NULL && cc_baseline_reserve(m, m->count + 1)) {
        baseline = &m->items[m->count];
        ZeroMemory(baseline, sizeof(*baseline));
        baseline->pid = pid;
        m->count++;
    }
    if (baseline != NULL) {
        baseline->cpu = cpu_now;
        baseline->wall = wall_now;
        baseline->io = io;
        baseline->has = true;
    }

    return true;
}

bool cc_metrics_has_baseline(const cc_metrics_t *m, uint32_t pid)
{
    const cc_baseline_t *baseline = cc_baseline_find_const(m, pid);

    return baseline != NULL && baseline->has;
}

void cc_metrics_prune(cc_metrics_t *m)
{
    HANDLE snap;
    PROCESSENTRY32W entry;
    bool *alive;
    size_t i;
    size_t write = 0;

    if (m == NULL || m->count == 0) {
        return;
    }
    alive = (bool *)calloc(m->count, sizeof(*alive));
    if (alive == NULL) {
        return;
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        free(alive);
        return;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            for (i = 0; i < m->count; i++) {
                if (m->items[i].pid == (uint32_t)entry.th32ProcessID) {
                    alive[i] = true;
                }
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);

    for (i = 0; i < m->count; i++) {
        if (alive[i]) {
            m->items[write++] = m->items[i];
        }
    }
    m->count = write;
    free(alive);
}
