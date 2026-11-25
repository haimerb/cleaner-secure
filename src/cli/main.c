#include "types.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
#include "config.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include "ioc.h"
#include "detect.h"
#include "registry_scan.h"
#include "eventlog_scan.h"
#include "response.h"
#include "trust.h"
#include "metrics.h"
#include "proc.h"
#include "json.h"

#include <shellapi.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CC_ALERT_CAP 256
#define CC_SLEEP_SLICE_MS 250

typedef enum {
    CC_ACTION_NONE = 0,
    CC_ACTION_KILL,
    CC_ACTION_SUSPEND,
    CC_ACTION_RESUME,
    CC_ACTION_SERVICE_STOP,
    CC_ACTION_SERVICE_START
} cc_action_t;

typedef struct {
    bool once;
    bool json;
    uint32_t interval_sec;
    cc_action_t action;
    uint32_t pid;
    wchar_t service[CC_MAX_NAME];
} cc_options_t;

typedef struct {
    cc_alert_t alert;
    int score;
    const wchar_t *name;
    double cpu;
    double ram_mb;
} cc_view_t;

static volatile bool g_stop = false;

static BOOL WINAPI cc_ctrl_handler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

static void cc_usage(const char *prog)
{
    fprintf(stdout,
            "Usage: %s [--once] [--interval <sec>] [--json] [--kill <pid>] "
            "[--suspend <pid>] [--resume <pid>] [--service-stop <name>] "
            "[--service-start <name>] [--help]\n",
            prog);
}

static bool cc_parse_u32(const wchar_t *text, uint32_t *out)
{
    wchar_t *end;
    unsigned long value;

    if (text == NULL || out == NULL || *text == L'\0') {
        return false;
    }
    errno = 0;
    value = wcstoul(text, &end, 10);
    if (errno == ERANGE || end == text || *end != L'\0') {
        return false;
    }
    if (value == 0 || value > (unsigned long)UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static void cc_options_init(cc_options_t *opts)
{
    opts->once = false;
    opts->json = false;
    opts->interval_sec = 0;
    opts->action = CC_ACTION_NONE;
    opts->pid = 0;
    opts->service[0] = L'\0';
}

static bool cc_parse_args(int argc, wchar_t **argv, cc_options_t *opts,
                          bool *help, const char *prog)
{
    char arg[CC_MAX_PATH_LEN * 4 + 1];
    char val[CC_MAX_PATH_LEN * 4 + 1];
    uint32_t number;
    int i;

    *help = false;
    for (i = 1; i < argc; i++) {
        cc_wide_to_utf8(argv[i], arg, sizeof(arg));
        if (wcscmp(argv[i], L"--help") == 0) {
            *help = true;
            cc_usage(prog);
            return true;
        }
        if (wcscmp(argv[i], L"--once") == 0) {
            opts->once = true;
            continue;
        }
        if (wcscmp(argv[i], L"--json") == 0) {
            opts->json = true;
            continue;
        }
        if (wcscmp(argv[i], L"--interval") == 0 ||
            wcscmp(argv[i], L"--kill") == 0 ||
            wcscmp(argv[i], L"--suspend") == 0 ||
            wcscmp(argv[i], L"--resume") == 0 ||
            wcscmp(argv[i], L"--service-stop") == 0 ||
            wcscmp(argv[i], L"--service-start") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for %s\n", arg);
                return false;
            }
            cc_wide_to_utf8(argv[i + 1], val, sizeof(val));
            if (wcscmp(argv[i], L"--service-stop") == 0 ||
                wcscmp(argv[i], L"--service-start") == 0) {
                if (argv[i + 1][0] == L'\0' ||
                    wcslen(argv[i + 1]) >= CC_MAX_NAME) {
                    fprintf(stderr, "Invalid value for %s: %s\n", arg, val);
                    return false;
                }
                wcscpy(opts->service, argv[i + 1]);
                opts->action = wcscmp(argv[i], L"--service-stop") == 0
                                   ? CC_ACTION_SERVICE_STOP
                                   : CC_ACTION_SERVICE_START;
            } else {
                if (!cc_parse_u32(argv[i + 1], &number)) {
                    fprintf(stderr, "Invalid value for %s: %s\n", arg, val);
                    return false;
                }
                if (wcscmp(argv[i], L"--interval") == 0) {
                    opts->interval_sec = number;
                } else {
                    opts->pid = number;
                    if (wcscmp(argv[i], L"--kill") == 0) {
                        opts->action = CC_ACTION_KILL;
                    } else if (wcscmp(argv[i], L"--suspend") == 0) {
                        opts->action = CC_ACTION_SUSPEND;
                    } else {
                        opts->action = CC_ACTION_RESUME;
                    }
                }
            }
            i++;
            continue;
        }
        fprintf(stderr, "Unknown argument: %s\n", arg);
        cc_usage(prog);
        return false;
    }
    return true;
}

static bool cc_join_path(wchar_t *dst, size_t cap, const wchar_t *dir,
                         const wchar_t *name)
{
    size_t dir_len;
    size_t name_len;
    size_t need;
    size_t i;
    size_t k;
    bool sep;

    if (dst == NULL || dir == NULL || name == NULL || cap == 0) {
        return false;
    }
    dir_len = wcslen(dir);
    name_len = wcslen(name);
    sep = dir_len > 0 && (dir[dir_len - 1] == L'\\' || dir[dir_len - 1] == L'/');
    need = dir_len + (sep ? 0 : 1) + name_len + 1;
    if (need > cap) {
        return false;
    }
    for (k = 0; k < dir_len; k++) {
        dst[k] = dir[k];
    }
    i = dir_len;
    if (!sep) {
        dst[i++] = L'\\';
    }
    for (k = 0; k < name_len; k++) {
        dst[i++] = name[k];
    }
    dst[i] = L'\0';
    return true;
}

static void cc_load_scan_settings(const wchar_t *config_dir,
                                  uint32_t *interval_sec,
                                  int *eventlog_minutes)
{
    wchar_t path[CC_MAX_PATH_LEN];
    cc_json_t *json;
    uint32_t value;

    json = NULL;
    if (cc_join_path(path, sizeof(path) / sizeof(path[0]), config_dir,
                     L"thresholds.json")) {
        json = cc_json_parse_file(path);
    }
    if (*interval_sec == 0) {
        value = 0;
        if (json != NULL && cc_json_get_uint(json, "scan_interval_seconds", &value) &&
            value > 0) {
            *interval_sec = value;
        } else {
            *interval_sec = 2;
        }
    }
    value = 0;
    if (json != NULL && cc_json_get_uint(json, "eventlog_window_minutes", &value) &&
        value > 0 && value <= (uint32_t)INT_MAX) {
        *eventlog_minutes = (int)value;
    } else {
        *eventlog_minutes = 60;
    }
    cc_json_free(json);
}

static bool cc_clear_console(void)
{
    HANDLE output;
    CONSOLE_SCREEN_BUFFER_INFO info;
    COORD home;
    DWORD written;
    DWORD cells;

    output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output == INVALID_HANDLE_VALUE) {
        return false;
    }
    home.X = 0;
    home.Y = 0;
    if (!SetConsoleCursorPosition(output, home) ||
        !GetConsoleScreenBufferInfo(output, &info)) {
        return false;
    }
    cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
    if (cells == 0) {
        return true;
    }
    if (!FillConsoleOutputCharacterW(output, L' ', cells, home, &written)) {
        return false;
    }
    (void)FillConsoleOutputAttribute(output, info.wAttributes, cells, home, &written);
    return SetConsoleCursorPosition(output, home) ? true : false;
}

static void cc_sleep_seconds(uint32_t seconds, volatile bool *stop)
{
    uint64_t remaining;

    remaining = (uint64_t)seconds * 1000ULL;
    while (remaining > 0 && !*stop) {
        DWORD chunk;

        chunk = remaining > (uint64_t)CC_SLEEP_SLICE_MS
                    ? (DWORD)CC_SLEEP_SLICE_MS
                    : (DWORD)remaining;
        Sleep(chunk);
        remaining -= chunk;
    }
}

static void cc_print_error(FILE *out, const char *what, DWORD err)
{
    wchar_t text[512];
    char utf8[2048];
    DWORD count;
    size_t len;

    count = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                           NULL, err, 0, text,
                           (DWORD)(sizeof(text) / sizeof(text[0])), NULL);
    if (count == 0) {
        (void)swprintf(text, sizeof(text) / sizeof(text[0]), L"error %lu",
                       (unsigned long)err);
    } else {
        len = (size_t)count;
        while (len > 0 && (text[len - 1] == L'\r' || text[len - 1] == L'\n')) {
            text[--len] = L'\0';
        }
    }
    cc_wide_to_utf8(text, utf8, sizeof(utf8));
    fprintf(out, "%s failed: %s (error %lu)\n", what, utf8, (unsigned long)err);
}

static int cc_execute_action(const cc_options_t *opts, FILE *out)
{
    char label[160];
    char service[CC_MAX_NAME * 4 + 1];
    DWORD err;
    DWORD code;
    bool ok;

    cc_wide_to_utf8(opts->service, service, sizeof(service));
    err = 0;
    ok = false;
    switch (opts->action) {
    case CC_ACTION_KILL:
        ok = cc_kill_process(opts->pid, &err);
        if (ok) {
            fprintf(out, "Killed pid %lu\n", (unsigned long)opts->pid);
        } else {
            (void)snprintf(label, sizeof(label), "kill pid %lu",
                           (unsigned long)opts->pid);
        }
        break;
    case CC_ACTION_SUSPEND:
        ok = cc_suspend_process(opts->pid, &err);
        if (ok) {
            fprintf(out, "Suspended pid %lu\n", (unsigned long)opts->pid);
        } else {
            (void)snprintf(label, sizeof(label), "suspend pid %lu",
                           (unsigned long)opts->pid);
        }
        break;
    case CC_ACTION_RESUME:
        ok = cc_resume_process(opts->pid, &err);
        if (ok) {
            fprintf(out, "Resumed pid %lu\n", (unsigned long)opts->pid);
        } else {
            (void)snprintf(label, sizeof(label), "resume pid %lu",
                           (unsigned long)opts->pid);
        }
        break;
    case CC_ACTION_SERVICE_STOP:
        ok = cc_service_stop(opts->service, &err);
        if (ok) {
            fprintf(out, "Stopped service %s\n", service);
        } else {
            (void)snprintf(label, sizeof(label), "stop service %s", service);
        }
        break;
    case CC_ACTION_SERVICE_START:
        ok = cc_service_start(opts->service, &err);
        if (ok) {
            fprintf(out, "Started service %s\n", service);
        } else {
            (void)snprintf(label, sizeof(label), "start service %s", service);
        }
        break;
    default:
        return 1;
    }
    if (!ok) {
        code = err != 0 ? err : GetLastError();
        cc_print_error(out, label, code);
    }
    return ok ? 0 : 1;
}

static const char *cc_risk_name(cc_risk_t risk)
{
    switch (risk) {
    case CC_RISK_NONE:
        return "none";
    case CC_RISK_LOW:
        return "low";
    case CC_RISK_MEDIUM:
        return "medium";
    case CC_RISK_HIGH:
        return "high";
    case CC_RISK_CRITICAL:
        return "critical";
    default:
        return "unknown";
    }
}

static void cc_copy_trunc(char *dst, size_t cap, const char *src)
{
    size_t i;

    if (dst == NULL || cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < cap && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

static const wchar_t *cc_find_proc_name(const cc_proc_info_t *procs, int count,
                                        uint32_t pid)
{
    int i;

    if (procs == NULL || pid == 0) {
        return NULL;
    }
    for (i = 0; i < count; i++) {
        if (procs[i].pid == pid) {
            return procs[i].name;
        }
    }
    return NULL;
}

static int cc_view_cmp(const void *left, const void *right)
{
    const cc_view_t *a;
    const cc_view_t *b;

    a = (const cc_view_t *)left;
    b = (const cc_view_t *)right;
    if (a->score != b->score) {
        return a->score > b->score ? -1 : 1;
    }
    if (a->alert.pid != b->alert.pid) {
        return a->alert.pid < b->alert.pid ? -1 : 1;
    }
    return 0;
}

static void cc_json_string(FILE *out, const char *text)
{
    const unsigned char *p;

    fputc('"', out);
    if (text != NULL) {
        for (p = (const unsigned char *)text; *p != '\0'; p++) {
            switch (*p) {
            case '"':
                fputs("\\\"", out);
                break;
            case '\\':
                fputs("\\\\", out);
                break;
            case '\b':
                fputs("\\b", out);
                break;
            case '\f':
                fputs("\\f", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (*p < 0x20) {
                    fprintf(out, "\\u%04x", (unsigned)*p);
                } else {
                    fputc((int)*p, out);
                }
                break;
            }
        }
    }
    fputc('"', out);
}

static void cc_make_timestamp(char *dst, size_t cap)
{
    SYSTEMTIME now;

    GetLocalTime(&now);
    (void)snprintf(dst, cap, "%04u-%02u-%02uT%02u:%02u:%02u",
                   (unsigned)now.wYear, (unsigned)now.wMonth, (unsigned)now.wDay,
                   (unsigned)now.wHour, (unsigned)now.wMinute, (unsigned)now.wSecond);
}

static void cc_print_table(FILE *out, const cc_view_t *views, int count,
                           int total_processes)
{
    char name_full[CC_MAX_NAME * 4 + 1];
    char name[28];
    char category[16];
    char reason[80];
    int i;

    fprintf(out, "Processes: %d  Alerts: %d\n", total_processes, count);
    fprintf(out, "%-8s %-28s %-7s %-9s %-8s %-16s %s\n",
            "PID", "NAME", "CPU%", "RAM MB", "RISK", "CATEGORY", "REASON");
    fprintf(out, "%-8s %-28s %-7s %-9s %-8s %-16s %s\n",
            "--------", "----------------------------", "-------", "---------",
            "--------", "----------------", "-------------------------");
    for (i = 0; i < count; i++) {
        const wchar_t *source;

        source = views[i].name != NULL ? views[i].name : views[i].alert.target;
        cc_wide_to_utf8(source, name_full, sizeof(name_full));
        cc_copy_trunc(name, sizeof(name), name_full);
        cc_copy_trunc(category, sizeof(category), views[i].alert.category);
        cc_copy_trunc(reason, sizeof(reason), views[i].alert.reason);
        fprintf(out, "%-8lu %-28s %6.1f %9.1f %-8s %-16s %s\n",
                (unsigned long)views[i].alert.pid, name, views[i].cpu,
                views[i].ram_mb, cc_risk_name(views[i].alert.risk), category, reason);
    }
}

static void cc_print_json(FILE *out, const char *timestamp, uint32_t pid,
                          int total_processes, const cc_view_t *views, int count)
{
    char target[CC_MAX_NAME * 4 + 1];
    int i;

    fputs("{\"timestamp\":", out);
    cc_json_string(out, timestamp);
    fprintf(out, ",\"pid\":%lu,\"total_processes\":%d,\"alerts\":[",
            (unsigned long)pid, total_processes);
    for (i = 0; i < count; i++) {
        if (i > 0) {
            fputc(',', out);
        }
        fputs("{\"pid\":", out);
        fprintf(out, "%lu", (unsigned long)views[i].alert.pid);
        fputs(",\"risk\":", out);
        cc_json_string(out, cc_risk_name(views[i].alert.risk));
        fputs(",\"category\":", out);
        cc_json_string(out, views[i].alert.category);
        fputs(",\"target\":", out);
        cc_wide_to_utf8(views[i].alert.target, target, sizeof(target));
        cc_json_string(out, target);
        fputs(",\"reason\":", out);
        cc_json_string(out, views[i].alert.reason);
        fputs(",\"score\":", out);
        fprintf(out, "%d", views[i].score);
        fputc('}', out);
    }
    fputs("]}\n", out);
}

static int cc_scan_once(cc_detect_ctx_t *ctx, const cc_ioc_t *ioc,
                        int eventlog_window_minutes, cc_proc_info_t *procs,
                        int procs_cap, cc_alert_t *alerts, cc_view_t *views,
                        int cap, int *total_processes)
{
    cc_proc_metrics_t metrics_sample;
    int listed;
    int count;
    int added;
    int i;
    ULONGLONG deadline = GetTickCount64() + 60000;

    if (ctx != NULL && ctx->cfg != NULL && ctx->cfg->scan_timeout_ms != 0) {
        deadline = GetTickCount64() + (ULONGLONG)ctx->cfg->scan_timeout_ms;
    }
    cc_metrics_prune(ctx->metrics);
    count = cc_detect_processes(ctx, alerts, cap, deadline);
    if (count < 0) {
        count = 0;
    }
    if (count > cap) {
        count = cap;
    }
    if (count < cap) {
        added = cc_registry_scan(ioc, alerts + count, cap - count, deadline);
        if (added < 0) {
            added = 0;
        }
        if (added > cap - count) {
            added = cap - count;
        }
        count += added;
    }
    if (count < cap) {
        added = cc_eventlog_scan(eventlog_window_minutes, alerts + count,
                                 cap - count, NULL, deadline);
        if (added < 0) {
            added = 0;
        }
        if (added > cap - count) {
            added = cap - count;
        }
        count += added;
    }
    listed = cc_proc_list(procs, procs_cap);
    if (listed < 0) {
        listed = 0;
    }
    *total_processes = listed;
    if (listed > procs_cap) {
        listed = procs_cap;
    }
    for (i = 0; i < count; i++) {
        views[i].alert = alerts[i];
        views[i].score = cc_alert_score(alerts[i].risk, alerts[i].category);
        views[i].name = cc_find_proc_name(procs, listed, alerts[i].pid);
        views[i].cpu = 0.0;
        views[i].ram_mb = 0.0;
        if (alerts[i].pid != 0 &&
            cc_metrics_sample(ctx->metrics, alerts[i].pid, &metrics_sample)) {
            views[i].cpu = metrics_sample.cpu_percent;
            views[i].ram_mb = (double)metrics_sample.working_set / 1048576.0;
        }
    }
    qsort(views, (size_t)count, sizeof(views[0]), cc_view_cmp);
    return count;
}

static int cc_main_wide(int argc, wchar_t **argv);

int main(void)
{
    int argc;
    wchar_t **argv;
    LPWSTR *wide_argv;
    int rc;

    wide_argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (wide_argv == NULL) {
        return 1;
    }
    argv = (wchar_t **)wide_argv;
    rc = cc_main_wide(argc, argv);
    LocalFree(wide_argv);
    return rc;
}

static int cc_main_wide(int argc, wchar_t **argv)
{
    char prog[CC_MAX_PATH_LEN * 4 + 1];
    cc_options_t opts;
    cc_config_t cfg;
    cc_detect_ctx_t ctx;
    cc_ioc_t *ioc;
    cc_publishers_t *publishers;
    cc_metrics_t *metrics;
    cc_trust_cache_t *trust_cache;
    cc_proc_info_t *procs;
    cc_alert_t *alerts;
    cc_view_t *views;
    wchar_t ioc_path[CC_MAX_PATH_LEN];
    wchar_t publishers_path[CC_MAX_PATH_LEN];
    uint32_t interval_sec;
    int eventlog_window_minutes;
    int alert_count;
    int total_processes;
    char timestamp[64];
    FILE *status;
    bool help;
    int rc;

    (void)SetConsoleOutputCP(CP_UTF8);
    cc_wide_to_utf8(argc > 0 && argv[0] != NULL ? argv[0] : L"cleaner-secure-cli",
                    prog, sizeof(prog));
    if (prog[0] == '\0') {
        (void)strcpy(prog, "cleaner-secure-cli");
    }
    cc_options_init(&opts);
    if (!cc_parse_args(argc, argv, &opts, &help, prog)) {
        return 1;
    }
    if (help) {
        return 0;
    }
    status = opts.json ? stderr : stdout;
    if (opts.action != CC_ACTION_NONE) {
        return cc_execute_action(&opts, status);
    }

    if (!cc_config_load(&cfg, NULL)) {
        fprintf(stderr, "Failed to load configuration\n");
        return 1;
    }
    interval_sec = opts.interval_sec;
    eventlog_window_minutes = 60;
    cc_load_scan_settings(cfg.config_dir, &interval_sec, &eventlog_window_minutes);
    fprintf(status, "VirusTotal: %s\n", cfg.vt_api_key[0] != '\0' ? "enabled" : "disabled");

    if (!cc_join_path(ioc_path, sizeof(ioc_path) / sizeof(ioc_path[0]),
                      cfg.config_dir, L"iocs.json") ||
        !cc_join_path(publishers_path,
                      sizeof(publishers_path) / sizeof(publishers_path[0]),
                      cfg.config_dir, L"publishers.json")) {
        fprintf(stderr, "Configuration path is too long\n");
        return 1;
    }

    ioc = NULL;
    publishers = NULL;
    metrics = NULL;
    trust_cache = NULL;
    procs = NULL;
    alerts = NULL;
    views = NULL;
    rc = 1;

    ioc = cc_ioc_load(ioc_path);
    publishers = cc_publishers_load(publishers_path);
    metrics = cc_metrics_create();
    trust_cache = cc_trust_cache_create();
    if (metrics == NULL || trust_cache == NULL) {
        fprintf(stderr, "Failed to initialize scanner contexts\n");
        goto cleanup;
    }
    procs = (cc_proc_info_t *)calloc((size_t)CC_MAX_PROCS, sizeof(*procs));
    alerts = (cc_alert_t *)calloc((size_t)CC_ALERT_CAP, sizeof(*alerts));
    views = (cc_view_t *)calloc((size_t)CC_ALERT_CAP, sizeof(*views));
    if (procs == NULL || alerts == NULL || views == NULL) {
        fprintf(stderr, "Out of memory\n");
        goto cleanup;
    }

    ctx.cfg = (const struct cc_config_s *)(void *)&cfg;
    ctx.ioc = ioc;
    ctx.pubs = publishers;
    ctx.metrics = metrics;
    ctx.trust_cache = trust_cache;
    ctx.alert_count = 0;
    (void)SetConsoleCtrlHandler(cc_ctrl_handler, TRUE);

    while (!g_stop) {
        if (!opts.json && !opts.once && !cc_clear_console()) {
            fprintf(stdout, "\n--- scan ---\n");
        }
        alert_count = cc_scan_once(&ctx, ioc, eventlog_window_minutes, procs,
                                   CC_MAX_PROCS, alerts, views, CC_ALERT_CAP,
                                   &total_processes);
        if (opts.json) {
            cc_make_timestamp(timestamp, sizeof(timestamp));
            cc_print_json(stdout, timestamp, GetCurrentProcessId(), total_processes,
                          views, alert_count);
        } else {
            cc_print_table(stdout, views, alert_count, total_processes);
        }
        fflush(stdout);
        if (opts.once || g_stop) {
            break;
        }
        cc_sleep_seconds(interval_sec, &g_stop);
    }
    rc = 0;

cleanup:
    free(views);
    free(alerts);
    free(procs);
    cc_trust_cache_free(trust_cache);
    cc_metrics_destroy(metrics);
    cc_publishers_free(publishers);
    cc_ioc_free(ioc);
    return rc;
}
