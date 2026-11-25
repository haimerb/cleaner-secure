#include "types.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
#include "config.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include "detect.h"
#include "ioc.h"
#include "json.h"
#include "metrics.h"
#include "proc.h"
#include "registry_scan.h"
#include "eventlog_scan.h"
#include "network_scan.h"
#include "response.h"
#include "trust.h"

#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define ID_LIST 100
#define ID_STATUS 101
#define ID_BTN_SCAN 102
#define ID_BTN_KILL 103
#define ID_BTN_SUSPEND 104
#define ID_BTN_RESUME 105
#define ID_BTN_ELEV 106
#define ID_BTN_RUNAS 107
#define ID_CHK_AUTO 108
#define ID_BTN_BLOCK_IP 109
#define ID_BTN_UNBLOCK_IP 110
#define ID_TABS 111
#define ID_PROC_LIST 112
#define ID_SEARCH 113
#define ID_FILTER 114
#define ID_PROGRESS 115
#define ID_TIMER 1
#define WM_APP_SCAN_DONE (WM_APP + 1)
#define CC_ALERT_CAP 1024
#define CC_COL_REASON 6
#define CC_PROC_COL_COUNT 9
#define CC_VIEW_ALERTS 0
#define CC_VIEW_PROCESSES 1
#define CC_IDI_APPLICATION 100
#define CC_IDC_ARROW 32512

#ifndef PBS_MARQUEE
#define PBS_MARQUEE 0x0008
#endif

#ifndef TCS_TOP
#define TCS_TOP 0
#endif

typedef struct {
    cc_alert_t alert;
    double cpu;
    double ram_mb;
    int score;
} ui_row_t;

typedef struct {
    const wchar_t *text;
    int width;
} ui_column_def_t;

typedef struct {
    ui_row_t *rows;
    int count;
    cc_process_view_t *processes;
    int process_count;
    int process_total;
    int analyzed;
    bool ok;
} ui_scan_result_t;

typedef struct {
    HWND tabs;
    HWND list;
    HWND proc_list;
    HWND search;
    HWND filter;
    HWND progress;
    HWND status;
    HWND btn_scan;
    HWND btn_kill;
    HWND btn_suspend;
    HWND btn_resume;
    HWND btn_block_ip;
    HWND btn_unblock_ip;
    HWND btn_elev;
    HWND btn_runas;
    HWND chk_auto;
    HWND hwnd;
    HANDLE scan_event;
    HANDLE stop_event;
    HANDLE scan_thread;
    volatile LONG scan_pending;
    volatile LONG scan_busy;
    volatile LONG shutdown;
    volatile LONG vt_live_request;
    HFONT font;
    cc_config_t cfg;
    cc_ioc_t *ioc;
    cc_publishers_t *pubs;
    cc_metrics_t *metrics;
    cc_metrics_t *view_metrics;
    cc_metrics_t *inventory_metrics;
    cc_trust_cache_t *cache;
    ui_row_t *rows;
    cc_process_view_t *processes;
    int row_count;
    int process_count;
    int process_total;
    int analyzed;
    int view;
    int sort_column;
    bool sort_desc;
    int filter_index;
    wchar_t search_text[128];
    wchar_t last_scan[32];
    bool elevated;
    UINT timer_ms;
    int eventlog_minutes;
} ui_state_t;

static ui_state_t g;

static bool ui_join_path(wchar_t *dst, size_t cap, const wchar_t *dir,
                         const wchar_t *name)
{
    size_t dir_len;
    size_t name_len;
    size_t need;
    size_t i;
    size_t k;

    if (dst == NULL || dir == NULL || name == NULL || cap == 0) {
        return false;
    }
    dir_len = wcslen(dir);
    name_len = wcslen(name);
    need = dir_len + 1 + name_len + 1;
    if (dir_len > 0 && (dir[dir_len - 1] == L'\\' || dir[dir_len - 1] == L'/')) {
        need--;
    }
    if (need > cap) {
        return false;
    }
    i = 0;
    for (k = 0; k < dir_len; k++) {
        dst[i++] = dir[k];
    }
    if (i > 0 && dst[i - 1] != L'\\' && dst[i - 1] != L'/') {
        dst[i++] = L'\\';
    }
    for (k = 0; k < name_len; k++) {
        dst[i++] = name[k];
    }
    dst[i] = L'\0';
    return true;
}

static void ui_utf8_to_wide(const char *src, wchar_t *dst, size_t cap)
{
    int written;

    if (cap == 0) {
        return;
    }
    if (src == NULL || src[0] == '\0') {
        dst[0] = L'\0';
        return;
    }
    written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1,
                                  dst, (int)cap);
    if (written <= 0) {
        dst[0] = L'\0';
    }
}

static void ui_wstr_copy(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t i = 0;

    if (dst == NULL || cap == 0) {
        return;
    }
    if (src != NULL) {
        while (i + 1 < cap && src[i] != L'\0') {
            dst[i] = src[i];
            i++;
        }
    }
    dst[i] = L'\0';
}

static const wchar_t *ui_risk_name(cc_risk_t risk)
{
    switch (risk) {
    case CC_RISK_NONE:
        return L"Ninguno";
    case CC_RISK_LOW:
        return L"Bajo";
    case CC_RISK_MEDIUM:
        return L"Medio";
    case CC_RISK_HIGH:
        return L"Alto";
    case CC_RISK_CRITICAL:
        return L"Crítico";
    default:
        return L"Desconocido";
    }
}

static void ui_error_text(DWORD code, wchar_t *dst, size_t cap)
{
    DWORD n;

    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, 0, dst, (DWORD)cap, NULL);
    if (n == 0) {
        swprintf(dst, cap, L"Error %lu (0x%08lX)", (unsigned long)code,
                 (unsigned long)code);
    }
}

static void ui_load_timing(const wchar_t *config_dir)
{
    wchar_t path[CC_MAX_PATH_LEN];
    cc_json_t *j;
    uint32_t seconds = 2;
    uint32_t minutes = 60;

    g.timer_ms = 2000;
    g.eventlog_minutes = 60;
    if (!ui_join_path(path, sizeof(path) / sizeof(path[0]), config_dir,
                      L"thresholds.json")) {
        return;
    }
    j = cc_json_parse_file(path);
    if (j == NULL) {
        return;
    }
    if (cc_json_get_uint(j, "scan_interval_seconds", &seconds)) {
        if (seconds < 1) {
            seconds = 1;
        }
        if (seconds > 3600) {
            seconds = 3600;
        }
    }
    if (cc_json_get_uint(j, "eventlog_window_minutes", &minutes)) {
        if (minutes < 1) {
            minutes = 1;
        }
        if (minutes > 1440) {
            minutes = 1440;
        }
    }
    cc_json_free(j);
    g.timer_ms = (UINT)(seconds * 1000);
    g.eventlog_minutes = (int)minutes;
}

static int ui_string_cmp(const wchar_t *a, const wchar_t *b)
{
    size_t i = 0;

    if (a == NULL) {
        a = L"";
    }
    if (b == NULL) {
        b = L"";
    }
    for (;;) {
        wchar_t ca = (wchar_t)towlower((wint_t)a[i]);
        wchar_t cb = (wchar_t)towlower((wint_t)b[i]);

        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
        if (ca == L'\0') {
            return 0;
        }
        i++;
    }
}

static bool ui_contains_i(const wchar_t *hay, const wchar_t *needle)
{
    if (hay == NULL || needle == NULL || needle[0] == L'\0') {
        return false;
    }
    return wcsstr(hay, needle) != NULL;
}

static void ui_lower_copy(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t i = 0;

    if (dst == NULL || cap == 0) {
        return;
    }
    if (src != NULL) {
        while (i + 1 < cap && src[i] != L'\0') {
            dst[i] = (wchar_t)towlower((wint_t)src[i]);
            i++;
        }
    }
    dst[i] = L'\0';
}

static bool ui_matches_search(const wchar_t *text)
{
    wchar_t hay[2048];
    wchar_t needle[160];

    if (g.search_text[0] == L'\0') {
        return true;
    }
    ui_lower_copy(hay, sizeof(hay) / sizeof(hay[0]), text);
    ui_lower_copy(needle, sizeof(needle) / sizeof(needle[0]), g.search_text);
    return ui_contains_i(hay, needle);
}

static bool ui_alert_matches(const ui_row_t *row)
{
    wchar_t category[64];
    wchar_t reason[CC_MAX_REASON * 2];
    wchar_t pid_text[32];

    if (row == NULL) {
        return false;
    }
    if (g.filter_index > 0) {
        cc_risk_t wanted = CC_RISK_NONE;
        if (g.filter_index == 1) {
            wanted = CC_RISK_CRITICAL;
        } else if (g.filter_index == 2) {
            wanted = CC_RISK_HIGH;
        } else if (g.filter_index == 3) {
            wanted = CC_RISK_MEDIUM;
        } else if (g.filter_index == 4) {
            wanted = CC_RISK_LOW;
        }
        if (row->alert.risk != wanted) {
            return false;
        }
    }
    if (g.search_text[0] == L'\0') {
        return true;
    }
    ui_utf8_to_wide(row->alert.category, category,
                    sizeof(category) / sizeof(category[0]));
    ui_utf8_to_wide(row->alert.reason, reason,
                    sizeof(reason) / sizeof(reason[0]));
    swprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu",
             (unsigned long)row->alert.pid);
    return ui_matches_search(row->alert.target) ||
           ui_matches_search(category) || ui_matches_search(reason) ||
           ui_matches_search(row->alert.indicator) ||
           ui_matches_search(pid_text);
}

static bool ui_pid_has_alert(uint32_t pid)
{
    int i;

    if (pid == 0) {
        return false;
    }
    for (i = 0; i < g.row_count; i++) {
        if (g.rows[i].alert.pid == pid) {
            return true;
        }
    }
    return false;
}

static bool ui_process_matches(const cc_process_view_t *view)
{
    wchar_t pid_text[32];
    wchar_t parent_text[32];
    wchar_t session_text[32];
    bool alerted;

    if (view == NULL) {
        return false;
    }
    if (g.filter_index == 1 || g.filter_index == 2) {
        alerted = ui_pid_has_alert(view->info.pid);
        if ((g.filter_index == 1 && !alerted) ||
            (g.filter_index == 2 && alerted)) {
            return false;
        }
    }
    if (g.search_text[0] == L'\0') {
        return true;
    }
    swprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu",
             (unsigned long)view->info.pid);
    swprintf(parent_text, sizeof(parent_text) / sizeof(parent_text[0]), L"%lu",
             (unsigned long)view->info.parent_pid);
    swprintf(session_text, sizeof(session_text) / sizeof(session_text[0]),
             L"%lu", (unsigned long)view->info.session_id);
    return ui_matches_search(view->info.name) ||
           ui_matches_search(view->info.path) ||
           ui_matches_search(view->info.user) ||
           ui_matches_search(view->info.command_line) ||
           ui_matches_search(pid_text) || ui_matches_search(parent_text) ||
           ui_matches_search(session_text);
}

static int ui_compare_score(const void *a, const void *b)
{
    const ui_row_t *ra = (const ui_row_t *)a;
    const ui_row_t *rb = (const ui_row_t *)b;

    if (ra->score != rb->score) {
        return ra->score > rb->score ? -1 : 1;
    }
    if (ra->alert.pid == rb->alert.pid) {
        return 0;
    }
    return ra->alert.pid > rb->alert.pid ? 1 : -1;
}

static int ui_row_compare_column(const ui_row_t *a, const ui_row_t *b, int col)
{
    wchar_t ca[64];
    wchar_t cb[64];

    switch (col) {
    case 0:
        return a->alert.pid < b->alert.pid ? -1
                                           : (a->alert.pid > b->alert.pid ? 1 : 0);
    case 1:
        return ui_string_cmp(a->alert.target, b->alert.target);
    case 2:
        return a->cpu < b->cpu ? -1 : (a->cpu > b->cpu ? 1 : 0);
    case 3:
        return a->ram_mb < b->ram_mb ? -1 : (a->ram_mb > b->ram_mb ? 1 : 0);
    case 4:
        return (int)a->alert.risk - (int)b->alert.risk;
    case 5:
        ui_utf8_to_wide(a->alert.category, ca, sizeof(ca) / sizeof(ca[0]));
        ui_utf8_to_wide(b->alert.category, cb, sizeof(cb) / sizeof(cb[0]));
        return ui_string_cmp(ca, cb);
    case 6:
        ui_utf8_to_wide(a->alert.reason, ca, sizeof(ca) / sizeof(ca[0]));
        ui_utf8_to_wide(b->alert.reason, cb, sizeof(cb) / sizeof(cb[0]));
        return ui_string_cmp(ca, cb);
    default:
        return 0;
    }
}

static int ui_process_compare_column(const cc_process_view_t *a,
                                     const cc_process_view_t *b, int col)
{
    switch (col) {
    case 0:
        return a->info.pid < b->info.pid ? -1
                                         : (a->info.pid > b->info.pid ? 1 : 0);
    case 1:
        return ui_string_cmp(a->info.name, b->info.name);
    case 2:
        return ui_string_cmp(a->info.user, b->info.user);
    case 3:
        return a->info.session_id < b->info.session_id
                   ? -1
                   : (a->info.session_id > b->info.session_id ? 1 : 0);
    case 4:
        return a->info.parent_pid < b->info.parent_pid
                   ? -1
                   : (a->info.parent_pid > b->info.parent_pid ? 1 : 0);
    case 5:
        return a->metrics.cpu_percent < b->metrics.cpu_percent
                   ? -1
                   : (a->metrics.cpu_percent > b->metrics.cpu_percent ? 1 : 0);
    case 6:
        return a->metrics.working_set < b->metrics.working_set
                   ? -1
                   : (a->metrics.working_set > b->metrics.working_set ? 1 : 0);
    case 7:
        return (int)a->info.integrity - (int)b->info.integrity;
    case 8:
        return ui_string_cmp(a->info.path, b->info.path);
    default:
        return 0;
    }
}

static int ui_row_sort(const void *a, const void *b)
{
    int rc = ui_row_compare_column((const ui_row_t *)a, (const ui_row_t *)b,
                                   g.sort_column);
    return g.sort_desc ? -rc : rc;
}

static int ui_process_sort(const void *a, const void *b)
{
    int rc = ui_process_compare_column((const cc_process_view_t *)a,
                                       (const cc_process_view_t *)b,
                                       g.sort_column);
    return g.sort_desc ? -rc : rc;
}

static void ui_set_subitem(HWND list, int row, int column, const wchar_t *text)
{
    LVITEMW item;

    memset(&item, 0, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.iSubItem = column;
    item.pszText = (LPWSTR)text;
    (void)SendMessageW(list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&item);
}

static void ui_fill_list(void)
{
    static const wchar_t *const risk_labels[] = {
        L"Ninguno", L"Bajo", L"Medio", L"Alto", L"Crítico"
    };
    wchar_t pid_text[32];
    wchar_t cpu_text[32];
    wchar_t ram_text[32];
    wchar_t category[64];
    wchar_t reason[CC_MAX_REASON * 2];
    LVITEMW item;
    int i;
    int row = 0;
    int risk_index;

    (void)SendMessageW(g.list, WM_SETREDRAW, FALSE, 0);
    (void)SendMessageW(g.list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < g.row_count; i++) {
        const ui_row_t *source = &g.rows[i];

        if (!ui_alert_matches(source)) {
            continue;
        }
        swprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu",
                 (unsigned long)source->alert.pid);
        swprintf(cpu_text, sizeof(cpu_text) / sizeof(cpu_text[0]), L"%.1f",
                 source->cpu);
        swprintf(ram_text, sizeof(ram_text) / sizeof(ram_text[0]), L"%.1f",
                 source->ram_mb);
        ui_utf8_to_wide(source->alert.category, category,
                        sizeof(category) / sizeof(category[0]));
        ui_utf8_to_wide(source->alert.reason, reason,
                        sizeof(reason) / sizeof(reason[0]));
        risk_index = (int)source->alert.risk;
        if (risk_index < 0 || risk_index > 4) {
            risk_index = 0;
        }

        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = pid_text;
        item.lParam = (LPARAM)i;
        if (SendMessageW(g.list, LVM_INSERTITEMW, 0, (LPARAM)&item) == -1) {
            continue;
        }
        ui_set_subitem(g.list, row, 1, source->alert.target);
        ui_set_subitem(g.list, row, 2, cpu_text);
        ui_set_subitem(g.list, row, 3, ram_text);
        ui_set_subitem(g.list, row, 4, risk_labels[risk_index]);
        ui_set_subitem(g.list, row, 5, category);
        ui_set_subitem(g.list, row, CC_COL_REASON, reason);
        row++;
    }
    (void)SendMessageW(g.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.list, NULL, FALSE);
}

static void ui_fill_proc_list(void)
{
    wchar_t pid_text[32];
    wchar_t parent_text[32];
    wchar_t session_text[32];
    wchar_t cpu_text[32];
    wchar_t ram_text[32];
    LVITEMW item;
    int i;
    int row = 0;

    (void)SendMessageW(g.proc_list, WM_SETREDRAW, FALSE, 0);
    (void)SendMessageW(g.proc_list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < g.process_count; i++) {
        const cc_process_view_t *source = &g.processes[i];

        if (!ui_process_matches(source)) {
            continue;
        }
        swprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu",
                 (unsigned long)source->info.pid);
        swprintf(parent_text, sizeof(parent_text) / sizeof(parent_text[0]),
                 L"%lu", (unsigned long)source->info.parent_pid);
        swprintf(session_text, sizeof(session_text) / sizeof(session_text[0]),
                 L"%lu", (unsigned long)source->info.session_id);
        swprintf(cpu_text, sizeof(cpu_text) / sizeof(cpu_text[0]), L"%.1f",
                 source->metrics.cpu_percent);
        swprintf(ram_text, sizeof(ram_text) / sizeof(ram_text[0]), L"%.1f",
                 (double)source->metrics.working_set / 1048576.0);

        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = pid_text;
        item.lParam = (LPARAM)i;
        if (SendMessageW(g.proc_list, LVM_INSERTITEMW, 0, (LPARAM)&item) == -1) {
            continue;
        }
        ui_set_subitem(g.proc_list, row, 1, source->info.name);
        ui_set_subitem(g.proc_list, row, 2, source->info.user);
        ui_set_subitem(g.proc_list, row, 3, session_text);
        ui_set_subitem(g.proc_list, row, 4, parent_text);
        ui_set_subitem(g.proc_list, row, 5, cpu_text);
        ui_set_subitem(g.proc_list, row, 6, ram_text);
        ui_set_subitem(g.proc_list, row, 7,
                       cc_integrity_name(source->info.integrity));
        ui_set_subitem(g.proc_list, row, 8, source->info.path);
        row++;
    }
    (void)SendMessageW(g.proc_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.proc_list, NULL, FALSE);
}

static void ui_fill_all(void)
{
    ui_fill_list();
    ui_fill_proc_list();
}

static void ui_update_status(void)
{
    wchar_t text[512];
    int critical = 0;
    int high = 0;
    int skipped;
    int i;

    for (i = 0; i < g.row_count; i++) {
        if (g.rows[i].alert.risk == CC_RISK_CRITICAL) {
            critical++;
        } else if (g.rows[i].alert.risk == CC_RISK_HIGH) {
            high++;
        }
    }
    skipped = g.process_total - g.analyzed;
    if (skipped < 0) {
        skipped = 0;
    }
    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"Alertas: %d | Críticas: %d | Altas: %d | Procesos: %d/%d | "
             L"Analizados: %d | Omitidos: %d | Admin: %s | Última: %s",
             g.row_count, critical, high, g.process_count, g.process_total,
             g.analyzed, skipped, g.elevated ? L"SÍ" : L"NO", g.last_scan);
    SetWindowTextW(g.status, text);
}

static ui_scan_result_t *ui_scan_collect(bool vt_live)
{
    cc_alert_t *buffer = NULL;
    ui_row_t *rows = NULL;
    ui_scan_result_t *result;
    cc_detect_ctx_t ctx;
    cc_proc_metrics_t pm;
    int count = 0;
    int added;
    int i;
    int total = 0;
    int analyzed = 0;
    ULONGLONG deadline = GetTickCount64() + 60000;

    if (g.cfg.scan_timeout_ms != 0) {
        deadline = GetTickCount64() + (ULONGLONG)g.cfg.scan_timeout_ms;
    }
    result = (ui_scan_result_t *)calloc(1, sizeof(*result));
    if (result == NULL) {
        return NULL;
    }
    result->count = -1;

    buffer = (cc_alert_t *)calloc(CC_ALERT_CAP, sizeof(*buffer));
    if (buffer == NULL) {
        return result;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg = (const struct cc_config_s *)&g.cfg;
    ctx.ioc = g.ioc;
    ctx.pubs = g.pubs;
    ctx.metrics = g.metrics;
    ctx.trust_cache = g.cache;
    ctx.vt_live = vt_live;
    ctx.vt_live_budget = 0;
    if (vt_live && g.cfg.vt_api_key[0] != L'\0') {
        uint32_t cap = g.cfg.network_vt_max_lookups;
        if (cap > 64) {
            cap = 64;
        }
        ctx.vt_live_budget = (int)cap;
    }

    added = cc_detect_processes(&ctx, buffer, CC_ALERT_CAP, deadline);
    count += added;
    if (count > CC_ALERT_CAP) {
        count = CC_ALERT_CAP;
    }

    added = cc_registry_scan(g.ioc, buffer + count, CC_ALERT_CAP - count, deadline);
    count += added;
    if (count > CC_ALERT_CAP) {
        count = CC_ALERT_CAP;
    }

    added = cc_eventlog_scan(g.eventlog_minutes, buffer + count,
                             CC_ALERT_CAP - count, NULL, deadline);
    count += added;
    if (count > CC_ALERT_CAP) {
        count = CC_ALERT_CAP;
    }

    added = cc_network_scan((const struct cc_config_s *)&g.cfg, g.ioc,
                            vt_live, buffer + count, CC_ALERT_CAP - count,
                            deadline);
    count += added;
    if (count > CC_ALERT_CAP) {
        count = CC_ALERT_CAP;
    }

    rows = (ui_row_t *)calloc((size_t)(count > 0 ? count : 1), sizeof(*rows));
    if (rows == NULL) {
        free(buffer);
        return result;
    }
    for (i = 0; i < count; i++) {
        rows[i].alert = buffer[i];
        rows[i].score = cc_alert_score(buffer[i].risk, buffer[i].category);
        if (buffer[i].pid != 0 &&
            cc_metrics_sample(g.view_metrics, buffer[i].pid, &pm)) {
            rows[i].cpu = pm.cpu_percent;
            rows[i].ram_mb = (double)pm.working_set / 1048576.0;
        }
    }
    qsort(rows, (size_t)count, sizeof(*rows), ui_compare_score);

    result->processes = (cc_process_view_t *)calloc(CC_MAX_PROCS,
                                                    sizeof(*result->processes));
    if (result->processes == NULL) {
        free(rows);
        free(buffer);
        return result;
    }
    result->process_count = cc_proc_inventory_collect(
        result->processes, CC_MAX_PROCS, &total, &analyzed,
        g.inventory_metrics, deadline);
    result->process_total = total;
    result->analyzed = analyzed;
    result->rows = rows;
    result->count = count;
    result->ok = true;
    free(buffer);
    return result;
}

static void ui_free_result(ui_scan_result_t *result)
{
    if (result == NULL) {
        return;
    }
    free(result->processes);
    free(result->rows);
    free(result);
}

static DWORD WINAPI ui_scan_thread_proc(LPVOID param)
{
    HANDLE waits[2];

    (void)param;
    waits[0] = g.scan_event;
    waits[1] = g.stop_event;
    for (;;) {
        DWORD rc = WaitForMultipleObjects(2, waits, FALSE, INFINITE);

        if (rc == WAIT_OBJECT_0 + 1) {
            break;
        }
        if (rc != WAIT_OBJECT_0) {
            continue;
        }
        (void)InterlockedExchange(&g.scan_pending, 0);
        if (InterlockedCompareExchange(&g.scan_busy, 1, 0) != 0) {
            continue;
        }
        {
            bool vt_live = InterlockedExchange(&g.vt_live_request, 0) != 0;
            ui_scan_result_t *result = ui_scan_collect(vt_live);
            bool posted = false;

            if (result != NULL) {
                if (InterlockedCompareExchange(&g.shutdown, 0, 0) == 0 &&
                    g.hwnd != NULL) {
                    posted = PostMessageW(g.hwnd, WM_APP_SCAN_DONE, 0,
                                          (LPARAM)result) ? true : false;
                }
                if (!posted) {
                    ui_free_result(result);
                }
            }
            InterlockedExchange(&g.scan_busy, 0);
        }
    }
    return 0;
}

static bool ui_start_worker(HWND hwnd)
{
    g.hwnd = hwnd;
    g.scan_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    g.stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g.scan_event == NULL || g.stop_event == NULL) {
        return false;
    }
    g.scan_thread = CreateThread(NULL, 0, ui_scan_thread_proc, NULL, 0, NULL);
    return g.scan_thread != NULL;
}

static void ui_stop_worker(HWND hwnd)
{
    MSG msg;

    InterlockedExchange(&g.shutdown, 1);
    if (g.stop_event != NULL) {
        (void)SetEvent(g.stop_event);
    }
    if (g.scan_thread != NULL) {
        (void)WaitForSingleObject(g.scan_thread, INFINITE);
        (void)CloseHandle(g.scan_thread);
        g.scan_thread = NULL;
    }
    while (PeekMessageW(&msg, hwnd, WM_APP_SCAN_DONE, WM_APP_SCAN_DONE,
                        PM_REMOVE)) {
        ui_free_result((ui_scan_result_t *)msg.lParam);
    }
    if (g.scan_event != NULL) {
        (void)CloseHandle(g.scan_event);
        g.scan_event = NULL;
    }
    if (g.stop_event != NULL) {
        (void)CloseHandle(g.stop_event);
        g.stop_event = NULL;
    }
}

static void ui_set_scanning(bool scanning)
{
    HWND buttons[] = {
        g.btn_scan, g.btn_kill, g.btn_suspend, g.btn_resume,
        g.btn_block_ip, g.btn_unblock_ip
    };
    size_t i;

    for (i = 0; i < sizeof(buttons) / sizeof(buttons[0]); i++) {
        if (buttons[i] != NULL) {
            (void)EnableWindow(buttons[i], !scanning);
        }
    }
    if (g.progress != NULL) {
        (void)SendMessageW(g.progress, PBM_SETPOS, scanning ? 0 : 100, 0);
        (void)SendMessageW(g.progress, PBM_SETMARQUEE, (WPARAM)(scanning ? TRUE : FALSE), 0);
    }
    if (scanning && g.status != NULL) {
        SetWindowTextW(g.status, L"Analizando sistema…");
    }
}

static void ui_request_scan(bool vt_live)
{
    if (g.scan_event == NULL ||
        InterlockedCompareExchange(&g.shutdown, 0, 0) != 0) {
        return;
    }
    if (vt_live) {
        InterlockedExchange(&g.vt_live_request, 1);
    }
    (void)InterlockedExchange(&g.scan_pending, 1);
    ui_set_scanning(true);
    (void)SetEvent(g.scan_event);
}

static void ui_stale_process(void)
{
    MessageBoxW(NULL, L"El proceso ya no está disponible o cambió de "
                      L"estado. Se actualizará el análisis.",
                L"Terminar", MB_OK | MB_ICONINFORMATION);
    ui_request_scan(false);
}

static void ui_reset_filter(void)
{
    if (g.filter == NULL) {
        return;
    }
    (void)SendMessageW(g.filter, CB_RESETCONTENT, 0, 0);
    if (g.view == CC_VIEW_PROCESSES) {
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Todos los procesos");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Solo con alerta");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Sin alerta");
    } else {
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Todas las alertas");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Críticas");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Altas");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Medias");
        (void)SendMessageW(g.filter, CB_ADDSTRING, 0, (LPARAM)L"Bajas");
    }
    g.filter_index = 0;
    (void)SendMessageW(g.filter, CB_SETCURSEL, 0, 0);
}

static void ui_set_view(int view)
{
    if (view != CC_VIEW_ALERTS && view != CC_VIEW_PROCESSES) {
        return;
    }
    g.view = view;
    if (g.tabs != NULL) {
        (void)SendMessageW(g.tabs, TCM_SETCURSEL, (WPARAM)view, 0);
    }
    if (g.list != NULL) {
        ShowWindow(g.list, view == CC_VIEW_ALERTS ? SW_SHOW : SW_HIDE);
    }
    if (g.proc_list != NULL) {
        ShowWindow(g.proc_list, view == CC_VIEW_PROCESSES ? SW_SHOW : SW_HIDE);
    }
    ui_reset_filter();
    ui_fill_all();
}

static void ui_apply_scan_result(ui_scan_result_t *result)
{
    SYSTEMTIME now;

    if (result == NULL) {
        return;
    }
    ui_set_scanning(false);
    if (!result->ok || result->count < 0) {
        MessageBoxW(NULL, L"No se pudo completar el análisis.",
                    L"cleaner-secure", MB_OK | MB_ICONERROR);
        ui_free_result(result);
        return;
    }
    if (InterlockedCompareExchange(&g.shutdown, 0, 0) != 0) {
        ui_free_result(result);
        return;
    }

    GetLocalTime(&now);
    swprintf(g.last_scan, sizeof(g.last_scan) / sizeof(g.last_scan[0]),
             L"%02u:%02u:%02u", (unsigned)now.wHour, (unsigned)now.wMinute,
             (unsigned)now.wSecond);

    free(g.rows);
    g.rows = result->rows;
    g.row_count = result->count;
    free(g.processes);
    g.processes = result->processes;
    g.process_count = result->process_count;
    g.process_total = result->process_total;
    g.analyzed = result->analyzed;
    result->rows = NULL;
    result->processes = NULL;

    if (g.view == CC_VIEW_ALERTS) {
        g.sort_column = 4;
    } else {
        g.sort_column = 6;
    }
    g.sort_desc = true;
    if (g.view == CC_VIEW_ALERTS) {
        qsort(g.rows, (size_t)g.row_count, sizeof(*g.rows), ui_compare_score);
    } else {
        qsort(g.processes, (size_t)g.process_count, sizeof(*g.processes),
              ui_process_sort);
    }
    ui_fill_all();
    ui_update_status();
    ui_free_result(result);
}

static void ui_show_detail(int index)
{
    wchar_t category[64];
    wchar_t reason[CC_MAX_REASON * 2];
    wchar_t indicator[128];
    wchar_t text[CC_MAX_REASON * 2 + 320];
    const ui_row_t *row;

    if (index < 0 || index >= g.row_count) {
        return;
    }
    row = &g.rows[index];
    ui_utf8_to_wide(row->alert.category, category,
                    sizeof(category) / sizeof(category[0]));
    ui_utf8_to_wide(row->alert.reason, reason,
                    sizeof(reason) / sizeof(reason[0]));
    ui_wstr_copy(indicator, sizeof(indicator) / sizeof(indicator[0]),
                 row->alert.indicator);
    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"PID: %lu\nProceso: %s\nRiesgo: %s\nCategoría: %s\n"
             L"Puntuación: %d\nCPU: %.1f%%\nRAM: %.1f MB\nIndicador: %s\n"
             L"Motivo: %s\nDestino: %s",
             (unsigned long)row->alert.pid, row->alert.target,
             ui_risk_name(row->alert.risk), category, row->score,
             row->cpu, row->ram_mb, indicator, reason, row->alert.target);
    MessageBoxW(NULL, text, L"Detalle de alerta", MB_OK | MB_ICONINFORMATION);
}

static void ui_show_process_detail(int index)
{
    const cc_process_view_t *view;
    wchar_t text[2048];

    if (index < 0 || index >= g.process_count) {
        return;
    }
    view = &g.processes[index];
    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"PID: %lu\nPadre: %lu\nProceso: %s\nUsuario: %s\nSesión: %lu\n"
             L"Integridad: %s\nElevado: %s\nArquitectura: %s\n"
             L"CPU: %.1f%%\nRAM: %.1f MB\nRuta: %s\nLínea de comandos: %s",
             (unsigned long)view->info.pid,
             (unsigned long)view->info.parent_pid, view->info.name,
             view->info.user[0] != L'\0' ? view->info.user : L"desconocido",
             (unsigned long)view->info.session_id,
             cc_integrity_name(view->info.integrity),
             view->info.is_elevated ? L"SÍ" : L"NO",
             !view->info.bitness_known
                 ? L"desconocida"
                 : (view->info.is_wow64 ? L"32 bits (WOW64)" : L"64 bits"),
             view->metrics.cpu_percent,
             (double)view->metrics.working_set / 1048576.0,
             view->info.path[0] != L'\0' ? view->info.path : L"no disponible",
             view->info.command_line[0] != L'\0' ? view->info.command_line
                                                 : L"no disponible");
    MessageBoxW(NULL, text, L"Detalle de proceso", MB_OK | MB_ICONINFORMATION);
}

static void ui_run_as_admin(void)
{
    wchar_t path[CC_MAX_PATH_LEN];
    DWORD n;
    INT_PTR result;

    n = GetModuleFileNameW(NULL, path, sizeof(path) / sizeof(path[0]));
    if (n == 0 || n >= sizeof(path) / sizeof(path[0])) {
        MessageBoxW(NULL, L"No se pudo obtener la ruta del ejecutable.",
                    L"Elevación", MB_OK | MB_ICONERROR);
        return;
    }
    result = (INT_PTR)ShellExecuteW(NULL, L"runas", path, NULL, NULL,
                                    SW_SHOWNORMAL);
    if (result <= 32) {
        wchar_t err_text[256];
        ui_error_text(GetLastError(), err_text,
                      sizeof(err_text) / sizeof(err_text[0]));
        MessageBoxW(NULL, err_text, L"Elevación", MB_OK | MB_ICONERROR);
    }
}

static bool ui_selected_alert(uint32_t *pid, wchar_t target[CC_MAX_NAME],
                              wchar_t indicator[64])
{
    HWND list;
    int selected;
    LVITEMW item;
    int index;

    if (g.view == CC_VIEW_PROCESSES) {
        selected = (int)SendMessageW(g.proc_list, LVM_GETNEXTITEM, (WPARAM)-1,
                                     LVNI_SELECTED);
        if (selected < 0) {
            MessageBoxW(NULL, L"Seleccione un proceso de la lista.",
                        L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
            return false;
        }
        memset(&item, 0, sizeof(item));
        item.mask = LVIF_PARAM;
        item.iItem = selected;
        if (!SendMessageW(g.proc_list, LVM_GETITEMW, 0, (LPARAM)&item)) {
            return false;
        }
        index = (int)item.lParam;
        if (index < 0 || index >= g.process_count) {
            return false;
        }
        *pid = g.processes[index].info.pid;
        for (index = 0; index < g.row_count; index++) {
            if (g.rows[index].alert.pid == *pid) {
                ui_wstr_copy(target, CC_MAX_NAME, g.rows[index].alert.target);
                ui_wstr_copy(indicator, 64, g.rows[index].alert.indicator);
                return true;
            }
        }
        MessageBoxW(NULL, L"El proceso seleccionado no tiene una alerta "
                          L"asociada.", L"cleaner-secure",
                    MB_OK | MB_ICONINFORMATION);
        return false;
    }

    list = g.list;
    selected = (int)SendMessageW(list, LVM_GETNEXTITEM, (WPARAM)-1,
                                 LVNI_SELECTED);
    if (selected < 0) {
        MessageBoxW(NULL, L"Seleccione una alerta de la lista.",
                    L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
        return false;
    }
    memset(&item, 0, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = selected;
    if (!SendMessageW(list, LVM_GETITEMW, 0, (LPARAM)&item)) {
        return false;
    }
    index = (int)item.lParam;
    if (index < 0 || index >= g.row_count) {
        return false;
    }
    *pid = g.rows[index].alert.pid;
    ui_wstr_copy(target, CC_MAX_NAME, g.rows[index].alert.target);
    ui_wstr_copy(indicator, 64, g.rows[index].alert.indicator);
    return true;
}

static bool ui_confirm_action(const wchar_t *action, uint32_t pid,
                              const wchar_t *target, const wchar_t *scope)
{
    wchar_t text[1024];
    int rc;

    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"%s\n\nPID: %lu\nObjetivo: %s\nDetalle: %s\n\n"
             L"Esta acción quedará registrada en actions.log.",
             action, (unsigned long)pid, target, scope);
    rc = MessageBoxW(NULL, text, L"Confirmar acción",
                     MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2);
    return rc == IDOK;
}

static void ui_action(int command)
{
    uint32_t pid = 0;
    wchar_t target[CC_MAX_NAME];
    wchar_t indicator[64];
    wchar_t action[32];
    wchar_t scope[CC_MAX_PATH_LEN];
    DWORD error_code = 0;
    bool ok = false;

    if (!ui_selected_alert(&pid, target, indicator)) {
        return;
    }
    if (command == ID_BTN_BLOCK_IP || command == ID_BTN_UNBLOCK_IP) {
        if (indicator[0] == L'\0') {
            MessageBoxW(NULL, L"La alerta seleccionada no tiene una IP.",
                        L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
            return;
        }
        if (command == ID_BTN_BLOCK_IP) {
            wcscpy(action, L"Bloquear IP");
            wcscpy(scope, indicator);
        } else {
            wcscpy(action, L"Desbloquear IP");
            wcscpy(scope, indicator);
        }
        if (!ui_confirm_action(action, pid, target, scope)) {
            return;
        }
        if (command == ID_BTN_BLOCK_IP) {
            ok = cc_block_ip(indicator, &error_code);
        } else {
            ok = cc_unblock_ip(indicator, &error_code);
        }
    } else {
        if (pid == 0) {
            MessageBoxW(NULL, L"La alerta seleccionada no tiene PID.",
                        L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
            return;
        }
        switch (command) {
        case ID_BTN_KILL:
            wcscpy(action, L"Terminar");
            break;
        case ID_BTN_SUSPEND:
            wcscpy(action, L"Suspender");
            break;
        case ID_BTN_RESUME:
            wcscpy(action, L"Reanudar");
            break;
        default:
            return;
        }
        ui_wstr_copy(scope, CC_MAX_PATH_LEN, indicator);
        if (scope[0] == L'\0') {
            ui_wstr_copy(scope, CC_MAX_PATH_LEN, target);
        }
        if (!ui_confirm_action(action, pid, target, scope)) {
            return;
        }
        if (command == ID_BTN_KILL) {
            if (!cc_process_matches_name(pid, target, &error_code)) {
                ui_stale_process();
                return;
            }
            ok = cc_kill_process(pid, &error_code);
        } else if (command == ID_BTN_SUSPEND) {
            ok = cc_suspend_process(pid, &error_code);
        } else {
            ok = cc_resume_process(pid, &error_code);
        }
    }
    if (!ok && command == ID_BTN_KILL &&
        (error_code == ERROR_GEN_FAILURE ||
         error_code == ERROR_INVALID_PARAMETER ||
         error_code == ERROR_NOT_FOUND)) {
        ui_stale_process();
        return;
    }
    if (!ok) {
        wchar_t err_text[256];
        ui_error_text(error_code, err_text,
                      sizeof(err_text) / sizeof(err_text[0]));
        MessageBoxW(NULL, err_text, action, MB_OK | MB_ICONERROR);
        return;
    }
    if (command == ID_BTN_KILL) {
        ui_request_scan(false);
    }
}

static void ui_layout(int width, int height)
{
    static const int alert_widths[] = { 80, 220, 80, 100, 90, 120 };
    static const int proc_widths[] = { 80, 200, 180, 80, 80, 80, 100, 110, 260 };
    const int gap = 6;
    const int margin = 8;
    const int filter_row_y = 38;
    const int list_y = 68;
    const int bottom_reserved = 122;
    LVCOLUMNW col;
    HWND buttons[8];
    int count = 0;
    int list_w;
    int list_h;
    int button_w;
    int last_w;
    int widths_count;
    const int *widths;
    int i;

    if (width < 640) {
        width = 640;
    }
    if (height < 420) {
        height = 420;
    }
    list_w = width - margin * 2;
    list_h = height - list_y - bottom_reserved;
    if (list_h < 100) {
        list_h = 100;
    }

    MoveWindow(g.tabs, margin, margin, list_w, 26, TRUE);
    MoveWindow(g.search, margin, filter_row_y, 260, 22, TRUE);
    MoveWindow(g.filter, margin + 268, filter_row_y, 200, 22, TRUE);
    MoveWindow(g.list, margin, list_y, list_w, list_h, TRUE);
    MoveWindow(g.proc_list, margin, list_y, list_w, list_h, TRUE);
    MoveWindow(g.progress, margin, list_y + list_h + 6, list_w, 14, TRUE);
    MoveWindow(g.chk_auto, margin, list_y + list_h + 24, 150, 22, TRUE);

    buttons[count++] = g.btn_scan;
    buttons[count++] = g.btn_kill;
    buttons[count++] = g.btn_suspend;
    buttons[count++] = g.btn_resume;
    buttons[count++] = g.btn_block_ip;
    buttons[count++] = g.btn_unblock_ip;
    buttons[count++] = g.btn_elev;
    if (g.btn_runas != NULL) {
        buttons[count++] = g.btn_runas;
    }
    button_w = (list_w - gap * (count - 1)) / count;
    if (button_w < 60) {
        button_w = 60;
    }
    for (i = 0; i < count; i++) {
        MoveWindow(buttons[i], margin + i * (button_w + gap), height - 82,
                   button_w, 28, TRUE);
    }
    MoveWindow(g.status, margin, height - 28, list_w, 24, TRUE);

    if (g.view == CC_VIEW_PROCESSES) {
        widths = proc_widths;
        widths_count = (int)(sizeof(proc_widths) / sizeof(proc_widths[0]));
    } else {
        widths = alert_widths;
        widths_count = (int)(sizeof(alert_widths) / sizeof(alert_widths[0]));
    }
    last_w = list_w - 24;
    for (i = 0; i < widths_count; i++) {
        last_w -= widths[i];
    }
    if (last_w < 140) {
        last_w = 140;
    }
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_WIDTH;
    col.cx = last_w;
    (void)SendMessageW(g.view == CC_VIEW_PROCESSES ? g.proc_list : g.list,
                       LVM_SETCOLUMNW, (WPARAM)(CC_PROC_COL_COUNT - 1),
                       (LPARAM)&col);
}

static HWND ui_create_button(HWND parent, int id, const wchar_t *text, int x,
                             int y, int w, int h)
{
    return CreateWindowExW(0, L"Button", text,
                           WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                           x, y, w, h, parent, (HMENU)(INT_PTR)id,
                           GetModuleHandleW(NULL), NULL);
}

static bool ui_create_columns(HWND list, const ui_column_def_t *columns,
                              size_t count)
{
    LVCOLUMNW col;
    size_t i;

    for (i = 0; i < count; i++) {
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.fmt = LVCFMT_LEFT;
        col.cx = columns[i].width;
        col.iSubItem = (int)i;
        col.pszText = (LPWSTR)columns[i].text;
        if (SendMessageW(list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col) < 0) {
            return false;
        }
    }
    return true;
}

static bool ui_create_controls(HWND hwnd)
{
    static const ui_column_def_t alert_columns[] = {
        { L"PID", 80 },
        { L"Proceso", 220 },
        { L"CPU%", 80 },
        { L"RAM(MB)", 100 },
        { L"Riesgo", 90 },
        { L"Categoría", 120 },
        { L"Motivo", 300 }
    };
    static const ui_column_def_t process_columns[] = {
        { L"PID", 80 },
        { L"Proceso", 200 },
        { L"Usuario", 180 },
        { L"Sesión", 80 },
        { L"Padre", 80 },
        { L"CPU%", 80 },
        { L"RAM(MB)", 100 },
        { L"Integridad", 110 },
        { L"Ruta", 260 }
    };
    TCITEMW tab;
    DWORD ex_style;
    int i;

    g.font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g.tabs = CreateWindowExW(0, WC_TABCONTROLW, L"",
                             WS_CHILD | WS_VISIBLE | TCS_TOP,
                             8, 8, 1084, 26, hwnd, (HMENU)(INT_PTR)ID_TABS,
                             GetModuleHandleW(NULL), NULL);
    if (g.tabs == NULL) {
        return false;
    }
    (void)SendMessageW(g.tabs, WM_SETFONT, (WPARAM)g.font, TRUE);
    for (i = 0; i < 2; i++) {
        memset(&tab, 0, sizeof(tab));
        tab.mask = TCIF_TEXT;
        tab.pszText = i == 0 ? (LPWSTR)L"Alertas" : (LPWSTR)L"Procesos";
        if (SendMessageW(g.tabs, TCM_INSERTITEMW, (WPARAM)i, (LPARAM)&tab) < 0) {
            return false;
        }
    }

    g.search = CreateWindowExW(WS_EX_CLIENTEDGE, L"Edit", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                               ES_AUTOHSCROLL,
                               8, 38, 260, 22, hwnd,
                               (HMENU)(INT_PTR)ID_SEARCH,
                               GetModuleHandleW(NULL), NULL);
    g.filter = CreateWindowExW(0, L"ComboBox", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                               CBS_DROPDOWNLIST | WS_VSCROLL,
                               276, 38, 200, 180, hwnd,
                               (HMENU)(INT_PTR)ID_FILTER,
                               GetModuleHandleW(NULL), NULL);
    if (g.search == NULL || g.filter == NULL) {
        return false;
    }
    (void)SendMessageW(g.search, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.filter, WM_SETFONT, (WPARAM)g.font, TRUE);

    g.list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | WS_BORDER |
                             LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                             8, 68, 1084, 490, hwnd, (HMENU)(INT_PTR)ID_LIST,
                             GetModuleHandleW(NULL), NULL);
    g.proc_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_BORDER |
                                  LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                  8, 68, 1084, 490, hwnd,
                                  (HMENU)(INT_PTR)ID_PROC_LIST,
                                  GetModuleHandleW(NULL), NULL);
    if (g.list == NULL || g.proc_list == NULL) {
        return false;
    }
    ex_style = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER;
    (void)SendMessageW(g.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)ex_style);
    (void)SendMessageW(g.proc_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)ex_style);
    (void)SendMessageW(g.list, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.proc_list, WM_SETFONT, (WPARAM)g.font, TRUE);

    if (!ui_create_columns(g.list, alert_columns,
                           sizeof(alert_columns) / sizeof(alert_columns[0])) ||
        !ui_create_columns(g.proc_list, process_columns,
                           sizeof(process_columns) / sizeof(process_columns[0]))) {
        return false;
    }

    g.progress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                                 WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
                                 8, 564, 1084, 14, hwnd,
                                 (HMENU)(INT_PTR)ID_PROGRESS,
                                 GetModuleHandleW(NULL), NULL);
    if (g.progress == NULL) {
        return false;
    }
    (void)SendMessageW(g.progress, PBM_SETMARQUEE, FALSE, 0);

    g.chk_auto = CreateWindowExW(0, L"Button", L"Auto-refresco",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                 BS_AUTOCHECKBOX,
                                 8, 586, 150, 22, hwnd,
                                 (HMENU)(INT_PTR)ID_CHK_AUTO,
                                 GetModuleHandleW(NULL), NULL);
    g.btn_scan = ui_create_button(hwnd, ID_BTN_SCAN, L"Analizar ahora", 8, 618,
                                  130, 28);
    g.btn_kill = ui_create_button(hwnd, ID_BTN_KILL, L"Terminar", 146, 618,
                                  120, 28);
    g.btn_suspend = ui_create_button(hwnd, ID_BTN_SUSPEND, L"Suspender", 274,
                                     618, 120, 28);
    g.btn_resume = ui_create_button(hwnd, ID_BTN_RESUME, L"Reanudar", 402, 618,
                                    120, 28);
    g.btn_block_ip = ui_create_button(hwnd, ID_BTN_BLOCK_IP, L"Bloquear IP",
                                      530, 618, 130, 28);
    g.btn_unblock_ip = ui_create_button(hwnd, ID_BTN_UNBLOCK_IP,
                                        L"Desbloquear IP", 668, 618, 140, 28);
    g.btn_elev = ui_create_button(hwnd, ID_BTN_ELEV, L"Elevación", 816, 618,
                                  120, 28);
    if (!g.elevated) {
        g.btn_runas = ui_create_button(hwnd, ID_BTN_RUNAS,
                                       L"Reiniciar como administrador",
                                       944, 618, 148, 28);
    }
    g.status = CreateWindowExW(0, L"Static", L"", WS_CHILD | WS_VISIBLE |
                               SS_LEFT | SS_SUNKEN,
                               8, 672, 1084, 24, hwnd,
                               (HMENU)(INT_PTR)ID_STATUS,
                               GetModuleHandleW(NULL), NULL);

    if (g.chk_auto == NULL || g.btn_scan == NULL || g.btn_kill == NULL ||
        g.btn_suspend == NULL || g.btn_resume == NULL ||
        g.btn_block_ip == NULL || g.btn_unblock_ip == NULL ||
        g.btn_elev == NULL || g.status == NULL ||
        (!g.elevated && g.btn_runas == NULL)) {
        return false;
    }
    (void)SendMessageW(g.chk_auto, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_scan, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_kill, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_suspend, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_resume, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_block_ip, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_unblock_ip, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_elev, WM_SETFONT, (WPARAM)g.font, TRUE);
    if (g.btn_runas != NULL) {
        (void)SendMessageW(g.btn_runas, WM_SETFONT, (WPARAM)g.font, TRUE);
    }
    (void)SendMessageW(g.status, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.chk_auto, BM_SETCHECK, BST_CHECKED, 0);
    wcscpy(g.last_scan, L"--:--:--");
    ui_set_view(CC_VIEW_ALERTS);
    return true;
}

static bool ui_init_state(void)
{
    wchar_t exe_dir[CC_MAX_PATH_LEN];
    wchar_t config_dir[CC_MAX_PATH_LEN];
    wchar_t file_path[CC_MAX_PATH_LEN];

    memset(&g, 0, sizeof(g));
    g.elevated = cc_is_elevated();
    if (!cc_exe_dir(exe_dir, sizeof(exe_dir) / sizeof(exe_dir[0]))) {
        wcscpy(exe_dir, L".");
    }
    if (!ui_join_path(config_dir, sizeof(config_dir) / sizeof(config_dir[0]),
                      exe_dir, L"config")) {
        config_dir[0] = L'\0';
    }
    if (!cc_config_load(&g.cfg, config_dir)) {
        if (!cc_config_load(&g.cfg, NULL)) {
            return false;
        }
    }
    ui_load_timing(g.cfg.config_dir);

    if (ui_join_path(file_path, sizeof(file_path) / sizeof(file_path[0]),
                     g.cfg.config_dir, L"iocs.json")) {
        g.ioc = cc_ioc_load(file_path);
    }
    if (ui_join_path(file_path, sizeof(file_path) / sizeof(file_path[0]),
                     g.cfg.config_dir, L"publishers.json")) {
        g.pubs = cc_publishers_load(file_path);
    }
    g.metrics = cc_metrics_create();
    g.view_metrics = cc_metrics_create();
    g.inventory_metrics = cc_metrics_create();
    g.cache = cc_trust_cache_create();
    if (g.metrics == NULL || g.view_metrics == NULL ||
        g.inventory_metrics == NULL || g.cache == NULL) {
        return false;
    }
    return true;
}

static void ui_free_state(void)
{
    free(g.rows);
    free(g.processes);
    g.rows = NULL;
    g.processes = NULL;
    g.row_count = 0;
    g.process_count = 0;
    cc_trust_cache_free(g.cache);
    cc_metrics_destroy(g.inventory_metrics);
    cc_metrics_destroy(g.view_metrics);
    cc_metrics_destroy(g.metrics);
    cc_publishers_free(g.pubs);
    cc_ioc_free(g.ioc);
    memset(&g, 0, sizeof(g));
}

static LRESULT CALLBACK ui_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam,
                                    LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        if (!ui_init_state() || !ui_create_controls(hwnd)) {
            return -1;
        }
        if (SetTimer(hwnd, ID_TIMER, g.timer_ms, NULL) == 0) {
            SetTimer(hwnd, ID_TIMER, 2000, NULL);
        }
        if (!ui_start_worker(hwnd)) {
            return -1;
        }
        ui_request_scan(false);
        return 0;

    case WM_APP_SCAN_DONE:
        ui_apply_scan_result((ui_scan_result_t *)lParam);
        return 0;

    case WM_TIMER:
        if (wParam == ID_TIMER &&
            SendMessageW(g.chk_auto, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            ui_request_scan(false);
        }
        return 0;

    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case ID_BTN_SCAN:
                ui_request_scan(true);
                break;
            case ID_BTN_KILL:
            case ID_BTN_SUSPEND:
            case ID_BTN_RESUME:
            case ID_BTN_BLOCK_IP:
            case ID_BTN_UNBLOCK_IP:
                ui_action(LOWORD(wParam));
                break;
            case ID_BTN_ELEV:
                if (g.elevated) {
                    MessageBoxW(NULL, L"El proceso se ejecuta con privilegios "
                                 L"de administrador.", L"Elevación",
                                 MB_OK | MB_ICONINFORMATION);
                } else {
                    ui_run_as_admin();
                }
                break;
            case ID_BTN_RUNAS:
                ui_run_as_admin();
                break;
            default:
                break;
            }
        } else if (HIWORD(wParam) == EN_CHANGE &&
                   LOWORD(wParam) == ID_SEARCH) {
            (void)GetWindowTextW(g.search, g.search_text,
                                 sizeof(g.search_text) / sizeof(g.search_text[0]));
            ui_fill_all();
        } else if (HIWORD(wParam) == CBN_SELCHANGE &&
                   LOWORD(wParam) == ID_FILTER) {
            g.filter_index = (int)SendMessageW(g.filter, CB_GETCURSEL, 0, 0);
            if (g.filter_index < 0) {
                g.filter_index = 0;
            }
            ui_fill_all();
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *header = (NMHDR *)lParam;

        if (header == NULL) {
            return 0;
        }
        if (header->idFrom == ID_TABS && header->code == TCN_SELCHANGE) {
            ui_set_view((int)SendMessageW(g.tabs, TCM_GETCURSEL, 0, 0));
            return 0;
        }
        if (header->code == LVN_COLUMNCLICK &&
            (header->idFrom == ID_LIST || header->idFrom == ID_PROC_LIST)) {
            NMLISTVIEW *view = (NMLISTVIEW *)header;

            if (g.sort_column == view->iSubItem) {
                g.sort_desc = !g.sort_desc;
            } else {
                g.sort_column = view->iSubItem;
                g.sort_desc = true;
            }
            if (header->idFrom == ID_LIST) {
                qsort(g.rows, (size_t)g.row_count, sizeof(*g.rows),
                      ui_row_sort);
            } else {
                qsort(g.processes, (size_t)g.process_count,
                      sizeof(*g.processes), ui_process_sort);
            }
            ui_fill_all();
            return 0;
        }
        if (header->code == NM_DBLCLK) {
            NMITEMACTIVATE *activate = (NMITEMACTIVATE *)header;
            if (header->idFrom == ID_LIST) {
                LVITEMW item;
                memset(&item, 0, sizeof(item));
                item.mask = LVIF_PARAM;
                item.iItem = activate->iItem;
                if (SendMessageW(g.list, LVM_GETITEMW, 0, (LPARAM)&item)) {
                    ui_show_detail((int)item.lParam);
                }
            } else if (header->idFrom == ID_PROC_LIST) {
                LVITEMW item;
                memset(&item, 0, sizeof(item));
                item.mask = LVIF_PARAM;
                item.iItem = activate->iItem;
                if (SendMessageW(g.proc_list, LVM_GETITEMW, 0, (LPARAM)&item)) {
                    ui_show_process_detail((int)item.lParam);
                }
            }
        }
        return 0;
    }

    case WM_SIZE:
        ui_layout(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
        ui_stop_worker(hwnd);
        ui_free_state();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    static const wchar_t *const class_name = L"CleanerSecureWindow";
    WNDCLASSEXW wc;
    INITCOMMONCONTROLSEX icc;
    HWND hwnd;
    MSG msg;
    int screen_w;
    int screen_h;
    int x;
    int y;

    (void)hPrevInstance;
    (void)lpCmdLine;

    memset(&icc, 0, sizeof(icc));
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_PROGRESS_CLASS;
    (void)InitCommonControlsEx(&icc);

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ui_wnd_proc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(CC_IDI_APPLICATION));
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(CC_IDC_ARROW));
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;
    if (RegisterClassExW(&wc) == 0) {
        return 0;
    }

    screen_w = GetSystemMetrics(SM_CXSCREEN);
    screen_h = GetSystemMetrics(SM_CYSCREEN);
    x = (screen_w - 1100) / 2;
    y = (screen_h - 700) / 2;
    if (x < 0) {
        x = 0;
    }
    if (y < 0) {
        y = 0;
    }
    hwnd = CreateWindowExW(0, class_name,
                           L"cleaner-secure — Monitor de procesos, servicios y red",
                           WS_OVERLAPPEDWINDOW, x, y, 1100, 700, NULL, NULL,
                           hInstance, NULL);
    if (hwnd == NULL) {
        return 0;
    }
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
