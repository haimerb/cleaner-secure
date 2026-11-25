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
#include "registry_scan.h"
#include "eventlog_scan.h"
#include "response.h"
#include "trust.h"

#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ID_LIST 100
#define ID_STATUS 101
#define ID_BTN_SCAN 102
#define ID_BTN_KILL 103
#define ID_BTN_SUSPEND 104
#define ID_BTN_RESUME 105
#define ID_BTN_ELEV 106
#define ID_BTN_RUNAS 107
#define ID_CHK_AUTO 108
#define ID_TIMER 1
#define CC_ALERT_CAP 1024
#define CC_COL_REASON 6
#define CC_IDI_APPLICATION 32512
#define CC_IDC_ARROW 32512

typedef struct {
    cc_alert_t alert;
    double cpu;
    double ram_mb;
    int score;
} ui_row_t;

typedef struct {
    HWND list;
    HWND status;
    HWND btn_scan;
    HWND btn_kill;
    HWND btn_suspend;
    HWND btn_resume;
    HWND btn_elev;
    HWND btn_runas;
    HWND chk_auto;
    HFONT font;
    cc_config_t cfg;
    cc_ioc_t *ioc;
    cc_publishers_t *pubs;
    cc_metrics_t *metrics;
    cc_metrics_t *view_metrics;
    cc_trust_cache_t *cache;
    ui_row_t *rows;
    int row_count;
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

static void ui_set_subitem(int row, int column, const wchar_t *text)
{
    LVITEMW item;

    memset(&item, 0, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.iSubItem = column;
    item.pszText = (LPWSTR)text;
    (void)SendMessageW(g.list, LVM_SETITEMTEXTW, (WPARAM)row, (LPARAM)&item);
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
    int risk_index;

    (void)SendMessageW(g.list, WM_SETREDRAW, FALSE, 0);
    (void)SendMessageW(g.list, LVM_DELETEALLITEMS, 0, 0);
    for (i = 0; i < g.row_count; i++) {
        const ui_row_t *row = &g.rows[i];

        swprintf(pid_text, sizeof(pid_text) / sizeof(pid_text[0]), L"%lu",
                 (unsigned long)row->alert.pid);
        swprintf(cpu_text, sizeof(cpu_text) / sizeof(cpu_text[0]), L"%.1f",
                 row->cpu);
        swprintf(ram_text, sizeof(ram_text) / sizeof(ram_text[0]), L"%.1f",
                 row->ram_mb);
        ui_utf8_to_wide(row->alert.category, category,
                        sizeof(category) / sizeof(category[0]));
        ui_utf8_to_wide(row->alert.reason, reason,
                        sizeof(reason) / sizeof(reason[0]));
        risk_index = (int)row->alert.risk;
        if (risk_index < 0 || risk_index > 4) {
            risk_index = 0;
        }

        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = pid_text;
        item.lParam = (LPARAM)i;
        if (SendMessageW(g.list, LVM_INSERTITEMW, 0, (LPARAM)&item) == -1) {
            continue;
        }
        ui_set_subitem(i, 1, row->alert.target);
        ui_set_subitem(i, 2, cpu_text);
        ui_set_subitem(i, 3, ram_text);
        ui_set_subitem(i, 4, risk_labels[risk_index]);
        ui_set_subitem(i, 5, category);
        ui_set_subitem(i, CC_COL_REASON, reason);
    }
    (void)SendMessageW(g.list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g.list, NULL, FALSE);
}

static void ui_update_status(void)
{
    wchar_t text[256];
    int critical = 0;
    int high = 0;
    int i;

    for (i = 0; i < g.row_count; i++) {
        if (g.rows[i].alert.risk == CC_RISK_CRITICAL) {
            critical++;
        } else if (g.rows[i].alert.risk == CC_RISK_HIGH) {
            high++;
        }
    }
    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"Alertas: %d | Críticas: %d | Altas: %d | Procesos: %d | Admin: %s",
             g.row_count, critical, high, g.row_count,
             g.elevated ? L"SÍ" : L"NO");
    SetWindowTextW(g.status, text);
}

static int ui_append_alerts(int used, int cap, int count)
{
    if (count < 0) {
        count = 0;
    }
    if (used < 0) {
        used = 0;
    }
    if (count > cap - used) {
        count = cap - used;
    }
    return count;
}

static void ui_scan(void)
{
    cc_alert_t *buffer;
    ui_row_t *rows;
    cc_detect_ctx_t ctx;
    cc_proc_metrics_t pm;
    int count = 0;
    int added;
    int i;
    ULONGLONG deadline = GetTickCount64() + 60000;

    if (g.cfg.scan_timeout_ms != 0) {
        deadline = GetTickCount64() + (ULONGLONG)g.cfg.scan_timeout_ms;
    }
    buffer = (cc_alert_t *)calloc(CC_ALERT_CAP, sizeof(*buffer));
    if (buffer == NULL) {
        return;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg = (const struct cc_config_s *)&g.cfg;
    ctx.ioc = g.ioc;
    ctx.pubs = g.pubs;
    ctx.metrics = g.metrics;
    ctx.trust_cache = g.cache;
    added = cc_detect_processes(&ctx, buffer, CC_ALERT_CAP, deadline);
    count += ui_append_alerts(count, CC_ALERT_CAP, added);

    added = cc_registry_scan(g.ioc, buffer + count, CC_ALERT_CAP - count, deadline);
    count += ui_append_alerts(count, CC_ALERT_CAP, added);

    added = cc_eventlog_scan(g.eventlog_minutes, buffer + count,
                             CC_ALERT_CAP - count, NULL, deadline);
    count += ui_append_alerts(count, CC_ALERT_CAP, added);

    rows = (ui_row_t *)calloc((size_t)(count > 0 ? count : 1), sizeof(*rows));
    if (rows == NULL) {
        free(buffer);
        return;
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

    free(g.rows);
    g.rows = rows;
    g.row_count = count;
    free(buffer);

    ui_fill_list();
    ui_update_status();
}

static void ui_show_detail(int index)
{
    wchar_t category[64];
    wchar_t reason[CC_MAX_REASON * 2];
    wchar_t text[CC_MAX_REASON * 2 + 256];
    const ui_row_t *row;

    if (index < 0 || index >= g.row_count) {
        return;
    }
    row = &g.rows[index];
    ui_utf8_to_wide(row->alert.category, category,
                    sizeof(category) / sizeof(category[0]));
    ui_utf8_to_wide(row->alert.reason, reason,
                    sizeof(reason) / sizeof(reason[0]));
    swprintf(text, sizeof(text) / sizeof(text[0]),
             L"PID: %lu\nProceso: %s\nRiesgo: %s\nCategoría: %s\n"
             L"Puntuación: %d\nCPU: %.1f%%\nRAM: %.1f MB\nMotivo: %s\nDestino: %s",
             (unsigned long)row->alert.pid, row->alert.target,
             ui_risk_name(row->alert.risk), category, row->score,
             row->cpu, row->ram_mb, reason, row->alert.target);
    MessageBoxW(NULL, text, L"Detalle de alerta", MB_OK | MB_ICONINFORMATION);
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

static void ui_action(int command)
{
    int selected;
    DWORD error_code = 0;
    wchar_t action[32];
    bool ok;

    selected = (int)SendMessageW(g.list, LVM_GETNEXTITEM, (WPARAM)-1,
                                 LVNI_SELECTED);
    if (selected < 0 || selected >= g.row_count) {
        MessageBoxW(NULL, L"Seleccione una alerta de la lista.",
                    L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (g.rows[selected].alert.pid == 0) {
        MessageBoxW(NULL, L"La alerta seleccionada no tiene PID.",
                    L"cleaner-secure", MB_OK | MB_ICONINFORMATION);
        return;
    }

    switch (command) {
    case ID_BTN_KILL:
        ok = cc_kill_process(g.rows[selected].alert.pid, &error_code);
        wcscpy(action, L"Terminar");
        break;
    case ID_BTN_SUSPEND:
        ok = cc_suspend_process(g.rows[selected].alert.pid, &error_code);
        wcscpy(action, L"Suspender");
        break;
    case ID_BTN_RESUME:
        ok = cc_resume_process(g.rows[selected].alert.pid, &error_code);
        wcscpy(action, L"Reanudar");
        break;
    default:
        return;
    }
    if (!ok) {
        wchar_t err_text[256];
        ui_error_text(error_code, err_text,
                      sizeof(err_text) / sizeof(err_text[0]));
        MessageBoxW(NULL, err_text, action, MB_OK | MB_ICONERROR);
    }
}

static void ui_layout(int width, int height)
{
    static const int fixed_widths[] = { 80, 220, 80, 100, 90, 120 };
    const int gap = 6;
    const int margin = 8;
    LVCOLUMNW col;
    HWND buttons[6];
    int count = 0;
    int list_w;
    int list_h;
    int button_w;
    int last_w;
    int i;

    if (width < 240) {
        width = 240;
    }
    if (height < 260) {
        height = 260;
    }
    list_w = width - margin * 2;
    list_h = height - 130;
    if (list_h < 80) {
        list_h = 80;
    }
    MoveWindow(g.list, margin, margin, list_w, list_h, TRUE);

    MoveWindow(g.chk_auto, margin, margin + list_h + 8, 150, 22, TRUE);

    buttons[count++] = g.btn_scan;
    buttons[count++] = g.btn_kill;
    buttons[count++] = g.btn_suspend;
    buttons[count++] = g.btn_resume;
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

    last_w = list_w - 24;
    for (i = 0; i < 6; i++) {
        last_w -= fixed_widths[i];
    }
    if (last_w < 160) {
        last_w = 160;
    }
    memset(&col, 0, sizeof(col));
    col.mask = LVCF_WIDTH;
    col.cx = last_w;
    (void)SendMessageW(g.list, LVM_SETCOLUMNW, (WPARAM)CC_COL_REASON,
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

static bool ui_create_controls(HWND hwnd)
{
    static const struct {
        const wchar_t *text;
        int width;
    } columns[] = {
        { L"PID", 80 },
        { L"Proceso", 220 },
        { L"CPU%", 80 },
        { L"RAM(MB)", 100 },
        { L"Riesgo", 90 },
        { L"Categoría", 120 },
        { L"Motivo", 300 }
    };
    LVCOLUMNW col;
    DWORD ex_style;
    size_t i;

    g.font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    g.list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | WS_BORDER |
                             LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                             8, 8, 1084, 570, hwnd, (HMENU)(INT_PTR)ID_LIST,
                             GetModuleHandleW(NULL), NULL);
    if (g.list == NULL) {
        return false;
    }
    ex_style = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES;
    (void)SendMessageW(g.list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)ex_style);
    (void)SendMessageW(g.list, WM_SETFONT, (WPARAM)g.font, TRUE);

    for (i = 0; i < sizeof(columns) / sizeof(columns[0]); i++) {
        memset(&col, 0, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.fmt = LVCFMT_LEFT;
        col.cx = columns[i].width;
        col.iSubItem = (int)i;
        col.pszText = (LPWSTR)columns[i].text;
        if (SendMessageW(g.list, LVM_INSERTCOLUMNW, (WPARAM)i, (LPARAM)&col) < 0) {
            return false;
        }
    }

    g.chk_auto = CreateWindowExW(0, L"Button", L"Auto-refresco",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                 BS_AUTOCHECKBOX,
                                 8, 586, 150, 22, hwnd,
                                 (HMENU)(INT_PTR)ID_CHK_AUTO,
                                 GetModuleHandleW(NULL), NULL);
    g.btn_scan = ui_create_button(hwnd, ID_BTN_SCAN, L"Analizar ahora", 8, 618,
                                  170, 28);
    g.btn_kill = ui_create_button(hwnd, ID_BTN_KILL, L"Terminar", 186, 618,
                                  170, 28);
    g.btn_suspend = ui_create_button(hwnd, ID_BTN_SUSPEND, L"Suspender", 364,
                                     618, 170, 28);
    g.btn_resume = ui_create_button(hwnd, ID_BTN_RESUME, L"Reanudar", 542, 618,
                                    170, 28);
    g.btn_elev = ui_create_button(hwnd, ID_BTN_ELEV, L"Elevación", 720, 618,
                                  170, 28);
    if (!g.elevated) {
        g.btn_runas = ui_create_button(hwnd, ID_BTN_RUNAS,
                                       L"Reiniciar como administrador",
                                       898, 618, 194, 28);
    }
    g.status = CreateWindowExW(0, L"Static", L"", WS_CHILD | WS_VISIBLE |
                               SS_LEFT | SS_SUNKEN,
                               8, 672, 1084, 24, hwnd,
                               (HMENU)(INT_PTR)ID_STATUS,
                               GetModuleHandleW(NULL), NULL);

    if (g.chk_auto == NULL || g.btn_scan == NULL || g.btn_kill == NULL ||
        g.btn_suspend == NULL || g.btn_resume == NULL || g.btn_elev == NULL ||
        g.status == NULL || (!g.elevated && g.btn_runas == NULL)) {
        return false;
    }
    (void)SendMessageW(g.chk_auto, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_scan, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_kill, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_suspend, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_resume, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.btn_elev, WM_SETFONT, (WPARAM)g.font, TRUE);
    if (g.btn_runas != NULL) {
        (void)SendMessageW(g.btn_runas, WM_SETFONT, (WPARAM)g.font, TRUE);
    }
    (void)SendMessageW(g.status, WM_SETFONT, (WPARAM)g.font, TRUE);
    (void)SendMessageW(g.chk_auto, BM_SETCHECK, BST_CHECKED, 0);
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
    g.cache = cc_trust_cache_create();
    if (g.metrics == NULL || g.view_metrics == NULL || g.cache == NULL) {
        return false;
    }
    return true;
}

static void ui_free_state(void)
{
    free(g.rows);
    g.rows = NULL;
    g.row_count = 0;
    cc_trust_cache_free(g.cache);
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
        ui_scan();
        return 0;

    case WM_TIMER:
        if (wParam == ID_TIMER &&
            SendMessageW(g.chk_auto, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            ui_scan();
        }
        return 0;

    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case ID_BTN_SCAN:
                ui_scan();
                break;
            case ID_BTN_KILL:
            case ID_BTN_SUSPEND:
            case ID_BTN_RESUME:
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
        }
        return 0;

    case WM_NOTIFY: {
        NMHDR *header = (NMHDR *)lParam;
        if (header != NULL && header->idFrom == ID_LIST &&
            header->code == NM_DBLCLK) {
            NMITEMACTIVATE *activate = (NMITEMACTIVATE *)header;
            ui_show_detail(activate->iItem);
        }
        return 0;
    }

    case WM_SIZE:
        ui_layout(LOWORD(lParam), HIWORD(lParam));
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
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
    HWND hwnd;
    MSG msg;
    int screen_w;
    int screen_h;
    int x;
    int y;

    (void)hPrevInstance;
    (void)lpCmdLine;

    INITCOMMONCONTROLSEX icc;
    memset(&icc, 0, sizeof(icc));
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    (void)InitCommonControlsEx(&icc);

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = ui_wnd_proc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(CC_IDI_APPLICATION));
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
                           L"cleaner-secure — Monitor de procesos y servicios",
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
