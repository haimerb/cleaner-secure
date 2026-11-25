#include "proc.h"

#include <stdlib.h>
#include <tlhelp32.h>
#include <winsvc.h>

static void cc_wstr_copy(wchar_t *dst, size_t cap, const wchar_t *src)
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

static ULONGLONG cc_filetime_value(const FILETIME *ft)
{
    if (ft == NULL) {
        return 0;
    }
    return ((ULONGLONG)ft->dwHighDateTime << 32) | (ULONGLONG)ft->dwLowDateTime;
}

static bool cc_ascii_ieq(const wchar_t *a, const char *b)
{
    size_t i = 0;

    if (a == NULL || b == NULL) {
        return false;
    }
    for (;;) {
        wchar_t ca = a[i];
        unsigned char cb = (unsigned char)b[i];

        if (ca >= L'A' && ca <= L'Z') {
            ca = (wchar_t)(ca - L'A' + L'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != (wchar_t)cb) {
            return false;
        }
        if (ca == L'\0') {
            return true;
        }
        i++;
    }
}

static const wchar_t *cc_basename(const wchar_t *path)
{
    const wchar_t *base = path;
    const wchar_t *p = path;

    if (path == NULL) {
        return L"";
    }
    while (*p != L'\0') {
        if (*p == L'\\' || *p == L'/') {
            base = p + 1;
        }
        p++;
    }
    return base;
}

static bool cc_name_is_system(const wchar_t *name)
{
    return cc_ascii_ieq(name, "System") ||
           cc_ascii_ieq(name, "Registry") ||
           cc_ascii_ieq(name, "smss.exe") ||
           cc_ascii_ieq(name, "csrss.exe");
}

static bool cc_skip_hidden_check(uint32_t pid)
{
    wchar_t name[CC_MAX_NAME];
    wchar_t path[CC_MAX_PATH_LEN];
    HANDLE snap;
    PROCESSENTRY32W entry;

    if (pid == 0 || pid == 4) {
        return true;
    }

    name[0] = L'\0';
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        ZeroMemory(&entry, sizeof(entry));
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry)) {
            do {
                if (entry.th32ProcessID == pid) {
                    cc_wstr_copy(name, CC_MAX_NAME, entry.szExeFile);
                    break;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
    }
    if (cc_name_is_system(name)) {
        return true;
    }

    path[0] = L'\0';
    if (cc_proc_path(pid, path, CC_MAX_PATH_LEN)) {
        if (cc_name_is_system(cc_basename(path))) {
            return true;
        }
    }
    return false;
}

typedef struct {
    uint32_t pid;
    bool visible;
} cc_hidden_ctx_t;

static BOOL CALLBACK cc_visible_window_proc(HWND hwnd, LPARAM lparam)
{
    cc_hidden_ctx_t *ctx = (cc_hidden_ctx_t *)(uintptr_t)lparam;
    DWORD window_pid = 0;

    if (ctx == NULL) {
        return TRUE;
    }
    GetWindowThreadProcessId(hwnd, &window_pid);
    if (window_pid == ctx->pid && IsWindowVisible(hwnd)) {
        ctx->visible = true;
        return FALSE;
    }
    return TRUE;
}

int cc_proc_list(cc_proc_info_t *out, int cap)
{
    HANDLE snap;
    PROCESSENTRY32W entry;
    int count = 0;

    if (out == NULL || cap <= 0) {
        return 0;
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            cc_proc_info_t *info;
            HANDLE proc;

            if (count >= cap) {
                break;
            }
            info = &out[count];
            ZeroMemory(info, sizeof(*info));
            info->pid = (uint32_t)entry.th32ProcessID;
            info->parent_pid = (uint32_t)entry.th32ParentProcessID;
            cc_wstr_copy(info->name, CC_MAX_NAME, entry.szExeFile);

            proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               (DWORD)info->pid);
            if (proc != NULL) {
                FILETIME create_time;
                FILETIME exit_time;
                FILETIME kernel_time;
                FILETIME user_time;

                if (GetProcessTimes(proc, &create_time, &exit_time,
                                    &kernel_time, &user_time)) {
                    info->create_time = cc_filetime_value(&create_time);
                }
                CloseHandle(proc);
            }

            (void)cc_proc_path(info->pid, info->path, CC_MAX_PATH_LEN);
            info->is_hidden = cc_proc_is_hidden(info->pid);
            info->is_elevated = cc_proc_is_elevated(info->pid);
            count++;
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return count;
}

static void cc_service_read_config(SC_HANDLE scm, const wchar_t *name,
                                   cc_service_info_t *info)
{
    SC_HANDLE service;

    if (scm == NULL || name == NULL || info == NULL) {
        return;
    }
    service = OpenServiceW(scm, name, SERVICE_QUERY_CONFIG);
    if (service == NULL) {
        return;
    }

    {
        DWORD needed = 0;

        if (!QueryServiceConfigW(service, NULL, 0, &needed) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER && needed > 0) {
            QUERY_SERVICE_CONFIGW *config =
                (QUERY_SERVICE_CONFIGW *)malloc(needed);

            if (config != NULL) {
                if (QueryServiceConfigW(service, config, needed, &needed)) {
                    info->start_type = (uint32_t)config->dwStartType;
                    cc_wstr_copy(info->path, CC_MAX_PATH_LEN,
                                 config->lpBinaryPathName);
                }
                free(config);
            }
        }
    }

    CloseServiceHandle(service);
}

int cc_service_list(cc_service_info_t *out, int cap)
{
    SC_HANDLE scm;
    ENUM_SERVICE_STATUS_PROCESSW *buffer = NULL;
    DWORD buffer_size = 16384;
    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    bool ok = false;
    int count = 0;

    if (out == NULL || cap <= 0) {
        return 0;
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL) {
        return -1;
    }

    for (;;) {
        DWORD allocated = buffer_size;
        ENUM_SERVICE_STATUS_PROCESSW *next =
            (ENUM_SERVICE_STATUS_PROCESSW *)realloc(buffer, allocated);

        if (next == NULL) {
            break;
        }
        buffer = next;
        needed = 0;
        returned = 0;
        resume = 0;
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                  SERVICE_STATE_ALL, (LPBYTE)buffer, allocated,
                                  &needed, &returned, &resume, NULL)) {
            ok = true;
            break;
        }
        if (GetLastError() != ERROR_MORE_DATA) {
            break;
        }
        if (needed > allocated) {
            buffer_size = needed;
        } else if (allocated > 0x7fffffffu) {
            break;
        } else {
            buffer_size = allocated * 2;
        }
    }

    if (ok) {
        DWORD i;

        for (i = 0; i < returned && count < cap; i++) {
            ENUM_SERVICE_STATUS_PROCESSW *entry = &buffer[i];
            cc_service_info_t *info = &out[count];

            ZeroMemory(info, sizeof(*info));
            cc_wstr_copy(info->name, CC_MAX_NAME, entry->lpServiceName);
            cc_wstr_copy(info->display_name, CC_MAX_NAME,
                         entry->lpDisplayName);
            info->state = (uint32_t)entry->ServiceStatusProcess.dwCurrentState;
            info->pid = (uint32_t)entry->ServiceStatusProcess.dwProcessId;
            cc_service_read_config(scm, entry->lpServiceName, info);
            count++;
        }
    }

    free(buffer);
    CloseServiceHandle(scm);
    return count;
}

bool cc_proc_path(uint32_t pid, wchar_t *out, size_t cap)
{
    HANDLE proc;
    DWORD length;
    bool ok = false;

    if (out == NULL || cap == 0 || pid == 0) {
        return false;
    }
    out[0] = L'\0';
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (proc == NULL) {
        return false;
    }

    length = cap > MAXDWORD ? MAXDWORD : (DWORD)cap;
    if (QueryFullProcessImageNameW(proc, 0, out, &length)) {
        out[cap - 1] = L'\0';
        ok = true;
    } else {
        out[0] = L'\0';
    }
    CloseHandle(proc);
    return ok;
}

uint32_t cc_proc_parent(uint32_t pid)
{
    HANDLE snap;
    PROCESSENTRY32W entry;
    uint32_t parent = 0;

    if (pid == 0) {
        return 0;
    }
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                parent = (uint32_t)entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return parent;
}

bool cc_proc_is_elevated(uint32_t pid)
{
    HANDLE proc;
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD length = 0;
    bool elevated = false;

    if (pid == 0) {
        return false;
    }
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (proc == NULL) {
        return false;
    }
    if (OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        ZeroMemory(&elevation, sizeof(elevation));
        if (GetTokenInformation(token, TokenElevation, &elevation,
                                sizeof(elevation), &length)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    CloseHandle(proc);
    return elevated;
}

bool cc_proc_is_hidden(uint32_t pid)
{
    cc_hidden_ctx_t ctx;

    if (cc_skip_hidden_check(pid)) {
        return false;
    }
    ctx.pid = pid;
    ctx.visible = false;
    EnumWindows(cc_visible_window_proc, (LPARAM)(uintptr_t)&ctx);
    return !ctx.visible;
}

int cc_service_find_by_pid(const cc_service_info_t *svcs, int count,
                           uint32_t pid)
{
    int i;

    if (svcs == NULL || count <= 0 || pid == 0) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (svcs[i].pid == pid) {
            return i;
        }
    }
    return -1;
}
