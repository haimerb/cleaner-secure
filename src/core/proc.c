#include "proc.h"

#include "metrics.h"

#include <stdlib.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <winsvc.h>

#define CC_NT_PROCESS_BASIC_INFORMATION 0
#define CC_PEB_PROCESS_PARAMETERS_OFFSET_X64 0x20
#define CC_PEB_PROCESS_PARAMETERS_OFFSET_X86 0x10
#define CC_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X64 0x70
#define CC_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X86 0x40

typedef LONG cc_ntstatus_t;
typedef LONG cc_kpriority_t;

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} cc_unicode_string_t;

typedef struct {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    cc_kpriority_t BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} cc_process_basic_info_t;

typedef cc_ntstatus_t(NTAPI *cc_nt_query_information_process_fn)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
    uint32_t *pids;
    int cap;
    int count;
} cc_window_pids_t;

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

static bool cc_name_is_system(const wchar_t *name)
{
    return cc_ascii_ieq(name, "System") ||
           cc_ascii_ieq(name, "Registry") ||
           cc_ascii_ieq(name, "smss.exe") ||
           cc_ascii_ieq(name, "csrss.exe");
}

static BOOL CALLBACK cc_collect_window_proc(HWND hwnd, LPARAM lparam)
{
    cc_window_pids_t *ctx = (cc_window_pids_t *)(uintptr_t)lparam;
    DWORD window_pid = 0;
    int i;

    if (ctx == NULL || ctx->pids == NULL || ctx->count >= ctx->cap) {
        return TRUE;
    }
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }
    GetWindowThreadProcessId(hwnd, &window_pid);
    if (window_pid == 0) {
        return TRUE;
    }
    for (i = 0; i < ctx->count; i++) {
        if (ctx->pids[i] == (uint32_t)window_pid) {
            return TRUE;
        }
    }
    ctx->pids[ctx->count++] = (uint32_t)window_pid;
    return TRUE;
}

static bool cc_pid_has_window(uint32_t pid, const uint32_t *pids, int count)
{
    int i;

    if (pids == NULL) {
        return false;
    }
    for (i = 0; i < count; i++) {
        if (pids[i] == pid) {
            return true;
        }
    }
    return false;
}

static void cc_read_path_handle(HANDLE proc, wchar_t *path, size_t cap)
{
    DWORD length;

    if (proc == NULL || path == NULL || cap == 0) {
        return;
    }
    path[0] = L'\0';
    length = cap > MAXDWORD ? MAXDWORD : (DWORD)cap;
    if (QueryFullProcessImageNameW(proc, 0, path, &length)) {
        path[cap - 1] = L'\0';
    } else {
        path[0] = L'\0';
    }
}

static cc_integrity_t cc_integrity_from_sid(PSID sid)
{
    UCHAR count;
    DWORD *sub;
    DWORD value;

    if (sid == NULL || !IsValidSid(sid)) {
        return CC_IL_UNKNOWN;
    }
    count = *GetSidSubAuthorityCount(sid);
    if (count == 0) {
        return CC_IL_UNKNOWN;
    }
    sub = GetSidSubAuthority(sid, count - 1);
    if (sub == NULL) {
        return CC_IL_UNKNOWN;
    }
    value = *sub;
    if (value <= 0x1000) {
        return CC_IL_LOW;
    }
    if (value <= 0x2000) {
        return CC_IL_MEDIUM;
    }
    if (value <= 0x3000) {
        return CC_IL_HIGH;
    }
    if (value <= 0x4000) {
        return CC_IL_SYSTEM;
    }
    return CC_IL_PROTECTED;
}

const wchar_t *cc_integrity_name(cc_integrity_t integrity)
{
    switch (integrity) {
    case CC_IL_LOW:
        return L"Baja";
    case CC_IL_MEDIUM:
        return L"Media";
    case CC_IL_HIGH:
        return L"Alta";
    case CC_IL_SYSTEM:
        return L"Sistema";
    case CC_IL_PROTECTED:
        return L"Protegida";
    case CC_IL_UNKNOWN:
    default:
        return L"Desconocida";
    }
}

static void cc_read_user(HANDLE token, cc_proc_info_t *info)
{
    TOKEN_USER *user = NULL;
    DWORD length = 0;
    wchar_t user_name[CC_MAX_NAME];
    wchar_t domain_name[CC_MAX_NAME];
    DWORD user_len;
    DWORD domain_len;
    SID_NAME_USE sid_use;

    if (token == NULL || info == NULL) {
        return;
    }
    if (!GetTokenInformation(token, TokenUser, NULL, 0, &length) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }
    if (length == 0 || length > 65536) {
        return;
    }
    user = (TOKEN_USER *)malloc(length);
    if (user == NULL) {
        return;
    }
    if (!GetTokenInformation(token, TokenUser, user, length, &length) ||
        user->User.Sid == NULL) {
        free(user);
        return;
    }

    user_len = CC_MAX_NAME;
    domain_len = CC_MAX_NAME;
    if (LookupAccountSidW(NULL, user->User.Sid, user_name, &user_len,
                          domain_name, &domain_len, &sid_use)) {
        if (domain_name[0] != L'\0') {
            swprintf(info->user, CC_MAX_NAME, L"%s\\%s", domain_name, user_name);
        } else {
            cc_wstr_copy(info->user, CC_MAX_NAME, user_name);
        }
        info->user_known = true;
    }
    free(user);
}

static void cc_read_token_info(HANDLE proc, cc_proc_info_t *info)
{
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    DWORD length = 0;
    BYTE *integrity = NULL;
    DWORD integrity_len = 0;
    TOKEN_MANDATORY_LABEL *label;

    if (proc == NULL || info == NULL || !OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        return;
    }

    ZeroMemory(&elevation, sizeof(elevation));
    if (GetTokenInformation(token, TokenElevation, &elevation,
                            sizeof(elevation), &length)) {
        info->is_elevated = elevation.TokenIsElevated != 0;
    }

    if (!GetTokenInformation(token, TokenIntegrityLevel, NULL, 0,
                             &integrity_len) &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        integrity_len > 0 && integrity_len <= 65536) {
        integrity = (BYTE *)malloc(integrity_len);
        if (integrity != NULL &&
            GetTokenInformation(token, TokenIntegrityLevel, integrity,
                                integrity_len, &integrity_len)) {
            label = (TOKEN_MANDATORY_LABEL *)(void *)integrity;
            info->integrity = cc_integrity_from_sid(label->Label.Sid);
        }
        free(integrity);
    }

    cc_read_user(token, info);
    CloseHandle(token);
}

static void cc_read_command_line(HANDLE proc, cc_proc_info_t *info)
{
    HMODULE ntdll;
    cc_nt_query_information_process_fn query;
    cc_process_basic_info_t basic;
    DWORD returned = 0;
    PVOID params = NULL;
    cc_unicode_string_t command;
    wchar_t *buffer;
    SIZE_T want;
    SIZE_T read = 0;
    size_t chars;
    size_t peb_offset;
    size_t command_offset;

    if (proc == NULL || info == NULL || info->is_wow64) {
        return;
    }
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return;
    }
    query = (cc_nt_query_information_process_fn)(void *)GetProcAddress(
        ntdll, "NtQueryInformationProcess");
    if (query == NULL) {
        return;
    }

    ZeroMemory(&basic, sizeof(basic));
    if (query(proc, CC_NT_PROCESS_BASIC_INFORMATION, &basic, sizeof(basic),
              &returned) != 0 || basic.PebBaseAddress == NULL) {
        return;
    }

    peb_offset = sizeof(void *) == 8
                     ? CC_PEB_PROCESS_PARAMETERS_OFFSET_X64
                     : CC_PEB_PROCESS_PARAMETERS_OFFSET_X86;
    command_offset = sizeof(void *) == 8
                         ? CC_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X64
                         : CC_PROCESS_PARAMETERS_COMMAND_LINE_OFFSET_X86;

    if (!ReadProcessMemory(proc, (BYTE *)basic.PebBaseAddress + peb_offset,
                           &params, sizeof(params), &read) ||
        params == NULL) {
        return;
    }
    ZeroMemory(&command, sizeof(command));
    if (!ReadProcessMemory(proc, (BYTE *)params + command_offset, &command,
                           sizeof(command), &read) ||
        command.Buffer == NULL || command.Length == 0 ||
        command.Length % sizeof(wchar_t) != 0) {
        return;
    }

    chars = (size_t)command.Length / sizeof(wchar_t);
    want = (SIZE_T)command.Length;
    buffer = (wchar_t *)malloc(want + sizeof(wchar_t));
    if (buffer == NULL) {
        return;
    }
    if (ReadProcessMemory(proc, command.Buffer, buffer, want, &read) &&
        read == want) {
        buffer[chars] = L'\0';
        cc_wstr_copy(info->command_line, CC_MAX_PATH_LEN, buffer);
    }
    free(buffer);
}

static void cc_proc_fill_info(HANDLE proc, cc_proc_info_t *info)
{
    FILETIME create_time;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    BOOL wow64 = FALSE;
    DWORD session_id = 0;
    HANDLE readable;

    if (proc == NULL || info == NULL) {
        return;
    }

    cc_read_path_handle(proc, info->path, CC_MAX_PATH_LEN);
    if (GetProcessTimes(proc, &create_time, &exit_time, &kernel_time,
                        &user_time)) {
        info->create_time = cc_filetime_value(&create_time);
    }
    if (ProcessIdToSessionId(info->pid, &session_id)) {
        info->session_id = (uint32_t)session_id;
    }
    if (IsWow64Process(proc, &wow64)) {
        info->is_wow64 = wow64 != FALSE;
        info->bitness_known = true;
    }
    cc_read_token_info(proc, info);

    readable = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                           (DWORD)info->pid);
    if (readable != NULL) {
        cc_read_command_line(readable, info);
        CloseHandle(readable);
    }
}

int cc_proc_list_ex(cc_proc_info_t *out, int cap, int *total)
{
    HANDLE snap;
    PROCESSENTRY32W entry;
    uint32_t *window_pids;
    cc_window_pids_t windows;
    int count = 0;
    int enumerated = 0;

    if (total != NULL) {
        *total = 0;
    }
    window_pids = (uint32_t *)calloc(CC_MAX_PROCS, sizeof(*window_pids));
    if (window_pids == NULL) {
        return 0;
    }
    windows.pids = window_pids;
    windows.cap = CC_MAX_PROCS;
    windows.count = 0;
    EnumWindows(cc_collect_window_proc, (LPARAM)(uintptr_t)&windows);

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        free(window_pids);
        return 0;
    }

    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            HANDLE proc;

            enumerated++;
            if (count < cap) {
                cc_proc_info_t *info = &out[count];

                ZeroMemory(info, sizeof(*info));
                info->pid = (uint32_t)entry.th32ProcessID;
                info->parent_pid = (uint32_t)entry.th32ParentProcessID;
                cc_wstr_copy(info->name, CC_MAX_NAME, entry.szExeFile);
                info->integrity = CC_IL_UNKNOWN;

                proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   (DWORD)info->pid);
                if (proc != NULL) {
                    cc_proc_fill_info(proc, info);
                    CloseHandle(proc);
                }
                info->is_hidden =
                    !cc_pid_has_window(info->pid, window_pids, windows.count) &&
                    !cc_name_is_system(info->name);
                count++;
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    free(window_pids);
    if (total != NULL) {
        *total = enumerated;
    }
    return count;
}

int cc_proc_list(cc_proc_info_t *out, int cap)
{
    return cc_proc_list_ex(out, cap, NULL);
}

int cc_proc_inventory_collect(cc_process_view_t *out, int cap, int *total,
                              int *analyzed, struct cc_metrics_s *metrics,
                              ULONGLONG deadline)
{
    cc_proc_info_t *procs;
    int listed;
    int counted = 0;
    int total_procs = 0;
    int i;
    uint32_t self_pid;

    if (analyzed != NULL) {
        *analyzed = 0;
    }
    if (out == NULL || cap <= 0) {
        return 0;
    }
    procs = (cc_proc_info_t *)calloc((size_t)cap, sizeof(*procs));
    if (procs == NULL) {
        return 0;
    }

    listed = cc_proc_list_ex(procs, cap, &total_procs);
    if (listed > cap) {
        listed = cap;
    }
    self_pid = GetCurrentProcessId();
    for (i = 0; i < listed; i++) {
        out[i].info = procs[i];
        ZeroMemory(&out[i].metrics, sizeof(out[i].metrics));
        if (procs[i].pid == 0 || procs[i].pid == 4 ||
            procs[i].pid == self_pid) {
            continue;
        }
        counted++;
        if (metrics != NULL && GetTickCount64() < deadline) {
            (void)cc_metrics_sample(metrics, procs[i].pid, &out[i].metrics);
        }
    }
    free(procs);
    if (total != NULL) {
        *total = total_procs;
    }
    if (analyzed != NULL) {
        *analyzed = counted;
    }
    return listed;
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
    bool ok = false;

    if (out == NULL || cap == 0 || pid == 0) {
        return false;
    }
    out[0] = L'\0';
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (proc == NULL) {
        return false;
    }
    cc_read_path_handle(proc, out, cap);
    ok = out[0] != L'\0';
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
    uint32_t *window_pids;
    cc_window_pids_t windows;
    bool hidden;

    if (pid == 0 || pid == 4) {
        return false;
    }
    window_pids = (uint32_t *)calloc(CC_MAX_PROCS, sizeof(*window_pids));
    if (window_pids == NULL) {
        return false;
    }
    windows.pids = window_pids;
    windows.cap = CC_MAX_PROCS;
    windows.count = 0;
    EnumWindows(cc_collect_window_proc, (LPARAM)(uintptr_t)&windows);
    hidden = !cc_pid_has_window(pid, window_pids, windows.count);
    free(window_pids);
    return hidden;
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
