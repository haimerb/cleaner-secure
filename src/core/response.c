#include "response.h"
#include "trust.h"

#include <lmcons.h>
#include <stdio.h>
#include <wchar.h>
#include <winsvc.h>

typedef LONG (NTAPI *cc_nt_process_op_t)(HANDLE);

static bool cc_audit_append(wchar_t *buf, size_t cap, const wchar_t *suffix)
{
    size_t n = wcslen(buf);
    size_t m = wcslen(suffix);
    if (n + m >= cap) {
        return false;
    }
    wcscpy(buf + n, suffix);
    return true;
}

static void cc_audit_clean(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t i = 0;
    if (dst == NULL || cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = L'\0';
        return;
    }
    while (src[i] != L'\0' && i + 1 < cap) {
        wchar_t c = src[i];
        dst[i++] = (c < 0x20 || c == 0x7f) ? L'?' : c;
    }
    dst[i] = L'\0';
}

static void cc_response_audit(const wchar_t *action, const wchar_t *target, bool ok, DWORD code)
{
    wchar_t dir[MAX_PATH];
    wchar_t user[UNLEN + 1] = L"?";
    wchar_t clean[CC_MAX_NAME];
    DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", dir, MAX_PATH);
    DWORD user_len = UNLEN + 1;
    SYSTEMTIME st;
    FILE *file;

    if (len == 0 || len >= MAX_PATH) {
        len = GetTempPathW(MAX_PATH, dir);
        if (len == 0 || len >= MAX_PATH) {
            return;
        }
    }
    dir[len] = L'\0';
    if (!cc_audit_append(dir, MAX_PATH, L"\\cleaner-c")) {
        return;
    }
    CreateDirectoryW(dir, NULL);
    if (!cc_audit_append(dir, MAX_PATH, L"\\actions.log")) {
        return;
    }
    if (!GetUserNameW(user, &user_len)) {
        wcscpy(user, L"?");
    }
    cc_audit_clean(clean, sizeof(clean) / sizeof(clean[0]), target);
    GetLocalTime(&st);
    file = _wfopen(dir, L"a");
    if (file == NULL) {
        return;
    }
    fwprintf(file,
             L"%04u-%02u-%02u %02u:%02u:%02u user=%ls action=%ls target=%ls ok=%d error=%lu\n",
             (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
             (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
             user, action, clean, ok ? 1 : 0, (unsigned long)code);
    fclose(file);
}

static void cc_pid_audit(const wchar_t *action, uint32_t pid, bool ok, DWORD code)
{
    wchar_t target[32];
    swprintf(target, sizeof(target) / sizeof(target[0]), L"pid=%u", (unsigned)pid);
    cc_response_audit(action, target, ok, code);
}

static bool cc_response_fail(DWORD *err, DWORD code)
{
    if (err != NULL) {
        *err = code;
    }
    return false;
}

static bool cc_pid_allowed(uint32_t pid, DWORD *err)
{
    static const wchar_t *const deny[] = {
        L"csrss.exe", L"wininit.exe", L"winlogon.exe", L"services.exe",
        L"lsass.exe", L"smss.exe", L"system", L"registry",
        L"cleaner-c.exe", L"cleaner-c-cli.exe"
    };
    wchar_t path[CC_MAX_PATH_LEN];
    DWORD len = CC_MAX_PATH_LEN;
    const wchar_t *base;
    HANDLE proc;
    DWORD i;

    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId()) {
        return cc_response_fail(err, ERROR_INVALID_PARAMETER);
    }
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (proc == NULL) {
        return cc_response_fail(err, GetLastError());
    }
    if (!QueryFullProcessImageNameW(proc, 0, path, &len)) {
        DWORD code = GetLastError();
        CloseHandle(proc);
        return cc_response_fail(err, code);
    }
    CloseHandle(proc);
    base = wcsrchr(path, L'\\');
    base = base != NULL ? base + 1 : path;
    for (i = 0; i < sizeof(deny) / sizeof(deny[0]); i++) {
        if (_wcsicmp(base, deny[i]) == 0) {
            return cc_response_fail(err, ERROR_ACCESS_DENIED);
        }
    }
    return true;
}

static bool cc_service_allowed(const wchar_t *name, DWORD *err)
{
    static const wchar_t *const deny[] = {
        L"WinDefend", L"EventLog", L"RpcSs", L"DcomLaunch",
        L"PlugPlay", L"Power", L"samss", L"LSM", L"Winmgmt"
    };
    DWORD i;

    if (name == NULL || name[0] == L'\0') {
        return cc_response_fail(err, ERROR_INVALID_PARAMETER);
    }
    for (i = 0; i < sizeof(deny) / sizeof(deny[0]); i++) {
        if (_wcsicmp(name, deny[i]) == 0) {
            return cc_response_fail(err, ERROR_ACCESS_DENIED);
        }
    }
    return true;
}

bool cc_kill_process(uint32_t pid, DWORD *err)
{
    HANDLE proc;
    DWORD code;

    if (!cc_pid_allowed(pid, &code)) {
        cc_pid_audit(L"kill", pid, false, code);
        return cc_response_fail(err, code);
    }
    proc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (proc == NULL) {
        code = GetLastError();
        cc_pid_audit(L"kill", pid, false, code);
        return cc_response_fail(err, code);
    }
    if (!TerminateProcess(proc, 1)) {
        code = GetLastError();
        CloseHandle(proc);
        cc_pid_audit(L"kill", pid, false, code);
        return cc_response_fail(err, code);
    }
    CloseHandle(proc);
    cc_pid_audit(L"kill", pid, true, 0);
    return true;
}

static bool cc_suspend_resume_op(uint32_t pid, const char *nt_name,
                                 const wchar_t *action, DWORD *err)
{
    HANDLE proc;
    DWORD code;

    if (!cc_pid_allowed(pid, &code)) {
        cc_pid_audit(action, pid, false, code);
        return cc_response_fail(err, code);
    }
    proc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, (DWORD)pid);
    if (proc == NULL) {
        code = GetLastError();
        cc_pid_audit(action, pid, false, code);
        return cc_response_fail(err, code);
    }
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC raw = ntdll != NULL ? GetProcAddress(ntdll, nt_name) : NULL;
    if (raw == NULL) {
        CloseHandle(proc);
        code = ERROR_NOT_SUPPORTED;
        cc_pid_audit(action, pid, false, code);
        return cc_response_fail(err, code);
    }
    cc_nt_process_op_t op = (cc_nt_process_op_t)(void *)raw;
    LONG status = op(proc);
    CloseHandle(proc);
    if (status != 0) {
        cc_pid_audit(action, pid, false, ERROR_ACCESS_DENIED);
        return cc_response_fail(err, ERROR_ACCESS_DENIED);
    }
    cc_pid_audit(action, pid, true, 0);
    return true;
}

bool cc_suspend_process(uint32_t pid, DWORD *err)
{
    return cc_suspend_resume_op(pid, "NtSuspendProcess", L"suspend", err);
}

bool cc_resume_process(uint32_t pid, DWORD *err)
{
    return cc_suspend_resume_op(pid, "NtResumeProcess", L"resume", err);
}

bool cc_service_stop(const wchar_t *name, DWORD *err)
{
    DWORD code = 0;
    bool ok = false;
    SC_HANDLE scm;

    if (!cc_service_allowed(name, &code)) {
        cc_response_audit(L"service-stop", name, false, code);
        return cc_response_fail(err, code);
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        code = GetLastError();
        cc_response_audit(L"service-stop", name, false, code);
        return cc_response_fail(err, code);
    }
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (svc == NULL) {
        code = GetLastError();
    } else {
        SERVICE_STATUS status;
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
            code = GetLastError();
        } else {
            bool stopped = status.dwCurrentState == SERVICE_STOPPED;
            for (int i = 0; i < 50 && !stopped; i++) {
                Sleep(200);
                if (!QueryServiceStatus(svc, &status)) {
                    code = GetLastError();
                    break;
                }
                stopped = status.dwCurrentState == SERVICE_STOPPED;
            }
            if (!stopped && code == 0) {
                code = ERROR_TIMEOUT;
            }
            ok = stopped;
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    if (!ok) {
        cc_response_audit(L"service-stop", name, false, code);
        return cc_response_fail(err, code);
    }
    cc_response_audit(L"service-stop", name, true, 0);
    return true;
}

bool cc_service_start(const wchar_t *name, DWORD *err)
{
    DWORD code = 0;
    bool ok = false;
    SC_HANDLE scm;

    if (!cc_service_allowed(name, &code)) {
        cc_response_audit(L"service-start", name, false, code);
        return cc_response_fail(err, code);
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        code = GetLastError();
        cc_response_audit(L"service-start", name, false, code);
        return cc_response_fail(err, code);
    }
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_START);
    if (svc == NULL) {
        code = GetLastError();
    } else {
        if (StartServiceW(svc, 0, NULL)) {
            ok = true;
        } else {
            code = GetLastError();
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    if (!ok) {
        cc_response_audit(L"service-start", name, false, code);
        return cc_response_fail(err, code);
    }
    cc_response_audit(L"service-start", name, true, 0);
    return true;
}
