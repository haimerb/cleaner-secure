#include "registry_scan.h"

#include "ioc.h"

#include <stdio.h>
#include <wchar.h>

#define CC_REG_PART 256
#define CC_REG_BAD_DIR_COUNT 4

static wchar_t cc_wlower(wchar_t c)
{
    if (c >= L'A' && c <= L'Z') {
        return (wchar_t)(c + (L'a' - L'A'));
    }
    return c;
}

static bool cc_wcontains_i(const wchar_t *s, const wchar_t *needle)
{
    size_t i;
    size_t j;

    if (s == NULL || needle == NULL) {
        return false;
    }
    for (i = 0; s[i] != L'\0'; i++) {
        for (j = 0; needle[j] != L'\0' && s[i + j] != L'\0'; j++) {
            if (cc_wlower(s[i + j]) != cc_wlower(needle[j])) {
                break;
            }
        }
        if (needle[j] == L'\0') {
            return true;
        }
    }
    return false;
}

static bool cc_wends_with_i(const wchar_t *s, const wchar_t *suffix)
{
    size_t n;
    size_t m;
    size_t i;

    if (s == NULL || suffix == NULL) {
        return false;
    }
    n = wcslen(s);
    m = wcslen(suffix);
    if (m > n) {
        return false;
    }
    for (i = 0; i < m; i++) {
        if (cc_wlower(s[n - m + i]) != cc_wlower(suffix[i])) {
            return false;
        }
    }
    return true;
}

static bool cc_suspicious_path(const wchar_t *path)
{
    static const wchar_t *const dirs[CC_REG_BAD_DIR_COUNT] = {
        L"\\temp\\", L"\\users\\public\\", L"\\$recycle.bin\\",
        L"\\windows\\tasks\\"
    };
    static const wchar_t *const tails[CC_REG_BAD_DIR_COUNT] = {
        L"\\temp", L"\\users\\public", L"\\$recycle.bin",
        L"\\windows\\tasks"
    };

    if (path == NULL) {
        return false;
    }
    for (size_t i = 0; i < CC_REG_BAD_DIR_COUNT; i++) {
        if (cc_wcontains_i(path, dirs[i]) || cc_wends_with_i(path, tails[i])) {
            return true;
        }
    }
    return false;
}

static void cc_wide_to_utf8(const wchar_t *src, char *dst, size_t cap)
{
    int written;

    if (cap == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)cap,
                                  NULL, NULL);
    if (written <= 0) {
        dst[0] = '\0';
    } else {
        dst[cap - 1] = '\0';
    }
}

static void cc_join_key(wchar_t *dst, size_t cap, const wchar_t *a,
                        const wchar_t *b)
{
    size_t len_a;
    size_t len_b;
    size_t take;

    if (cap == 0 || a == NULL) {
        return;
    }
    len_a = wcslen(a);
    if (len_a > cap - 1) {
        len_a = cap - 1;
    }
    wmemcpy(dst, a, len_a);
    dst[len_a] = L'\0';
    if (b == NULL || b[0] == L'\0' || len_a == cap - 1) {
        return;
    }
    len_b = wcslen(b);
    dst[len_a++] = L'\\';
    take = cap - 1 - len_a;
    if (take > len_b) {
        take = len_b;
    }
    wmemcpy(dst + len_a, b, take);
    dst[len_a + take] = L'\0';
}

static void cc_reason(char *dst, size_t cap, const wchar_t *key,
                      const wchar_t *label, const wchar_t *data)
{
    char key_buf[CC_REG_PART];
    char data_buf[CC_REG_PART];

    cc_wide_to_utf8(key, key_buf, sizeof(key_buf));
    cc_wide_to_utf8(data, data_buf, sizeof(data_buf));
    if (label != NULL && label[0] != L'\0') {
        char label_buf[64];

        cc_wide_to_utf8(label, label_buf, sizeof(label_buf));
        snprintf(dst, cap, "%s | %s: %s", key_buf, label_buf, data_buf);
    } else {
        snprintf(dst, cap, "%s | %s", key_buf, data_buf);
    }
}

static int cc_emit(cc_alert_t *out, int cap, int count, cc_risk_t risk,
                   const wchar_t *target, const char *reason)
{
    cc_alert_t *alert;

    if (out == NULL || cap <= 0 || count < 0 || count >= cap) {
        return count;
    }
    alert = &out[count];
    alert->risk = risk;
    snprintf(alert->category, sizeof(alert->category), "%s", "registry");
    wcsncpy(alert->target, target != NULL ? target : L"", CC_MAX_NAME - 1);
    alert->target[CC_MAX_NAME - 1] = L'\0';
    snprintf(alert->reason, sizeof(alert->reason), "%s",
             reason != NULL ? reason : "");
    alert->pid = 0;
    return count + 1;
}

static size_t cc_reg_data_len(DWORD bytes, size_t cap)
{
    size_t count;

    count = (size_t)bytes / sizeof(wchar_t);
    if (cap == 0) {
        return 0;
    }
    if (count >= cap) {
        count = cap - 1;
    }
    return count;
}

static int cc_scan_run_key(HKEY root, const wchar_t *hive,
                           const wchar_t *subkey,
                           const struct cc_ioc_s *ioc,
                           cc_alert_t *out, int cap, int count)
{
    wchar_t full_key[CC_MAX_PATH_LEN];
    wchar_t name[CC_MAX_NAME];
    wchar_t data[CC_MAX_PATH_LEN];
    char reason[CC_MAX_REASON];
    HKEY key = NULL;

    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return count;
    }
    cc_join_key(full_key, sizeof(full_key) / sizeof(full_key[0]), hive, subkey);
    for (DWORD index = 0;; index++) {
        DWORD name_len = CC_MAX_NAME;
        DWORD data_len = (DWORD)(sizeof(data) - sizeof(wchar_t));
        DWORD type = 0;
        LONG result;
        size_t chars;
        bool ioc_hit;

        result = RegEnumValueW(key, index, name, &name_len, NULL, &type,
                               (BYTE *)data, &data_len);
        if (result != ERROR_SUCCESS) {
            break;
        }
        name[CC_MAX_NAME - 1] = L'\0';
        chars = cc_reg_data_len(data_len,
                                sizeof(data) / sizeof(data[0]));
        data[chars] = L'\0';
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            continue;
        }
        ioc_hit = false;
        if (ioc != NULL) {
            ioc_hit = cc_ioc_match_proc(ioc, name, data, NULL);
        }
        if (!ioc_hit && !cc_suspicious_path(data)) {
            continue;
        }
        cc_reason(reason, sizeof(reason), full_key, NULL, data);
        count = cc_emit(out, cap, count,
                        ioc_hit ? CC_RISK_CRITICAL : CC_RISK_HIGH,
                        name, reason);
        if (out == NULL || count >= cap) {
            break;
        }
    }
    RegCloseKey(key);
    return count;
}

static void cc_extract_image(const wchar_t *image, wchar_t *dst, size_t cap)
{
    const wchar_t *start;
    const wchar_t *end;
    size_t len;

    if (cap == 0) {
        return;
    }
    dst[0] = L'\0';
    if (image == NULL) {
        return;
    }
    start = image;
    while (*start == L' ' || *start == L'\t') {
        start++;
    }
    if (*start == L'"') {
        start++;
        end = wcschr(start, L'"');
        if (end == NULL) {
            end = start + wcslen(start);
        }
    } else {
        end = start;
        while (*end != L'\0' && *end != L' ' && *end != L'\t') {
            end++;
        }
    }
    len = (size_t)(end - start);
    if (len > cap - 1) {
        len = cap - 1;
    }
    wmemcpy(dst, start, len);
    dst[len] = L'\0';
}

static int cc_scan_services(const struct cc_ioc_s *ioc, cc_alert_t *out,
                            int cap, int count)
{
    static const wchar_t *const subkey =
        L"SYSTEM\\CurrentControlSet\\Services";
    static const wchar_t *const full_key =
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services";
    wchar_t name[CC_MAX_NAME];
    wchar_t image[CC_MAX_PATH_LEN];
    wchar_t exe[CC_MAX_PATH_LEN];
    wchar_t entry_key[CC_MAX_PATH_LEN];
    char reason[CC_MAX_REASON];
    HKEY root = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                      KEY_ENUMERATE_SUB_KEYS, &root) != ERROR_SUCCESS) {
        return count;
    }
    for (DWORD index = 0;; index++) {
        DWORD name_len = CC_MAX_NAME;
        DWORD data_len = (DWORD)(sizeof(image) - sizeof(wchar_t));
        DWORD type = 0;
        LONG result;
        size_t chars;
        bool ioc_hit;

        result = RegEnumKeyExW(root, index, name, &name_len, NULL,
                               NULL, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            break;
        }
        name[CC_MAX_NAME - 1] = L'\0';
        HKEY service = NULL;
        if (RegOpenKeyExW(root, name, 0, KEY_QUERY_VALUE, &service)
                != ERROR_SUCCESS) {
            continue;
        }
        result = RegQueryValueExW(service, L"ImagePath", NULL, &type,
                                  (BYTE *)image, &data_len);
        RegCloseKey(service);
        if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            continue;
        }
        chars = cc_reg_data_len(data_len,
                                sizeof(image) / sizeof(image[0]));
        image[chars] = L'\0';
        cc_extract_image(image, exe, sizeof(exe) / sizeof(exe[0]));
        ioc_hit = false;
        if (ioc != NULL) {
            ioc_hit = cc_ioc_match_service(ioc, name, exe);
        }
        if (!ioc_hit) {
            if (cc_wends_with_i(exe, L".sys") || !cc_suspicious_path(exe)) {
                continue;
            }
        }
        cc_join_key(entry_key, sizeof(entry_key) / sizeof(entry_key[0]),
                    full_key, name);
        cc_reason(reason, sizeof(reason), entry_key, L"ImagePath", image);
        count = cc_emit(out, cap, count,
                        ioc_hit ? CC_RISK_CRITICAL : CC_RISK_HIGH, name, reason);
        if (out == NULL || count >= cap) {
            break;
        }
    }
    RegCloseKey(root);
    return count;
}

static int cc_scan_ifeo(cc_alert_t *out, int cap, int count)
{
    static const wchar_t *const subkey =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        L"Image File Execution Options";
    static const wchar_t *const full_key =
        L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        L"Image File Execution Options";
    wchar_t name[CC_MAX_NAME];
    wchar_t debugger[CC_MAX_PATH_LEN];
    wchar_t entry_key[CC_MAX_PATH_LEN];
    char reason[CC_MAX_REASON];
    HKEY root = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                      KEY_ENUMERATE_SUB_KEYS, &root) != ERROR_SUCCESS) {
        return count;
    }
    for (DWORD index = 0;; index++) {
        DWORD name_len = CC_MAX_NAME;
        DWORD data_len = (DWORD)(sizeof(debugger) - sizeof(wchar_t));
        DWORD type = 0;
        LONG result;
        size_t chars;

        result = RegEnumKeyExW(root, index, name, &name_len, NULL,
                               NULL, NULL, NULL);
        if (result != ERROR_SUCCESS) {
            break;
        }
        name[CC_MAX_NAME - 1] = L'\0';
        HKEY entry = NULL;
        if (RegOpenKeyExW(root, name, 0, KEY_QUERY_VALUE, &entry)
                != ERROR_SUCCESS) {
            continue;
        }
        result = RegQueryValueExW(entry, L"Debugger", NULL, &type,
                                  (BYTE *)debugger, &data_len);
        RegCloseKey(entry);
        if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
            continue;
        }
        chars = cc_reg_data_len(data_len,
                                sizeof(debugger) / sizeof(debugger[0]));
        debugger[chars] = L'\0';
        if (debugger[0] == L'\0') {
            continue;
        }
        cc_join_key(entry_key, sizeof(entry_key) / sizeof(entry_key[0]),
                    full_key, name);
        cc_reason(reason, sizeof(reason), entry_key, L"Debugger", debugger);
        count = cc_emit(out, cap, count, CC_RISK_HIGH, name, reason);
        if (out == NULL || count >= cap) {
            break;
        }
    }
    RegCloseKey(root);
    return count;
}

static int cc_check_required(HKEY key, const wchar_t *full_key,
                             const wchar_t *value_name,
                             const wchar_t *required,
                             cc_alert_t *out, int cap, int count)
{
    wchar_t data[CC_MAX_PATH_LEN];
    DWORD data_len = (DWORD)(sizeof(data) - sizeof(wchar_t));
    DWORD type = 0;
    LONG result;
    size_t chars;
    char reason[CC_MAX_REASON];

    result = RegQueryValueExW(key, value_name, NULL, &type,
                              (BYTE *)data, &data_len);
    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return count;
    }
    chars = cc_reg_data_len(data_len,
                            sizeof(data) / sizeof(data[0]));
    data[chars] = L'\0';
    if (cc_wcontains_i(data, required)) {
        return count;
    }
    cc_reason(reason, sizeof(reason), full_key, value_name, data);
    return cc_emit(out, cap, count, CC_RISK_CRITICAL, value_name, reason);
}

static int cc_scan_winlogon(cc_alert_t *out, int cap, int count)
{
    static const wchar_t *const subkey =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    static const wchar_t *const full_key =
        L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    wchar_t notify[CC_MAX_PATH_LEN];
    DWORD data_len = (DWORD)(sizeof(notify) - sizeof(wchar_t));
    DWORD type = 0;
    LONG result;
    size_t chars;
    char reason[CC_MAX_REASON];
    HKEY key = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &key)
            != ERROR_SUCCESS) {
        return count;
    }
    count = cc_check_required(key, full_key, L"Shell", L"explorer.exe",
                              out, cap, count);
    count = cc_check_required(key, full_key, L"Userinit", L"userinit.exe",
                              out, cap, count);
    result = RegQueryValueExW(key, L"Notify", NULL, &type,
                              (BYTE *)notify, &data_len);
    if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        chars = cc_reg_data_len(data_len,
                                sizeof(notify) / sizeof(notify[0]));
        notify[chars] = L'\0';
        if (notify[0] != L'\0') {
            cc_reason(reason, sizeof(reason), full_key, L"Notify", notify);
            count = cc_emit(out, cap, count, CC_RISK_CRITICAL,
                            L"Notify", reason);
        }
    }
    RegCloseKey(key);
    return count;
}

static int cc_scan_known_dlls(cc_alert_t *out, int cap, int count)
{
    static const wchar_t *const subkey =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";
    static const wchar_t *const full_key =
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";
    wchar_t name[CC_MAX_NAME];
    wchar_t data[CC_MAX_PATH_LEN];
    char reason[CC_MAX_REASON];
    HKEY key = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE, &key)
            != ERROR_SUCCESS) {
        return count;
    }
    for (DWORD index = 0;; index++) {
        DWORD name_len = CC_MAX_NAME;
        DWORD data_len = (DWORD)(sizeof(data) - sizeof(wchar_t));
        DWORD type = 0;
        LONG result;
        size_t chars;

        result = RegEnumValueW(key, index, name, &name_len, NULL, &type,
                               (BYTE *)data, &data_len);
        if (result != ERROR_SUCCESS) {
            break;
        }
        name[CC_MAX_NAME - 1] = L'\0';
        chars = cc_reg_data_len(data_len,
                                sizeof(data) / sizeof(data[0]));
        data[chars] = L'\0';
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            continue;
        }
        if (!cc_wcontains_i(data, L"\\") || cc_wcontains_i(data, L"system32")) {
            continue;
        }
        cc_reason(reason, sizeof(reason), full_key, NULL, data);
        count = cc_emit(out, cap, count, CC_RISK_HIGH, name, reason);
        if (out == NULL || count >= cap) {
            break;
        }
    }
    RegCloseKey(key);
    return count;
}

int cc_registry_scan(const struct cc_ioc_s *ioc, cc_alert_t *out, int cap,
                      ULONGLONG deadline)
{
    static const wchar_t *const run_paths[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    static const HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    static const wchar_t *const hives[] = { L"HKLM", L"HKCU" };
    int count = 0;

    if (out == NULL || cap <= 0) {
        return 0;
    }
    for (size_t r = 0; r < sizeof(roots) / sizeof(roots[0]); r++) {
        for (size_t p = 0; p < sizeof(run_paths) / sizeof(run_paths[0]); p++) {
            if (GetTickCount64() >= deadline) {
                return count;
            }
            count = cc_scan_run_key(roots[r], hives[r], run_paths[p], ioc,
                                    out, cap, count);
            if (count >= cap) {
                return count;
            }
        }
    }
    if (GetTickCount64() >= deadline) return count;
    count = cc_scan_services(ioc, out, cap, count);
    if (count >= cap || GetTickCount64() >= deadline) {
        return count;
    }
    count = cc_scan_ifeo(out, cap, count);
    if (count >= cap || GetTickCount64() >= deadline) {
        return count;
    }
    count = cc_scan_winlogon(out, cap, count);
    if (count >= cap || GetTickCount64() >= deadline) {
        return count;
    }
    count = cc_scan_known_dlls(out, cap, count);
    return count;
}
