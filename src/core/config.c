#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
#include "config.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "json.h"
#include "virustotal.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static bool cc_path_join(wchar_t *dst, size_t cap, const wchar_t *dir,
                         const wchar_t *name)
{
    size_t dir_len;
    size_t name_len;
    bool sep;
    size_t i;
    size_t k;
    size_t need;

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
    i = 0;
    for (k = 0; k < dir_len; k++) {
        dst[i++] = dir[k];
    }
    if (!sep) {
        dst[i++] = L'\\';
    }
    for (k = 0; k < name_len; k++) {
        dst[i++] = name[k];
    }
    dst[i] = L'\0';
    return true;
}

bool cc_exe_dir(wchar_t *out, size_t cap)
{
    DWORD n;
    size_t i;

    if (out == NULL || cap == 0) {
        return false;
    }
    out[0] = L'\0';
    if (cap > (size_t)0x7FFFFFFF) {
        cap = (size_t)0x7FFFFFFF;
    }
    n = GetModuleFileNameW(NULL, out, (DWORD)cap);
    if (n == 0 || (size_t)n >= cap) {
        out[0] = L'\0';
        return false;
    }
    i = (size_t)n;
    while (i > 0 && out[i - 1] != L'\\' && out[i - 1] != L'/') {
        i--;
    }
    if (i == 0) {
        out[0] = L'\0';
        return false;
    }
    if (i == 3 && out[1] == L':') {
        out[3] = L'\0';
    } else {
        out[i - 1] = L'\0';
    }
    return true;
}

static bool cc_cfg_double(const cc_json_t *j, const char *const *keys, int count,
                          double *out)
{
    int i;

    if (j == NULL || out == NULL) {
        return false;
    }
    for (i = 0; i < count; i++) {
        if (cc_json_get_double(j, keys[i], out) && isfinite(*out)) {
            return true;
        }
    }
    return false;
}

static bool cc_cfg_u64(const cc_json_t *j, const char *const *keys, int count,
                       uint64_t *out)
{
    double value;

    if (out == NULL || !cc_cfg_double(j, keys, count, &value)) {
        return false;
    }
    if (value < 0.0 || value > (double)UINT64_MAX) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static bool cc_cfg_u32(const cc_json_t *j, const char *const *keys, int count,
                       uint32_t *out)
{
    double value;

    if (out == NULL || !cc_cfg_double(j, keys, count, &value)) {
        return false;
    }
    if (value < 0.0 || value > (double)UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool cc_cfg_bool(const cc_json_t *j, const char *const *keys, int count,
                        bool *out)
{
    int i;

    if (j == NULL || out == NULL) {
        return false;
    }
    for (i = 0; i < count; i++) {
        if (cc_json_get_bool(j, keys[i], out)) {
            return true;
        }
    }
    return false;
}

static void cc_copy_key(char *dst, size_t cap, const char *src)
{
    size_t start = 0;
    size_t end;
    size_t n;
    size_t i;

    if (dst == NULL || cap == 0 || src == NULL) {
        return;
    }
    end = strlen(src);
    while (start < end && (src[start] == ' ' || src[start] == '\t' ||
                           src[start] == '\r' || src[start] == '\n')) {
        start++;
    }
    while (end > start && (src[end - 1] == ' ' || src[end - 1] == '\t' ||
                           src[end - 1] == '\r' || src[end - 1] == '\n')) {
        end--;
    }
    for (i = start; i < end; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c < 0x21 || c > 0x7e) {
            dst[0] = '\0';
            return;
        }
    }
    n = end - start;
    if (n >= cap) {
        n = cap - 1;
    }
    memmove(dst, src + start, n);
    dst[n] = '\0';
}

static void cc_load_thresholds(cc_config_t *out, const wchar_t *dir)
{
    static const char *const k_cpu[] = {
        "cpu_percent_threshold", "cpu_threshold", "cpu"
    };
    static const char *const k_sustain[] = {
        "cpu_sustain_seconds", "sustain_seconds", "sustain"
    };
    static const char *const k_ram[] = {
        "ram_bytes_threshold", "ram_threshold", "ram_bytes", "ram"
    };
    static const char *const k_handles[] = {
        "handle_threshold", "handles_threshold", "handles"
    };
    static const char *const k_io[] = {
        "io_bytes_threshold", "io_threshold", "io_bytes", "io"
    };
    static const char *const k_vt_enabled[] = { "vt_enabled" };
    static const char *const k_vt_rpm[] = {
        "vt_requests_per_minute", "vt_rpm", "requests_per_minute"
    };
    static const char *const k_scan_timeout[] = {
        "scan_timeout_ms", "scan_timeout", "scan_timeout_seconds"
    };
    wchar_t path[CC_MAX_PATH_LEN];
    cc_json_t *j;

    if (!cc_path_join(path, sizeof(path) / sizeof(path[0]), dir, L"thresholds.json")) {
        return;
    }
    j = cc_json_parse_file(path);
    if (j == NULL) {
        return;
    }
    (void)cc_cfg_double(j, k_cpu, 3, &out->cpu_percent_threshold);
    (void)cc_cfg_u32(j, k_sustain, 3, &out->cpu_sustain_seconds);
    (void)cc_cfg_u64(j, k_ram, 4, &out->ram_bytes_threshold);
    (void)cc_cfg_u32(j, k_handles, 3, &out->handle_threshold);
    (void)cc_cfg_u64(j, k_io, 4, &out->io_bytes_threshold);
    (void)cc_cfg_bool(j, k_vt_enabled, 1, &out->vt_enabled);
    (void)cc_cfg_u32(j, k_vt_rpm, 3, &out->vt_requests_per_minute);
    {
        double scan_timeout = 0.0;
        if (cc_cfg_double(j, k_scan_timeout, 3, &scan_timeout) &&
            isfinite(scan_timeout) && scan_timeout > 0.0) {
            if (scan_timeout <= 1000.0) {
                scan_timeout *= 1000.0;
            }
            if (scan_timeout >= 100.0 && scan_timeout <= 60000.0) {
                out->scan_timeout_ms = (uint32_t)scan_timeout;
            }
        }
    }
    cc_json_free(j);
}

static void cc_load_local(cc_config_t *out, const wchar_t *dir)
{
    static const char *const k_key[] = { "vt_api_key", "api_key" };
    wchar_t path[CC_MAX_PATH_LEN];
    cc_json_t *j;
    const char *src = NULL;
    int i;

    if (cc_path_join(path, sizeof(path) / sizeof(path[0]), dir, L"local.json")) {
        j = cc_json_parse_file(path);
        if (j != NULL) {
            for (i = 0; i < 2; i++) {
                if (cc_json_get_str(j, k_key[i], out->vt_api_key,
                                    sizeof(out->vt_api_key))) {
                    src = out->vt_api_key;
                    break;
                }
            }
            cc_json_free(j);
        }
    }
    cc_copy_key(out->vt_api_key, sizeof(out->vt_api_key), src);
    if (out->vt_api_key[0] == L'\0') {
        const char *env = getenv("VT_API_KEY");
        cc_copy_key(out->vt_api_key, sizeof(out->vt_api_key), env);
    }
}

bool cc_config_load(cc_config_t *out, const wchar_t *config_dir)
{
    wchar_t dir[CC_MAX_PATH_LEN];
    size_t used;

    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->cpu_percent_threshold = 80.0;
    out->cpu_sustain_seconds = 10;
    out->ram_bytes_threshold = 1610612736ULL;
    out->handle_threshold = 4000;
    out->io_bytes_threshold = 524288000ULL;
    out->vt_enabled = true;
    out->vt_requests_per_minute = 4;
    out->scan_timeout_ms = 60000;

    if (config_dir != NULL && config_dir[0] != L'\0') {
        if (wcslen(config_dir) >= sizeof(dir) / sizeof(dir[0])) {
            return false;
        }
        wcscpy(dir, config_dir);
    } else {
        if (!cc_exe_dir(dir, sizeof(dir) / sizeof(dir[0]))) {
            return false;
        }
        used = wcslen(dir);
        if (used == 0 || used + 7 >= sizeof(dir) / sizeof(dir[0])) {
            return false;
        }
        if (dir[used - 1] != L'\\' && dir[used - 1] != L'/') {
            dir[used++] = L'\\';
        }
        wcscpy(dir + used, L"config");
    }
    wcscpy(out->config_dir, dir);

    cc_load_thresholds(out, dir);
    cc_load_local(out, dir);
    cc_virustotal_configure(out->vt_api_key, (int)out->vt_requests_per_minute);
    return true;
}
