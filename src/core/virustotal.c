#include "virustotal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <winhttp.h>

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 8
#endif

#define CC_VT_KEY_LEN 256
#define CC_VT_CACHE_MAX 4096
#define CC_VT_RATE_MAX 64
#define CC_VT_BODY_MAX 1048576u

typedef struct {
    char hash[65];
    char hits;
    char total;
} cc_vt_cache_entry_t;

static char vt_key[CC_VT_KEY_LEN];
static int vt_rpm = 4;
static bool vt_disabled = true;
static bool vt_session_disabled = false;
static bool vt_cache_loaded = false;
static cc_vt_cache_entry_t vt_cache[CC_VT_CACHE_MAX];
static size_t vt_cache_count = 0;
static time_t vt_requests[CC_VT_RATE_MAX];
static size_t vt_request_count = 0;

static void cc_vt_load_cache(void)
{
    if (vt_cache_loaded) {
        return;
    }
    vt_cache_loaded = true;
    vt_cache_count = 0;
}

static void cc_vt_cache_add(const char *hash, char hits, char total)
{
    size_t i;

    for (i = 0; i < vt_cache_count; i++) {
        if (strcmp(vt_cache[i].hash, hash) == 0) {
            break;
        }
    }
    if (i < vt_cache_count) {
        vt_cache[i].hits = hits;
        vt_cache[i].total = total;
    } else if (vt_cache_count < CC_VT_CACHE_MAX) {
        memcpy(vt_cache[vt_cache_count].hash, hash, sizeof(vt_cache[0].hash));
        vt_cache[vt_cache_count].hits = hits;
        vt_cache[vt_cache_count].total = total;
        vt_cache_count++;
    }
}

static bool cc_vt_rate_limit(void)
{
    time_t now = time(NULL);
    int limit = vt_rpm;
    int attempt;

    if (limit <= 0) {
        return true;
    }
    if (limit > CC_VT_RATE_MAX) {
        limit = CC_VT_RATE_MAX;
    }
    for (attempt = 0; attempt < 3; attempt++) {
        size_t kept = 0;
        size_t i;

        for (i = 0; i < vt_request_count; i++) {
            if (difftime(now, vt_requests[i]) < 60.0) {
                vt_requests[kept++] = vt_requests[i];
            }
        }
        vt_request_count = kept;
        if (vt_request_count < (size_t)limit) {
            break;
        }
        {
            double wait = 60.0 - difftime(now, vt_requests[0]);
            if (wait > 15.0) {
                return false;
            }
            if (wait < 0.0) {
                wait = 0.0;
            }
            Sleep((DWORD)(wait * 1000.0) + 100);
            now = time(NULL);
        }
    }
    if (vt_request_count >= (size_t)limit) {
        return false;
    }
    if (vt_request_count < CC_VT_RATE_MAX) {
        vt_requests[vt_request_count++] = now;
    } else {
        memmove(&vt_requests[0], &vt_requests[1],
                (CC_VT_RATE_MAX - 1) * sizeof(vt_requests[0]));
        vt_requests[CC_VT_RATE_MAX - 1] = now;
    }
    return true;
}

static long cc_vt_parse_number(const char *p, const char *end, const char **next)
{
    char *stop = NULL;
    long value;

    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    if (p >= end || *p < '0' || *p > '9') {
        *next = p;
        return -1;
    }
    value = strtol(p, &stop, 10);
    *next = stop > end ? end : stop;
    return value;
}

static bool cc_vt_parse_stats(const char *body, char *hits, char *total)
{
    const char *stats = strstr(body, "last_analysis_stats");
    const char *open;
    const char *close;
    const char *p;
    long h = 0;
    long t = 0;
    bool got_stats = false;
    bool got_hits = false;

    if (stats == NULL) {
        return false;
    }
    open = strchr(stats, '{');
    if (open == NULL) {
        return false;
    }
    close = strchr(open, '}');
    if (close == NULL) {
        return false;
    }
    p = open + 1;
    while (p < close) {
        const char *key = strchr(p, '"');
        const char *key_end;
        const char *colon;
        const char *next;
        long value;

        if (key == NULL || key >= close) {
            break;
        }
        key_end = strchr(key + 1, '"');
        if (key_end == NULL || key_end >= close) {
            break;
        }
        colon = strchr(key_end + 1, ':');
        if (colon == NULL || colon >= close) {
            break;
        }
        value = cc_vt_parse_number(colon + 1, close, &next);
        if (value < 0) {
            p = colon + 1;
            continue;
        }
        if ((size_t)(key_end - key - 1) == 9 &&
            strncmp(key + 1, "malicious", 9) == 0) {
            h = value;
            got_hits = true;
        }
        if (t < 127) {
            t += value;
            if (t > 127) {
                t = 127;
            }
        }
        got_stats = true;
        p = next > p ? next : colon + 1;
    }
    if (!got_stats) {
        return false;
    }
    *hits = (char)(got_hits ? h : 0);
    *total = (char)t;
    return true;
}

static bool cc_vt_request(const wchar_t *hash, char *hits, char *total)
{
    HINTERNET session = NULL;
    HINTERNET connect = NULL;
    HINTERNET request = NULL;
    wchar_t key_w[CC_VT_KEY_LEN];
    wchar_t resource[128];
    wchar_t header[CC_VT_KEY_LEN + 32];
    char *body = NULL;
    size_t len = 0;
    size_t cap = 8192;
    DWORD status = 0;
    DWORD status_len = sizeof(status);
    bool ok = false;

    if (MultiByteToWideChar(CP_UTF8, 0, vt_key, -1, key_w, CC_VT_KEY_LEN) == 0 ||
        wcslen(hash) + 20 >= 128) {
        goto done;
    }
    wcscpy(resource, L"/api/v3/files/");
    wcscat(resource, hash);
    wcscpy(header, L"x-apikey: ");
    wcscat(header, key_w);

    session = WinHttpOpen(L"cleaner-c/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL) {
        goto done;
    }
    (void)WinHttpSetTimeouts(session, 10000, 10000, 10000, 10000);
    connect = WinHttpConnect(session, L"www.virustotal.com",
                             INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connect == NULL) {
        goto done;
    }
    request = WinHttpOpenRequest(connect, L"GET", resource, NULL,
                                 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 WINHTTP_FLAG_SECURE);
    if (request == NULL) {
        goto done;
    }
    {
        DWORD ssl_feature = WINHTTP_ENABLE_SSL_REVOCATION;
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        (void)WinHttpSetOption(request, WINHTTP_OPTION_SECURE_PROTOCOLS,
                               &protocols, sizeof(protocols));
        (void)WinHttpSetOption(request, WINHTTP_OPTION_ENABLE_FEATURE,
                               &ssl_feature, sizeof(ssl_feature));
    }
    if (!WinHttpAddRequestHeaders(request, header, (DWORD)wcslen(header),
                                  WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
        goto done;
    }
    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, NULL)) {
        goto done;
    }
    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
                             WINHTTP_NO_HEADER_INDEX)) {
        goto done;
    }
    if (status == 401 || status == 403) {
        vt_session_disabled = true;
        goto done;
    }
    if (status == 404) {
        *hits = 0;
        *total = 0;
        ok = true;
        goto done;
    }
    if (status != 200) {
        goto done;
    }
    body = (char *)malloc(cap);
    if (body == NULL) {
        goto done;
    }
    for (;;) {
        DWORD available = 0;
        DWORD read = 0;

        if (!WinHttpQueryDataAvailable(request, &available)) {
            goto done;
        }
        if (available == 0) {
            break;
        }
        if ((size_t)available > CC_VT_BODY_MAX - len - 1) {
            goto done;
        }
        if (len + (size_t)available + 1 > cap) {
            size_t new_cap = cap;
            char *tmp;

            while (new_cap < len + (size_t)available + 1 && new_cap < CC_VT_BODY_MAX) {
                new_cap *= 2;
            }
            if (new_cap > CC_VT_BODY_MAX) {
                new_cap = CC_VT_BODY_MAX;
            }
            tmp = (char *)realloc(body, new_cap);
            if (tmp == NULL) {
                goto done;
            }
            body = tmp;
            cap = new_cap;
        }
        if (!WinHttpReadData(request, body + len, available, &read)) {
            goto done;
        }
        if (read == 0) {
            break;
        }
        len += read;
    }
    body[len] = '\0';
    ok = cc_vt_parse_stats(body, hits, total);

done:
    free(body);
    if (request != NULL) {
        WinHttpCloseHandle(request);
    }
    if (connect != NULL) {
        WinHttpCloseHandle(connect);
    }
    if (session != NULL) {
        WinHttpCloseHandle(session);
    }
    return ok;
}

void cc_virustotal_configure(const char *api_key, int requests_per_minute)
{
    const char *key = api_key;
    size_t n;

    if (key == NULL || key[0] == '\0') {
        key = getenv("VT_API_KEY");
    }
    memset(vt_key, 0, sizeof(vt_key));
    vt_disabled = true;
    if (key != NULL && key[0] != '\0') {
        n = strlen(key);
        if (n >= sizeof(vt_key)) {
            n = sizeof(vt_key) - 1;
        }
        memcpy(vt_key, key, n);
        vt_disabled = false;
    }
    vt_rpm = requests_per_minute > 0 ? requests_per_minute : 4;
    vt_session_disabled = false;
    vt_request_count = 0;
}

void cc_virustotal_reset(void)
{
    memset(vt_cache, 0, sizeof(vt_cache));
    vt_cache_count = 0;
    vt_cache_loaded = false;
    vt_request_count = 0;
    vt_session_disabled = false;
}

bool cc_virustotal_lookup(const char *sha256, cc_trust_result_t *out)
{
    char key[65];
    wchar_t hash[65];
    size_t i;
    char hits = -1;
    char total = -1;

    if (out == NULL) {
        return false;
    }
    out->virustotal_hits = -1;
    out->virustotal_total = -1;
    if (vt_disabled || vt_session_disabled || sha256 == NULL || strlen(sha256) != 64) {
        return false;
    }
    for (i = 0; i < 64; i++) {
        char c = sha256[i];
        if (c >= 'A' && c <= 'F') {
            c = (char)(c - 'A' + 'a');
        }
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
        key[i] = c;
    }
    key[64] = '\0';

    cc_vt_load_cache();
    for (i = 0; i < vt_cache_count; i++) {
        if (strcmp(vt_cache[i].hash, key) == 0) {
            out->virustotal_hits = vt_cache[i].hits;
            out->virustotal_total = vt_cache[i].total;
            return true;
        }
    }
    if (!cc_vt_rate_limit() ||
        MultiByteToWideChar(CP_UTF8, 0, key, -1, hash, 65) == 0 ||
        !cc_vt_request(hash, &hits, &total)) {
        return false;
    }
    out->virustotal_hits = hits;
    out->virustotal_total = total;
    cc_vt_cache_add(key, hits, total);
    return true;
}
