#include "eventlog_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<wevtapi.h>)
#    include <wevtapi.h>
#    define CC_HAVE_WEVTAPI_HEADER 1
#  endif
#endif

#ifndef CC_HAVE_WEVTAPI_HEADER
typedef void *EVT_HANDLE;
typedef EVT_HANDLE *PEVT_HANDLE;

enum {
    EvtQueryChannelPath = 0x1,
    EvtQueryReverseDirection = 0x200,
    EvtRenderEventXml = 0x1
};

EVT_HANDLE WINAPI EvtQuery(EVT_HANDLE session, LPCWSTR path, LPCWSTR query,
                           DWORD flags);
BOOL WINAPI EvtNext(EVT_HANDLE results, DWORD size, PEVT_HANDLE events,
                    DWORD timeout, DWORD flags, PDWORD returned);
BOOL WINAPI EvtRender(EVT_HANDLE context, EVT_HANDLE fragment, DWORD flags,
                      DWORD buffer_size, PVOID buffer, PDWORD buffer_used,
                      PDWORD property_count);
BOOL WINAPI EvtClose(EVT_HANDLE object);
#endif

#define CC_EVT_XML_LIMIT (4u * 1024u * 1024u)
#define CC_EVT_BAD_PATTERN_COUNT 7

static int cc_emit(cc_alert_t *out, int cap, int count, cc_risk_t risk,
                   const wchar_t *target, const char *reason)
{
    cc_alert_t *alert;

    if (out == NULL || cap <= 0 || count < 0 || count >= cap) {
        return count;
    }
    alert = &out[count];
    alert->risk = risk;
    snprintf(alert->category, sizeof(alert->category), "%s", "eventlog");
    wcsncpy(alert->target, target != NULL ? target : L"", CC_MAX_NAME - 1);
    alert->target[CC_MAX_NAME - 1] = L'\0';
    snprintf(alert->reason, sizeof(alert->reason), "%s",
             reason != NULL ? reason : "");
    alert->pid = 0;
    return count + 1;
}

static char cc_lower_char(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

static const char *cc_strcasestr(const char *s, const char *needle)
{
    size_t i;

    if (s == NULL || needle == NULL || needle[0] == '\0') {
        return NULL;
    }
    for (; *s != '\0'; s++) {
        for (i = 0; needle[i] != '\0' && s[i] != '\0'; i++) {
            if (cc_lower_char(s[i]) != cc_lower_char(needle[i])) {
                break;
            }
        }
        if (needle[i] == '\0') {
            return s;
        }
    }
    return NULL;
}

static bool cc_contains_i(const char *s, const char *needle)
{
    return cc_strcasestr(s, needle) != NULL;
}

static bool cc_ends_with_i(const char *s, const char *suffix)
{
    size_t n;
    size_t m;

    if (s == NULL || suffix == NULL) {
        return false;
    }
    n = strlen(s);
    m = strlen(suffix);
    if (m > n) {
        return false;
    }
    for (size_t i = 0; i < m; i++) {
        if (cc_lower_char(s[n - m + i]) != cc_lower_char(suffix[i])) {
            return false;
        }
    }
    return true;
}

static bool cc_mem_contains(const char *hay, size_t length,
                            const char *needle, size_t needle_len)
{
    if (needle_len > length) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= length; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool cc_event_id_is(const char *xml, int id)
{
    const char *p;

    if (xml == NULL) {
        return false;
    }
    p = xml;
    while ((p = strstr(p, "<EventID")) != NULL) {
        const char *gt = strchr(p, '>');
        const char *end;
        const char *start;
        const char *finish;
        size_t length;
        char number[16];

        if (gt == NULL) {
            break;
        }
        end = strstr(gt + 1, "</EventID>");
        if (end == NULL) {
            break;
        }
        start = gt + 1;
        finish = end;
        while (start < finish && (*start == ' ' || *start == '\t' ||
                                  *start == '\r' || *start == '\n')) {
            start++;
        }
        while (finish > start && (finish[-1] == ' ' || finish[-1] == '\t' ||
                                  finish[-1] == '\r' || finish[-1] == '\n')) {
            finish--;
        }
        length = (size_t)(finish - start);
        if (length > 0 && length < sizeof(number)) {
            memcpy(number, start, length);
            number[length] = '\0';
            if (atoi(number) == id) {
                return true;
            }
        }
        p = end;
    }
    return false;
}

static void cc_xml_unescape(char *text)
{
    char *dst;
    const char *p;

    if (text == NULL) {
        return;
    }
    dst = text;
    p = text;
    while (*p != '\0') {
        if (p[0] == '&') {
            if (strncmp(p, "&amp;", 5) == 0) {
                *dst++ = '&';
                p += 5;
                continue;
            }
            if (strncmp(p, "&quot;", 6) == 0) {
                *dst++ = '"';
                p += 6;
                continue;
            }
            if (strncmp(p, "&apos;", 6) == 0) {
                *dst++ = '\'';
                p += 6;
                continue;
            }
            if (strncmp(p, "&lt;", 4) == 0) {
                *dst++ = '<';
                p += 4;
                continue;
            }
            if (strncmp(p, "&gt;", 4) == 0) {
                *dst++ = '>';
                p += 4;
                continue;
            }
            if (strncmp(p, "&#39;", 5) == 0) {
                *dst++ = '\'';
                p += 5;
                continue;
            }
        }
        *dst++ = *p++;
    }
    *dst = '\0';
}

static void cc_copy_value(const char *start, const char *end,
                          char *out, size_t cap)
{
    size_t length;

    length = (size_t)(end - start);
    if (length > cap - 1) {
        length = cap - 1;
    }
    memcpy(out, start, length);
    out[length] = '\0';
    cc_xml_unescape(out);
}

static void cc_extract_data(const char *xml, const char *name,
                            char *out, size_t cap)
{
    char attr[128];
    char attr_single[128];
    char open_tag[128];
    char close_tag[128];
    const char *p;

    out[0] = '\0';
    if (xml == NULL || name == NULL || cap == 0) {
        return;
    }
    snprintf(attr, sizeof(attr), "Name=\"%s\"", name);
    snprintf(attr_single, sizeof(attr_single), "Name='%s'", name);
    p = xml;
    while ((p = strstr(p, "<Data")) != NULL) {
        const char *gt = strchr(p, '>');
        const char *end;

        if (gt == NULL) {
            break;
        }
        if (cc_mem_contains(p, (size_t)(gt - p), attr, strlen(attr)) ||
            cc_mem_contains(p, (size_t)(gt - p), attr_single,
                            strlen(attr_single))) {
            end = strstr(gt + 1, "</Data>");
            if (end != NULL) {
                cc_copy_value(gt + 1, end, out, cap);
                return;
            }
        }
        p = gt + 1;
    }
    snprintf(open_tag, sizeof(open_tag), "<%s>", name);
    snprintf(close_tag, sizeof(close_tag), "</%s>", name);
    p = strstr(xml, open_tag);
    if (p != NULL) {
        const char *value = p + strlen(open_tag);
        const char *end = strstr(value, close_tag);

        if (end != NULL) {
            cc_copy_value(value, end, out, cap);
        }
    }
}

static char *cc_event_xml(EVT_HANDLE event)
{
    DWORD needed = 0;
    DWORD used = 0;
    DWORD properties = 0;
    wchar_t *raw;
    char *text;
    int chars;

    if (EvtRender(NULL, event, EvtRenderEventXml, 0, NULL,
                  &needed, &properties) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed == 0 || needed > CC_EVT_XML_LIMIT) {
        return NULL;
    }
    raw = (wchar_t *)malloc(needed);
    if (raw == NULL) {
        return NULL;
    }
    if (!EvtRender(NULL, event, EvtRenderEventXml, needed, raw,
                   &used, &properties)) {
        free(raw);
        return NULL;
    }
    (void)used;
    chars = WideCharToMultiByte(CP_UTF8, 0, raw, -1, NULL, 0, NULL, NULL);
    if (chars <= 0) {
        free(raw);
        return NULL;
    }
    text = (char *)malloc((size_t)chars);
    if (text != NULL &&
        WideCharToMultiByte(CP_UTF8, 0, raw, -1, text, chars,
                            NULL, NULL) <= 0) {
        free(text);
        text = NULL;
    }
    free(raw);
    return text;
}

static bool cc_suspicious_image(const char *image)
{
    static const char *const dirs[5] = {
        "\\temp\\", "\\appdata\\", "\\users\\public\\",
        "\\programdata\\", "\\$recycle.bin\\"
    };
    static const char *const tails[5] = {
        "\\temp", "\\appdata", "\\users\\public",
        "\\programdata", "\\$recycle.bin"
    };

    if (image == NULL || image[0] == '\0') {
        return false;
    }
    for (size_t i = 0; i < 5; i++) {
        if (cc_contains_i(image, dirs[i]) || cc_ends_with_i(image, tails[i])) {
            return true;
        }
    }
    return false;
}

static int cc_process_event(int kind, const char *xml,
                            cc_alert_t *out, int cap, int count)
{
    char reason[CC_MAX_REASON];

    if (kind == 0) {
        static const char *const patterns[CC_EVT_BAD_PATTERN_COUNT] = {
            "-enc", "-nop", "frombase64", "certutil -urlcache",
            "bitsadmin /transfer", "mshta http", "regsvr32 /s /n /u"
        };
        char command[CC_MAX_REASON];

        if (cc_event_id_is(xml, 1102)) {
            snprintf(reason, sizeof(reason), "%s",
                     "Security 1102: audit log cleared");
            return cc_emit(out, cap, count, CC_RISK_CRITICAL,
                           L"Security", reason);
        }
        if (cc_event_id_is(xml, 4688)) {
            cc_extract_data(xml, "CommandLine", command, sizeof(command));
            for (size_t i = 0; i < CC_EVT_BAD_PATTERN_COUNT; i++) {
                if (cc_contains_i(command, patterns[i])) {
                    snprintf(reason, sizeof(reason),
                             "Security 4688 suspicious CommandLine: %.200s",
                             command);
                    return cc_emit(out, cap, count, CC_RISK_MEDIUM,
                                   L"Security", reason);
                }
            }
        }
    } else if (kind == 1) {
        static const int ids[] = { 1006, 1007, 1116, 1117 };
        char threat[256];
        int id = 0;

        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            if (cc_event_id_is(xml, ids[i])) {
                id = ids[i];
                break;
            }
        }
        if (id == 0) {
            return count;
        }
        threat[0] = '\0';
        cc_extract_data(xml, "Threat Name", threat, sizeof(threat));
        if (threat[0] == '\0') {
            cc_extract_data(xml, "ThreatName", threat, sizeof(threat));
        }
        if (threat[0] != '\0') {
            snprintf(reason, sizeof(reason),
                     "Windows Defender %d: Threat Name: %s", id, threat);
        } else {
            snprintf(reason, sizeof(reason),
                     "Windows Defender %d: malware detected or blocked", id);
        }
        return cc_emit(out, cap, count, CC_RISK_CRITICAL,
                       L"Defender", reason);
    } else {
        char image[CC_MAX_PATH_LEN];

        if (!cc_event_id_is(xml, 1)) {
            return count;
        }
        cc_extract_data(xml, "Image", image, sizeof(image));
        if (!cc_suspicious_image(image)) {
            return count;
        }
        snprintf(reason, sizeof(reason),
                 "Sysmon 1 process create from suspicious path: %s", image);
        return cc_emit(out, cap, count, CC_RISK_MEDIUM, L"Sysmon", reason);
    }
    return count;
}

static int cc_scan_channel(int kind, const wchar_t *channel,
                            const wchar_t *xpath, uint32_t bit,
                            uint32_t *mask, cc_alert_t *out,
                            int cap, int count, ULONGLONG deadline)
{
    EVT_HANDLE query;

    query = EvtQuery(NULL, channel, xpath,
                     EvtQueryChannelPath | EvtQueryReverseDirection);
    if (query == NULL) {
        return count;
    }
    if (mask != NULL) {
        *mask |= bit;
    }
    for (;;) {
        EVT_HANDLE event = NULL;
        DWORD returned = 0;
        char *xml;

        if (GetTickCount64() >= deadline) {
            break;
        }
        if (!EvtNext(query, 1, &event, 0, 0, &returned) ||
            returned == 0 || event == NULL) {
            break;
        }
        xml = cc_event_xml(event);
        EvtClose(event);
        if (xml != NULL) {
            count = cc_process_event(kind, xml, out, cap, count);
            free(xml);
        }
        if (out != NULL && count >= cap) {
            break;
        }
    }
    EvtClose(query);
    return count;
}

int cc_eventlog_scan(int minutes, cc_alert_t *out, int cap,
                      uint32_t *available_mask, ULONGLONG deadline)
{
    wchar_t xpath[160];
    int mins = minutes > 0 ? minutes : 1;
    int count = 0;

    if (available_mask != NULL) {
        *available_mask = 0;
    }
    if (out == NULL || cap <= 0) {
        return 0;
    }
    swprintf(xpath, sizeof(xpath) / sizeof(xpath[0]),
             L"*[System[TimeCreated[timediff(@SystemTime)<=%lld]]]",
             (long long)mins * 60000LL);
    count = cc_scan_channel(0, L"Security", xpath, CC_EVT_SECURITY,
                             available_mask, out, cap, count, deadline);
    if (count >= cap) {
        return count;
    }
    count = cc_scan_channel(1,
                            L"Microsoft-Windows-Windows Defender/Operational",
                            xpath, CC_EVT_DEFENDER, available_mask,
                            out, cap, count, deadline);
    if (count >= cap) {
        return count;
    }
    count = cc_scan_channel(2, L"Microsoft-Windows-Sysmon/Operational",
                             xpath, CC_EVT_SYSMON, available_mask,
                             out, cap, count, deadline);
    return count;
}
