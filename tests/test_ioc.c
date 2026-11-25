#include "ioc.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <wchar.h>

#define ASSERT_TRUE(cond, msg) \
    do { \
        if (!(cond)) { \
            return (msg); \
        } \
    } while (0)

#define ASSERT_EQ_INT(a, b) \
    do { \
        if ((long)(a) != (long)(b)) { \
            return "ASSERT_EQ_INT failed: " #a " != " #b; \
        } \
    } while (0)

static bool temp_file_path(const wchar_t *name, wchar_t *out, size_t cap)
{
    wchar_t dir[CC_MAX_PATH_LEN];
    DWORD n = GetTempPathW(CC_MAX_PATH_LEN, dir);
    if (n == 0 || n >= (DWORD)CC_MAX_PATH_LEN) {
        return false;
    }
    if (wcslen(dir) + wcslen(name) + 1 > cap) {
        return false;
    }
    wcscpy(out, dir);
    wcscat(out, name);
    return true;
}

static bool write_temp_file(const wchar_t *name, wchar_t *path_out, size_t cap,
                            const char *content)
{
    if (!temp_file_path(name, path_out, cap)) {
        return false;
    }
    FILE *f = _wfopen(path_out, L"w");
    if (f == NULL) {
        return false;
    }
    bool ok = fputs(content, f) >= 0;
    if (fclose(f) != 0) {
        ok = false;
    }
    return ok;
}

const char *test_ioc_load_match(void)
{
    wchar_t path[CC_MAX_PATH_LEN];
    ASSERT_TRUE(write_temp_file(L"cc_test_iocs.json", path, CC_MAX_PATH_LEN,
        "{\"process_names\":[\"xmrig.exe\",\"minerd.exe\"],"
        "\"path_substrings\":[\"\\\\AppData\\\\Local\\\\Temp\\\\\"],"
        "\"hashes_sha256\":[],"
        "\"service_names\":[\"winupdate32\"],"
        "\"service_path_substrings\":[\"\\\\Temp\\\\\"]}"),
        "create temp iocs.json");

    cc_ioc_t *ioc = cc_ioc_load(path);
    DeleteFileW(path);
    ASSERT_TRUE(ioc != NULL, "cc_ioc_load returned NULL");

    ASSERT_TRUE(cc_ioc_count(ioc) > 0, "cc_ioc_count is 0");
    ASSERT_TRUE(cc_ioc_match_proc(ioc, L"xmrig.exe", L"", ""), "no match on xmrig.exe");
    ASSERT_TRUE(!cc_ioc_match_proc(ioc, L"notepad.exe", L"", ""), "false match on notepad.exe");
    ASSERT_TRUE(cc_ioc_match_proc(ioc, L"", L"C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe", ""),
                "no match on temp path");
    ASSERT_TRUE(!cc_ioc_match_proc(ioc, L"", L"C:\\Windows\\System32\\notepad.exe", ""),
                "false match on system path");
    ASSERT_TRUE(cc_ioc_match_service(ioc, L"winupdate32", L""), "no match on service name");
    ASSERT_TRUE(!cc_ioc_match_service(ioc, L"Spooler", L""), "false match on Spooler");

    cc_ioc_free(ioc);
    return NULL;
}

const char *test_ioc_publishers(void)
{
    wchar_t path[CC_MAX_PATH_LEN];
    ASSERT_TRUE(write_temp_file(L"cc_test_publishers.json", path, CC_MAX_PATH_LEN,
        "{\"trusted_publishers\":[\"Microsoft Windows Publisher\",\"Google LLC\"]}"),
        "create temp publishers.json");

    cc_publishers_t *pubs = cc_publishers_load(path);
    DeleteFileW(path);
    ASSERT_TRUE(pubs != NULL, "cc_publishers_load returned NULL");

    ASSERT_TRUE(cc_publishers_is_trusted(pubs, L"Microsoft Windows Publisher"),
                "Microsoft Windows Publisher not trusted");
    ASSERT_TRUE(!cc_publishers_is_trusted(pubs, L"Evil Corp"), "Evil Corp trusted");

    cc_publishers_free(pubs);
    return NULL;
}

const char *test_ioc_network(void)
{
    wchar_t path[CC_MAX_PATH_LEN];
    cc_ioc_t *ioc;

    ASSERT_TRUE(write_temp_file(L"cc_test_iocs_network.json", path,
                                CC_MAX_PATH_LEN,
        "{\"process_names\":[],\"path_substrings\":[],"
        "\"hashes_sha256\":[],\"service_names\":[],"
        "\"service_path_substrings\":[],"
        "\"malicious_ips\":[\"45.77.1.2\"],"
        "\"suspicious_ports\":[4444,\"6667\"]}"),
        "create temp network iocs.json");

    ioc = cc_ioc_load(path);
    DeleteFileW(path);
    ASSERT_TRUE(ioc != NULL, "cc_ioc_load returned NULL for network IOCs");

    ASSERT_TRUE(cc_ioc_is_malicious_ipv4(ioc, inet_addr("45.77.1.2")),
                "malicious IP not matched");
    ASSERT_TRUE(!cc_ioc_is_malicious_ipv4(ioc, inet_addr("8.8.8.8")),
                "benign IP matched");
    ASSERT_TRUE(cc_ioc_is_suspicious_port(ioc, 4444),
                "numeric suspicious port not matched");
    ASSERT_TRUE(cc_ioc_is_suspicious_port(ioc, 6667),
                "string suspicious port not matched");
    ASSERT_TRUE(!cc_ioc_is_suspicious_port(ioc, 443),
                "benign port matched");

    cc_ioc_free(ioc);
    return NULL;
}
