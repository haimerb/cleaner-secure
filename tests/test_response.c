#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
#include "config.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include "network_scan.h"
#include "response.h"

#include <windows.h>
#include <string.h>

const char *test_response_denylist(void)
{
    wchar_t path[CC_MAX_PATH_LEN];
    wchar_t *base;
    DWORD len = sizeof(path) / sizeof(path[0]);
    DWORD err = 0;

    if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &len)) {
        base = wcsrchr(path, L'\\');
        base = base != NULL ? base + 1 : path;
        if (!cc_process_matches_name(GetCurrentProcessId(), base, &err)) {
            return "self image name should match current process";
        }
    }
    if (cc_process_matches_name(GetCurrentProcessId(),
                                L"__no_such_process__.exe", &err)) {
        return "different image name should not match current process";
    }
    if (cc_kill_process(0, &err)) {
        return "pid 0 should be denied";
    }
    if (err == 0) {
        return "pid 0 should set an error code";
    }
    err = 0;
    if (cc_suspend_process(GetCurrentProcessId(), &err)) {
        return "self suspend should be denied";
    }
    err = 0;
    if (cc_service_stop(L"WinDefend", &err)) {
        return "critical service stop should be denied";
    }
    err = 0;
    if (cc_service_start(L"", &err)) {
        return "empty service name should be denied";
    }
    return NULL;
}

const char *test_config_defaults(void)
{
    cc_config_t cfg;

    if (!cc_config_load(&cfg, L"C:\\__cc_no_such_config__")) {
        return "config load with missing dir should use defaults";
    }
    if (cfg.scan_timeout_ms != 60000) {
        return "default scan_timeout_ms should be 60000";
    }
    if (cfg.cpu_percent_threshold != 80.0 || cfg.handle_threshold != 4000) {
        return "default thresholds should be populated";
    }
    if (!cfg.network_enabled || cfg.network_max_conns_per_pid != 500 ||
        cfg.network_max_unique_ips_per_pid != 100 ||
        cfg.network_max_listen_ports_per_pid != 25) {
        return "default network thresholds should be populated";
    }
    if (cfg.network_vt_enabled || cfg.network_vt_max_lookups != 8 ||
        cfg.vt_auto_lookup) {
        return "default VT lookup settings should be cache-only";
    }
    return NULL;
}

const char *test_network_scan_snapshot(void)
{
    cc_network_snapshot_t snap;
    cc_config_t cfg;
    cc_alert_t alerts[4];

    if (!cc_config_load(&cfg, L"C:\\__cc_no_such_config__")) {
        return "config load with missing dir should use defaults";
    }
    memset(&snap, 0, sizeof(snap));

    cfg.network_enabled = false;
    if (cc_network_scan_snapshot((const struct cc_config_s *)&cfg, NULL, &snap,
                                 false, alerts, 4, 0) != 0) {
        return "disabled network scan should emit no alerts";
    }
    cfg.network_enabled = true;
    if (cc_network_scan_snapshot((const struct cc_config_s *)&cfg, NULL, &snap,
                                 false, alerts, 4, 0) != 0) {
        return "empty snapshot should emit no alerts";
    }
    if (cc_network_collect(&snap) < 0) {
        return "network collection failed";
    }
    return NULL;
}

const char *test_response_ip_denylist(void)
{
    DWORD err = 0;

    if (cc_block_ip(L"127.0.0.1", &err)) {
        return "loopback block should be denied";
    }
    if (err == 0) {
        return "loopback block should set an error code";
    }
    err = 0;
    if (cc_block_ip(L"10.10.10.10", &err)) {
        return "private IP block should be denied";
    }
    err = 0;
    if (cc_block_ip(L"not-an-ip", &err)) {
        return "invalid IP block should be denied";
    }
    err = 0;
    if (cc_unblock_ip(L"::1", &err)) {
        return "IPv6 loopback unblock should be denied";
    }
    return NULL;
}
