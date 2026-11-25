#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#endif
#include "config.h"
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include "response.h"

#include <windows.h>

const char *test_response_denylist(void)
{
    DWORD err = 0;

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
    return NULL;
}
