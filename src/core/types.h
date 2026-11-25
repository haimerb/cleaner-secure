#ifndef CC_TYPES_H
#define CC_TYPES_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#define CC_MAX_PATH_LEN     520
#define CC_MAX_NAME         260
#define CC_MAX_PUBLISHER    256
#define CC_MAX_REASON       512
#define CC_MAX_PROCS        4096
#define CC_MAX_SERVICES      1024

typedef enum {
    CC_RISK_NONE = 0,
    CC_RISK_LOW,
    CC_RISK_MEDIUM,
    CC_RISK_HIGH,
    CC_RISK_CRITICAL
} cc_risk_t;

typedef enum {
    CC_IL_UNKNOWN = 0,
    CC_IL_LOW,
    CC_IL_MEDIUM,
    CC_IL_HIGH,
    CC_IL_SYSTEM,
    CC_IL_PROTECTED
} cc_integrity_t;

typedef struct {
    uint32_t pid;
    uint32_t parent_pid;
    wchar_t  name[CC_MAX_NAME];
    wchar_t  path[CC_MAX_PATH_LEN];
    wchar_t  publisher[CC_MAX_PUBLISHER];
    wchar_t  user[CC_MAX_NAME];
    wchar_t  command_line[CC_MAX_PATH_LEN];
    uint32_t session_id;
    uint64_t create_time;
    cc_integrity_t integrity;
    bool     is_hidden;
    bool     is_elevated;
    bool     is_wow64;
    bool     bitness_known;
    bool     user_known;
} cc_proc_info_t;

typedef struct {
    double   cpu_percent;      /* 0..100 (sum across cores possible) */
    uint64_t working_set;      /* bytes */
    uint64_t private_bytes;    /* bytes */
    uint64_t handle_count;
    uint32_t thread_count;
    uint64_t io_read_bytes;
    uint64_t io_write_bytes;
} cc_proc_metrics_t;

typedef struct {
    cc_proc_info_t info;
    cc_proc_metrics_t metrics;
} cc_process_view_t;

typedef struct {
    wchar_t  name[CC_MAX_NAME];
    wchar_t  display_name[CC_MAX_NAME];
    wchar_t  path[CC_MAX_PATH_LEN];
    uint32_t pid;              /* 0 if not running */
    uint32_t state;            /* SERVICE_* */
    uint32_t start_type;       /* SERVICE_*_START */
    cc_risk_t risk;
} cc_service_info_t;

typedef struct {
    char     hash_sha256[65];  /* lowercase hex + NUL */
    bool     signature_valid;
    bool     publisher_checked;
    bool     publisher_trusted;
    wchar_t  publisher[CC_MAX_PUBLISHER];
    char     virustotal_hits;  /* -1 = not queried/unknown, 0 = clean */
    char     virustotal_total; /* -1 = not queried */
} cc_trust_result_t;

typedef struct {
    cc_risk_t risk;
    char      category[32];    /* "resource"|"ioc"|"anomaly"|"signature"|"registry"|"eventlog" */
    char      reason[CC_MAX_REASON];
    wchar_t   target[CC_MAX_NAME]; /* process/service/registry key name */
    wchar_t   indicator[64];
    uint32_t  pid;
} cc_alert_t;

#endif /* CC_TYPES_H */
