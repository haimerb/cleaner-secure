#ifndef CC_CONFIG_H
#define CC_CONFIG_H

#include "types.h"

typedef struct cc_config_s {
    double   cpu_percent_threshold;   /* e.g. 80.0 */
    uint32_t cpu_sustain_seconds;     /* e.g. 10 */
    uint64_t ram_bytes_threshold;     /* e.g. 1.5 GB */
    uint32_t handle_threshold;        /* e.g. 4000 */
    uint64_t io_bytes_threshold;      /* e.g. 500 MB */
    bool     network_enabled;
    uint32_t network_max_conns_per_pid;
    uint32_t network_max_unique_ips_per_pid;
    uint32_t network_max_listen_ports_per_pid;
    bool     network_vt_enabled;
    uint32_t network_vt_max_lookups;
    bool     vt_enabled;
    bool     vt_auto_lookup;
    uint32_t vt_requests_per_minute;  /* e.g. 4 */
    uint32_t scan_timeout_ms;         /* e.g. 2000 */
    char     vt_api_key[128];
    wchar_t  config_dir[CC_MAX_PATH_LEN];
} cc_config_t;

/* Load config/*.json from dir (or exe dir/config default). Never fails hard:
 * fills defaults if files missing. Returns false only if dir unusable. */
bool cc_config_load(cc_config_t *out, const wchar_t *config_dir);

/* Directory of the running exe. */
bool cc_exe_dir(wchar_t *out, size_t cap);

#endif /* CC_CONFIG_H */
