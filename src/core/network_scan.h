#ifndef CC_NETWORK_SCAN_H
#define CC_NETWORK_SCAN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "types.h"

#define CC_MAX_NETWORK_CONNS 4096

typedef struct {
    uint32_t pid;
    uint8_t  protocol;
    uint32_t state;
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t remote_addr;
    uint16_t remote_port;
    bool     listening;
} cc_network_conn_t;

typedef struct {
    cc_network_conn_t items[CC_MAX_NETWORK_CONNS];
    int count;
    bool truncated;
} cc_network_snapshot_t;

struct cc_config_s;
struct cc_ioc_s;

int cc_network_collect(cc_network_snapshot_t *snap);
int cc_network_scan_snapshot(const struct cc_config_s *cfg,
                             const struct cc_ioc_s *ioc,
                             const cc_network_snapshot_t *snap,
                             bool vt_live,
                             cc_alert_t *out,
                             int cap,
                             ULONGLONG deadline);
int cc_network_scan(const struct cc_config_s *cfg,
                    const struct cc_ioc_s *ioc,
                    bool vt_live,
                    cc_alert_t *out,
                    int cap,
                    ULONGLONG deadline);

#endif
