#include "network_scan.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcomment"
#include "config.h"
#pragma clang diagnostic pop
#include "ioc.h"
#include "proc.h"
#include "virustotal.h"
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CC_NET_MAX_PIDS 512
#define CC_NET_MAX_UNIQUE 64

typedef struct {
    uint32_t pid;
    uint32_t conn_count;
    uint32_t unique_ips[CC_NET_MAX_UNIQUE];
    int unique_count;
    uint32_t listen_ports;
    uint32_t suspicious_ports;
    uint32_t malicious_ips;
    uint32_t vt_hits;
    uint32_t vt_total;
    wchar_t indicator[64];
} cc_net_pid_t;

static void cc_net_ip_text(uint32_t addr, char *dst, size_t cap)
{
    struct in_addr in_addr_value;

    if (dst == NULL || cap == 0) return;
    dst[0] = '\0';
    in_addr_value.S_un.S_addr = addr;
    (void)InetNtopA(AF_INET, &in_addr_value, dst, (ULONG)cap);
}

static bool cc_net_public_ipv4(uint32_t addr)
{
    uint32_t host = ntohl(addr);
    unsigned a = (unsigned)((host >> 24) & 0xff);
    unsigned b = (unsigned)((host >> 16) & 0xff);

    if (a == 0 || a == 10 || a == 127 || a >= 224) return false;
    if (a == 172 && b >= 16 && b <= 31) return false;
    if (a == 192 && b == 168) return false;
    if (a == 169 && b == 254) return false;
    if (a == 100 && b >= 64 && b <= 127) return false;
    return true;
}

static void cc_net_add_unique(cc_net_pid_t *st, uint32_t addr)
{
    int i;

    if (st == NULL || addr == 0 || st->unique_count >= CC_NET_MAX_UNIQUE) return;
    for (i = 0; i < st->unique_count; i++) {
        if (st->unique_ips[i] == addr) return;
    }
    st->unique_ips[st->unique_count++] = addr;
}

static cc_net_pid_t *cc_net_pid(cc_net_pid_t *items, int *count, uint32_t pid)
{
    int i;

    if (items == NULL || count == NULL || pid == 0) return NULL;
    for (i = 0; i < *count; i++) {
        if (items[i].pid == pid) return &items[i];
    }
    if (*count >= CC_NET_MAX_PIDS) return NULL;
    memset(&items[*count], 0, sizeof(items[0]));
    items[*count].pid = pid;
    (*count)++;
    return &items[*count - 1];
}

static int cc_net_collect_tcp(cc_network_snapshot_t *snap)
{
    ULONG size = 0;
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD ret;
    DWORD i;
    int added = 0;

    ret = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                              TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0) return 0;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (table == NULL) return 0;
    ret = GetExtendedTcpTable(table, &size, FALSE, AF_INET,
                              TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret == NO_ERROR) {
        for (i = 0; i < table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            cc_network_conn_t *c;

            if (snap->count >= CC_MAX_NETWORK_CONNS) {
                snap->truncated = true;
                break;
            }
            c = &snap->items[snap->count++];
            memset(c, 0, sizeof(*c));
            c->pid = row->dwOwningPid;
            c->protocol = IPPROTO_TCP;
            c->state = row->dwState;
            c->local_addr = row->dwLocalAddr;
            c->local_port = (uint16_t)ntohs((USHORT)row->dwLocalPort);
            c->remote_addr = row->dwRemoteAddr;
            c->remote_port = (uint16_t)ntohs((USHORT)row->dwRemotePort);
            c->listening = row->dwState == MIB_TCP_STATE_LISTEN;
            added++;
        }
    }
    free(table);
    return added;
}

static int cc_net_collect_udp(cc_network_snapshot_t *snap)
{
    ULONG size = 0;
    PMIB_UDPTABLE_OWNER_PID table = NULL;
    DWORD ret;
    DWORD i;
    int added = 0;

    ret = GetExtendedUdpTable(NULL, &size, FALSE, AF_INET,
                              UDP_TABLE_OWNER_PID, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0) return 0;
    table = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
    if (table == NULL) return 0;
    ret = GetExtendedUdpTable(table, &size, FALSE, AF_INET,
                              UDP_TABLE_OWNER_PID, 0);
    if (ret == NO_ERROR) {
        for (i = 0; i < table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &table->table[i];
            cc_network_conn_t *c;

            if (snap->count >= CC_MAX_NETWORK_CONNS) {
                snap->truncated = true;
                break;
            }
            c = &snap->items[snap->count++];
            memset(c, 0, sizeof(*c));
            c->pid = row->dwOwningPid;
            c->protocol = IPPROTO_UDP;
            c->local_addr = row->dwLocalAddr;
            c->local_port = (uint16_t)ntohs((USHORT)row->dwLocalPort);
            c->listening = true;
            added++;
        }
    }
    free(table);
    return added;
}

int cc_network_collect(cc_network_snapshot_t *snap)
{
    if (snap == NULL) return -1;
    memset(snap, 0, sizeof(*snap));
    (void)cc_net_collect_tcp(snap);
    (void)cc_net_collect_udp(snap);
    return snap->count;
}

static const wchar_t *cc_net_proc_name(const cc_proc_info_t *procs, int count,
                                       uint32_t pid)
{
    int i;

    if (procs == NULL || pid == 0) return NULL;
    for (i = 0; i < count; i++) {
        if (procs[i].pid == pid) return procs[i].name;
    }
    return NULL;
}

static bool cc_net_push(cc_alert_t *out, int cap, int *count,
                        cc_risk_t risk, const char *reason,
                        const wchar_t *target, const wchar_t *indicator,
                        uint32_t pid)
{
    cc_alert_t *alert;

    if (out == NULL || count == NULL || cap <= 0 || *count >= cap) return false;
    alert = &out[*count];
    memset(alert, 0, sizeof(*alert));
    alert->risk = risk;
    alert->pid = pid;
    (void)strncpy(alert->category, "network", sizeof(alert->category) - 1);
    if (reason != NULL) {
        (void)strncpy(alert->reason, reason, sizeof(alert->reason) - 1);
    }
    if (target != NULL) {
        (void)wcsncpy(alert->target, target, CC_MAX_NAME - 1);
    }
    if (indicator != NULL) {
        (void)wcsncpy(alert->indicator, indicator, 63);
    }
    (*count)++;
    return true;
}

int cc_network_scan_snapshot(const struct cc_config_s *cfg_in,
                             const struct cc_ioc_s *ioc,
                             const cc_network_snapshot_t *snap,
                             bool vt_live,
                             cc_alert_t *out,
                             int cap,
                             ULONGLONG deadline)
{
    const cc_config_t *cfg = (const cc_config_t *)(const void *)cfg_in;
    cc_proc_info_t *procs = NULL;
    cc_net_pid_t *stats = NULL;
    int proc_count = 0;
    int stat_count = 0;
    int count = 0;
    int i;
    uint32_t lookups = 0;

    if (cfg == NULL || snap == NULL || out == NULL || cap <= 0) return 0;
    if (!cfg->network_enabled) return 0;

    procs = (cc_proc_info_t *)calloc(CC_MAX_PROCS, sizeof(*procs));
    stats = (cc_net_pid_t *)calloc(CC_NET_MAX_PIDS, sizeof(*stats));
    if (procs == NULL || stats == NULL) goto done;
    proc_count = cc_proc_list(procs, CC_MAX_PROCS);
    if (proc_count < 0) proc_count = 0;

    for (i = 0; i < snap->count; i++) {
        const cc_network_conn_t *c = &snap->items[i];
        cc_net_pid_t *st;
        char ip[64];
        int hits = 0;
        int total = 0;

        if (deadline != 0 && GetTickCount64() >= deadline) break;
        st = cc_net_pid(stats, &stat_count, c->pid);
        if (st == NULL) continue;
        st->conn_count++;

        if (c->protocol == IPPROTO_TCP) {
            if (c->listening && cfg->network_max_listen_ports_per_pid > 0) {
                st->listen_ports++;
            }
            if (c->local_port != 0 && cc_ioc_is_suspicious_port(ioc, c->local_port)) {
                st->suspicious_ports++;
            }
            if (c->remote_addr == 0) continue;
            cc_net_add_unique(st, c->remote_addr);
            if (st->indicator[0] == L'\0') {
                cc_net_ip_text(c->remote_addr, ip, sizeof(ip));
                (void)MultiByteToWideChar(CP_UTF8, 0, ip, -1, st->indicator, 64);
            }
            if (cc_ioc_is_malicious_ipv4(ioc, c->remote_addr)) {
                st->malicious_ips++;
            }
            if (c->remote_port != 0 &&
                cc_ioc_is_suspicious_port(ioc, c->remote_port)) {
                st->suspicious_ports++;
            }
            if (cfg->network_vt_enabled &&
                lookups < cfg->network_vt_max_lookups &&
                cc_net_public_ipv4(c->remote_addr)) {
                cc_net_ip_text(c->remote_addr, ip, sizeof(ip));
                lookups++;
                if (cc_virustotal_lookup_ip(ip, &hits, &total, vt_live) && hits > 0) {
                    st->vt_hits++;
                    st->vt_total = (uint32_t)total;
                }
            }
        } else if (c->protocol == IPPROTO_UDP) {
            if (c->local_port != 0 && cc_ioc_is_suspicious_port(ioc, c->local_port)) {
                st->suspicious_ports++;
            }
        }
    }

    for (i = 0; i < stat_count && count < cap; i++) {
        cc_net_pid_t *st = &stats[i];
        const wchar_t *name = cc_net_proc_name(procs, proc_count, st->pid);
        wchar_t fallback[CC_MAX_NAME];
        wchar_t target[CC_MAX_NAME];
        const wchar_t *indicator = st->indicator;
        char reason[CC_MAX_REASON];
        char ip[64];

        if (deadline != 0 && GetTickCount64() >= deadline) break;
        if (name == NULL) {
            (void)swprintf(fallback, CC_MAX_NAME, L"pid:%lu",
                           (unsigned long)st->pid);
            name = fallback;
        }
        if (name[0] != L'\0') {
            (void)wcsncpy(target, name, CC_MAX_NAME - 1);
            target[CC_MAX_NAME - 1] = L'\0';
        } else {
            target[0] = L'\0';
        }
        if (indicator[0] == L'\0') {
            cc_net_ip_text(0, ip, sizeof(ip));
            (void)MultiByteToWideChar(CP_UTF8, 0, ip, -1, fallback, 64);
            indicator = fallback;
        }

        if (st->malicious_ips > 0) {
            (void)snprintf(reason, sizeof(reason),
                           "Malicious IP IOC: %ls (%lu hit%s)",
                           indicator, (unsigned long)st->malicious_ips,
                           st->malicious_ips == 1 ? "" : "s");
            if (!cc_net_push(out, cap, &count, CC_RISK_CRITICAL, reason,
                             target, indicator, st->pid)) break;
        }
        if (st->vt_hits > 0) {
            (void)snprintf(reason, sizeof(reason),
                           "VirusTotal IP: %lu/%d detections",
                           (unsigned long)st->vt_hits, (int)st->vt_total);
            if (!cc_net_push(out, cap, &count, CC_RISK_CRITICAL, reason,
                             target, indicator, st->pid)) break;
        }
        if (st->suspicious_ports > 0) {
            (void)snprintf(reason, sizeof(reason),
                           "Suspicious network port: %ls (%lu hit%s)",
                           indicator, (unsigned long)st->suspicious_ports,
                           st->suspicious_ports == 1 ? "" : "s");
            if (!cc_net_push(out, cap, &count, CC_RISK_HIGH, reason,
                             target, indicator, st->pid)) break;
        }
        if (cfg->network_max_conns_per_pid > 0 &&
            st->conn_count > cfg->network_max_conns_per_pid) {
            (void)snprintf(reason, sizeof(reason),
                           "Excessive connections: %lu (limit %lu)",
                           (unsigned long)st->conn_count,
                           (unsigned long)cfg->network_max_conns_per_pid);
            if (!cc_net_push(out, cap, &count, CC_RISK_MEDIUM, reason,
                             target, indicator, st->pid)) break;
        }
        if (cfg->network_max_unique_ips_per_pid > 0 &&
            st->unique_count > (int)cfg->network_max_unique_ips_per_pid) {
            (void)snprintf(reason, sizeof(reason),
                           "Excessive distinct remote IPs: %d (limit %lu)",
                           st->unique_count,
                           (unsigned long)cfg->network_max_unique_ips_per_pid);
            if (!cc_net_push(out, cap, &count, CC_RISK_MEDIUM, reason,
                             target, indicator, st->pid)) break;
        }
        if (cfg->network_max_listen_ports_per_pid > 0 &&
            st->listen_ports > cfg->network_max_listen_ports_per_pid) {
            (void)snprintf(reason, sizeof(reason),
                           "Excessive listening TCP ports: %lu (limit %lu)",
                           (unsigned long)st->listen_ports,
                           (unsigned long)cfg->network_max_listen_ports_per_pid);
            if (!cc_net_push(out, cap, &count, CC_RISK_HIGH, reason,
                             target, indicator, st->pid)) break;
        }
    }

done:
    free(stats);
    free(procs);
    return count;
}

int cc_network_scan(const struct cc_config_s *cfg,
                    const struct cc_ioc_s *ioc,
                    bool vt_live,
                    cc_alert_t *out,
                    int cap,
                    ULONGLONG deadline)
{
    cc_network_snapshot_t snap;
    int count;

    if (cc_network_collect(&snap) < 0) return 0;
    count = cc_network_scan_snapshot(cfg, ioc, &snap, vt_live,
                                     out, cap, deadline);
    return count;
}
