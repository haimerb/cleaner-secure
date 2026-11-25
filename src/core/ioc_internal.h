#ifndef CC_IOC_INTERNAL_H
#define CC_IOC_INTERNAL_H

#include "ioc.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

struct cc_ioc_s {
    wchar_t proc_names[256][CC_MAX_NAME];
    int proc_names_n;
    wchar_t path_subs[128][CC_MAX_PATH_LEN];
    int path_subs_n;
    char hashes[128][65];
    int hashes_n;
    wchar_t svc_names[128][CC_MAX_NAME];
    int svc_names_n;
    wchar_t svc_path_subs[64][CC_MAX_PATH_LEN];
    int svc_path_subs_n;
    uint32_t malicious_ipv4[64];
    int malicious_ipv4_n;
    uint16_t suspicious_ports[128];
    int suspicious_ports_n;
    struct {
        wchar_t parent[CC_MAX_NAME];
        wchar_t children[16][CC_MAX_NAME];
        int n;
    } parents[64];
    int parents_n;
};

bool cc_ioc_parent_child_match(const struct cc_ioc_s *ioc, const wchar_t *parent, const wchar_t *child);

#endif
