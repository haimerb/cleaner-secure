#ifndef CC_IOC_H
#define CC_IOC_H

#include "types.h"

/* Loaded IOC list (process names, paths, hashes, service names). */
typedef struct cc_ioc_s cc_ioc_t;

cc_ioc_t *cc_ioc_load(const wchar_t *path); /* NULL on failure; file optional */
void cc_ioc_free(cc_ioc_t *ioc);
int  cc_ioc_count(const cc_ioc_t *ioc);

/* Match helpers: return true on hit (case-insensitive). */
bool cc_ioc_match_proc(const cc_ioc_t *ioc, const wchar_t *name,
                       const wchar_t *path, const char *sha256);
bool cc_ioc_match_service(const cc_ioc_t *ioc, const wchar_t *service_name,
                           const wchar_t *service_path);
bool cc_ioc_is_malicious_ipv4(const cc_ioc_t *ioc, uint32_t addr);
bool cc_ioc_is_suspicious_port(const cc_ioc_t *ioc, uint16_t port);


/* Publisher allowlist: trusted publisher CNs (from publishers.json). */
typedef struct cc_publishers_s cc_publishers_t;

cc_publishers_t *cc_publishers_load(const wchar_t *path);
void cc_publishers_free(cc_publishers_t *p);
bool cc_publishers_is_trusted(const cc_publishers_t *p, const wchar_t *publisher);

#endif /* CC_IOC_H */
