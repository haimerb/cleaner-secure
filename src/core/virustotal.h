#ifndef CC_VIRUSTOTAL_H
#define CC_VIRUSTOTAL_H

#include "types.h"

/*
 * Query VirusTotal for a SHA-256 hash.
 * API key from config (vt_api_key) or VT_API_KEY env var.
 * Rate-limited (default 4 req/min) with an in-memory cache.
 * On any failure: sets out->virustotal_hits = -1, returns false.
 * offline/disabled: returns false immediately without network.
 */
bool cc_virustotal_lookup(const char *sha256, cc_trust_result_t *out);
bool cc_virustotal_lookup_ex(const char *sha256, cc_trust_result_t *out, bool allow_live);
bool cc_virustotal_lookup_ip(const char *ip, int *hits, int *total, bool allow_live);

/* Configure key + rate limit (called from cc_config_load). */
void cc_virustotal_configure(const char *api_key, int requests_per_minute);

/* Flush/reset cache. */
void cc_virustotal_reset(void);

#endif /* CC_VIRUSTOTAL_H */
