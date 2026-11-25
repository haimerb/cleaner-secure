#ifndef CC_DETECT_H
#define CC_DETECT_H

#include "types.h"

struct cc_metrics_s;
struct cc_ioc_s;
struct cc_publishers_s;
struct cc_config_s;
struct cc_trust_cache_s;

typedef struct {
    const struct cc_config_s    *cfg;
    const struct cc_ioc_s       *ioc;
    const struct cc_publishers_s *pubs;
    struct cc_metrics_s         *metrics; /* shared sampler for CPU deltas */
    struct cc_trust_cache_s     *trust_cache;
    int alert_count;
} cc_detect_ctx_t;

/*
 * Full detection pass over current processes/services:
 *  1. resource thresholds (via metrics sampler)
 *  2. IOC match (name/path/hash)
 *  3. anomalies (unsigned, hidden, odd path, suspicious parent)
 *  4. signature + publisher (+ VirusTotal if enabled)
 *  5. services (suspicious names/paths + resource hogs)
 *
 * Hashing/signature/VT are done at most once per unique path and cached
 * by the caller-provided trust cache (see detect_cache_*).
 * Returns alerts written to out (up to cap).
 */
int cc_detect_processes(const cc_detect_ctx_t *ctx, cc_alert_t *out, int cap,
                        ULONGLONG deadline);

/* Score a single alert into0..100 (for GUI ranking). */
int cc_alert_score(cc_risk_t risk, const char *category);

/* Trust cache: path -> cc_trust_result_t, so VT/signature run once per path. */
typedef struct cc_trust_cache_s cc_trust_cache_t;
cc_trust_cache_t *cc_trust_cache_create(void);
void cc_trust_cache_free(cc_trust_cache_t *c);
const cc_trust_result_t *cc_trust_cache_get(cc_trust_cache_t *c, const wchar_t *path);

#endif /* CC_DETECT_H */
