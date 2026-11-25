#ifndef CC_METRICS_H
#define CC_METRICS_H

#include "types.h"

/*
 * Sampler: call cc_metrics_begin() once, then cc_metrics_sample() every
 * interval; CPU% is computed as delta between samples.
 */
typedef struct cc_metrics_s cc_metrics_t;

cc_metrics_t *cc_metrics_create(void);
void cc_metrics_destroy(cc_metrics_t *m);

/* Take a sample for pid. Returns false if process gone/inaccessible. */
bool cc_metrics_sample(cc_metrics_t *m, uint32_t pid, cc_proc_metrics_t *out);

/* True if pid was sampled in the previous call (for CPU delta). */
bool cc_metrics_has_baseline(const cc_metrics_t *m, uint32_t pid);

/* Drop baseline for dead pids (call periodically). */
void cc_metrics_prune(cc_metrics_t *m);

#endif /* CC_METRICS_H */
