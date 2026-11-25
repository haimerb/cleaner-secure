#ifndef CC_REGISTRY_SCAN_H
#define CC_REGISTRY_SCAN_H

#include "types.h"

struct cc_ioc_s;

/*
 * Scan Windows Registry persistence / tampering locations:
 *  - HKLM/HKCU ...\Run, RunOnce
 *  - HKLM ...\Services (suspicious ImagePath)
 *  - IFEO (Image File Execution Options) Debugger hijacks
 *  - Winlogon: Shell, Userinit, Notify
 *  - KnownDLLs overrides
 * Each suspicious entry becomes an alert (risk + reason).
 * Access-denied keys are skipped silently.
 *
 * ioc may be NULL (path/name heuristics still apply).
 * Returns number of alerts written to out (up to cap).
 */
int cc_registry_scan(const struct cc_ioc_s *ioc, cc_alert_t *out, int cap,
                      ULONGLONG deadline);

#endif /* CC_REGISTRY_SCAN_H */
