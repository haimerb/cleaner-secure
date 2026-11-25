#ifndef CC_EVENTLOG_SCAN_H
#define CC_EVENTLOG_SCAN_H

#include "types.h"

/*
 * Scan Windows Event Logs for suspicious activity:
 *  - Security: 4688 (process creation w/ unusual cmdline), 4624 Type 10/11 oddities,
 *    4672 (special privileges), 1102 (audit log cleared)
 *  - Defender/Operational: 1006/1007/1116/1117 (malware detected/blocked)
 *  - Sysmon (if installed): 1 (process create), 3 (network), 11 (file create)
 *
 * Reads only the last N minutes (param minutes, default 60).
 * Unavailable logs are skipped (reported via available_mask bits).
 * Returns number of alerts written to out (up to cap).
 */
int cc_eventlog_scan(int minutes, cc_alert_t *out, int cap,
                      uint32_t *available_mask /* optional */,
                      ULONGLONG deadline);

#define CC_EVT_SECURITY   0x1
#define CC_EVT_DEFENDER   0x2
#define CC_EVT_SYSMON     0x4

#endif /* CC_EVENTLOG_SCAN_H */
