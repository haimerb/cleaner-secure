#ifndef CC_PROC_H
#define CC_PROC_H

#include "types.h"

/* Snapshot all processes. Returns count, fills caller array up to cap. */
int cc_proc_list(cc_proc_info_t *out, int cap);

/* Snapshot services (SCM). Returns count; -1 on SCM access failure. */
int cc_service_list(cc_service_info_t *out, int cap);

/* Resolve full image path for a pid. Returns false if not accessible. */
bool cc_proc_path(uint32_t pid, wchar_t *out, size_t cap);

/* Parent pid of pid, 0 if unknown. */
uint32_t cc_proc_parent(uint32_t pid);

/* Check if process runs elevated (admin). False if not queryable. */
bool cc_proc_is_elevated(uint32_t pid);

/* True if process has no visible top-level window. */
bool cc_proc_is_hidden(uint32_t pid);

/* Find service by pid; returns index into list or -1. */
int cc_service_find_by_pid(const cc_service_info_t *svcs, int count, uint32_t pid);

#endif /* CC_PROC_H */
