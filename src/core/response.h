#ifndef CC_RESPONSE_H
#define CC_RESPONSE_H

#include "types.h"

/* All return true on success. On failure sets *err (system message). */

bool cc_kill_process(uint32_t pid, DWORD *err);
bool cc_suspend_process(uint32_t pid, DWORD *err);
bool cc_resume_process(uint32_t pid, DWORD *err);

/* Stop/start a service by name. */
bool cc_service_stop(const wchar_t *name, DWORD *err);
bool cc_service_start(const wchar_t *name, DWORD *err);

#endif /* CC_RESPONSE_H */
