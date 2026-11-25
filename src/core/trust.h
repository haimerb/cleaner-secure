#ifndef CC_TRUST_H
#define CC_TRUST_H

#include "types.h"

/*
 * Validate Authenticode signature of an image file:
 *  - WinVerifyTrust (chain + revocation)
 *  - extract publisher CN
 *  - SHA-256 of the file
 * Does NOT do VirusTotal (see virustotal.h) and does NOT check allowlist
 * (see ioc.h cc_publishers_is_trusted).
 * Never fails hard: on error returns result with signature_valid=false.
 */
bool cc_trust_verify(const wchar_t *path, cc_trust_result_t *out);

/* SHA-256 hex (lowercase) of file. false on I/O error. */
bool cc_hash_sha256_file(const wchar_t *path, char out[65]);

/* Is the current process elevated? */
bool cc_is_elevated(void);

#endif /* CC_TRUST_H */
