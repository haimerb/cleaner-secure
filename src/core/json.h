#ifndef CC_JSON_H
#define CC_JSON_H

#include "types.h"

/*
 * Minimal JSON reader for our config files (no external deps).
 * Supports: objects, arrays, strings, numbers, booleans, null.
 * Enough for iocs.json / publishers.json / thresholds.json.
 */

typedef struct cc_json_s cc_json_t;

cc_json_t *cc_json_parse_file(const wchar_t *path);
cc_json_t *cc_json_parse(const char *text, size_t len);
void cc_json_free(cc_json_t *j);

const cc_json_t *cc_json_obj_get(const cc_json_t *j, const char *key);
const cc_json_t *cc_json_arr_get(const cc_json_t *j, int index);
int  cc_json_arr_len(const cc_json_t *j);
bool cc_json_is_str(const cc_json_t *j, const char **out);
bool cc_json_is_num(const cc_json_t *j, double *out);
bool cc_json_is_bool(const cc_json_t *j, bool *out);

/* Convenience: string field or default. Writes to out (UTF-8). */
bool cc_json_get_str(const cc_json_t *j, const char *key, char *out, size_t cap);
bool cc_json_get_double(const cc_json_t *j, const char *key, double *out);
bool cc_json_get_uint(const cc_json_t *j, const char *key, uint32_t *out);
bool cc_json_get_bool(const cc_json_t *j, const char *key, bool *out);

/* UTF-8 -> UTF-16 helper. */
void cc_utf8_to_wide(const char *src, wchar_t *dst, size_t cap);
void cc_wide_to_utf8(const wchar_t *src, char *dst, size_t cap);

#endif /* CC_JSON_H */
