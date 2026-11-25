#include "json.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    CCJ_NULL = 0,
    CCJ_BOOL,
    CCJ_NUM,
    CCJ_STR,
    CCJ_ARR,
    CCJ_OBJ
} cc_json_kind_t;

typedef struct {
    char *key;
    cc_json_t *value;
} cc_json_pair_t;

struct cc_json_s {
    cc_json_kind_t kind;
    union {
        bool b;
        double num;
        struct {
            char *data;
            size_t len;
        } str;
        struct {
            cc_json_t **items;
            int count;
            int cap;
        } arr;
        struct {
            cc_json_pair_t *items;
            int count;
            int cap;
        } obj;
    } u;
    cc_json_t *next_all;
};

typedef struct {
    const char *p;
    const char *end;
    cc_json_t *all;
    int depth;
    bool failed;
} cc_parse_ctx_t;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} cc_strbuf_t;

static bool cc_sb_reserve(cc_strbuf_t *sb, size_t extra)
{
    size_t need;
    size_t cap;
    char *tmp;

    if (sb == NULL || extra > SIZE_MAX - sb->len - 1) {
        return false;
    }
    need = sb->len + extra + 1;
    if (need <= sb->cap) {
        return true;
    }
    cap = sb->cap != 0 ? sb->cap : 32;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) {
            cap = need;
            break;
        }
        cap *= 2;
    }
    tmp = (char *)realloc(sb->data, cap);
    if (tmp == NULL) {
        return false;
    }
    sb->data = tmp;
    sb->cap = cap;
    return true;
}

static bool cc_sb_push(cc_strbuf_t *sb, char c)
{
    if (!cc_sb_reserve(sb, 1)) {
        return false;
    }
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
    return true;
}

static bool cc_sb_codepoint(cc_strbuf_t *sb, uint32_t cp)
{
    if (cp <= 0x7F) {
        return cc_sb_push(sb, (char)cp);
    }
    if (cp <= 0x7FF) {
        return cc_sb_push(sb, (char)(0xC0 | (cp >> 6))) &&
               cc_sb_push(sb, (char)(0x80 | (cp & 0x3F)));
    }
    if (cp <= 0xFFFF) {
        if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        return cc_sb_push(sb, (char)(0xE0 | (cp >> 12))) &&
               cc_sb_push(sb, (char)(0x80 | ((cp >> 6) & 0x3F))) &&
               cc_sb_push(sb, (char)(0x80 | (cp & 0x3F)));
    }
    if (cp > 0x10FFFF) {
        cp = 0xFFFD;
    }
    return cc_sb_push(sb, (char)(0xF0 | (cp >> 18))) &&
           cc_sb_push(sb, (char)(0x80 | ((cp >> 12) & 0x3F))) &&
           cc_sb_push(sb, (char)(0x80 | ((cp >> 6) & 0x3F))) &&
           cc_sb_push(sb, (char)(0x80 | (cp & 0x3F)));
}

static char *cc_sb_take(cc_strbuf_t *sb)
{
    if (!cc_sb_reserve(sb, 0)) {
        return NULL;
    }
    if (sb->data == NULL) {
        sb->data = (char *)malloc(1);
        if (sb->data == NULL) {
            return NULL;
        }
        sb->cap = 1;
    }
    sb->data[sb->len] = '\0';
    return sb->data;
}

static cc_json_t *cc_node_new(cc_parse_ctx_t *ctx, cc_json_kind_t kind)
{
    cc_json_t *node = (cc_json_t *)calloc(1, sizeof(*node));
    if (node == NULL) {
        ctx->failed = true;
        return NULL;
    }
    node->kind = kind;
    node->next_all = ctx->all;
    ctx->all = node;
    return node;
}

static bool cc_grow(void **items, int *cap, int need, size_t elem)
{
    int newcap;
    void *tmp;

    if (need <= *cap) {
        return true;
    }
    newcap = *cap > 0 ? *cap : 8;
    while (newcap < need) {
        if (newcap > INT_MAX / 2) {
            newcap = need;
            break;
        }
        newcap *= 2;
    }
    if ((size_t)newcap > SIZE_MAX / elem) {
        return false;
    }
    tmp = realloc(*items, (size_t)newcap * elem);
    if (tmp == NULL) {
        return false;
    }
    *items = tmp;
    *cap = newcap;
    return true;
}

static void cc_skip_ws(cc_parse_ctx_t *ctx)
{
    while (ctx->p < ctx->end) {
        char c = *ctx->p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ctx->p++;
        } else {
            break;
        }
    }
}

static bool cc_read_hex4(cc_parse_ctx_t *ctx, uint32_t *out)
{
    uint32_t value = 0;
    int i;

    for (i = 0; i < 4; i++) {
        unsigned char c;
        if (ctx->p >= ctx->end) {
            return false;
        }
        c = (unsigned char)*ctx->p++;
        if (c >= '0' && c <= '9') {
            value = (value << 4) | (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            value = (value << 4) | (uint32_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            value = (value << 4) | (uint32_t)(c - 'A' + 10);
        } else {
            return false;
        }
    }
    *out = value;
    return true;
}

static bool cc_parse_string_buf(cc_parse_ctx_t *ctx, cc_strbuf_t *out)
{
    if (ctx->p >= ctx->end || *ctx->p != '"') {
        return false;
    }
    ctx->p++;
    while (ctx->p < ctx->end) {
        unsigned char c = (unsigned char)*ctx->p++;
        if (c == '"') {
            return cc_sb_reserve(out, 0);
        }
        if (c < 0x20) {
            goto fail;
        }
        if (c != '\\') {
            if (!cc_sb_push(out, (char)c)) {
                goto fail;
            }
            continue;
        }
        if (ctx->p >= ctx->end) {
            goto fail;
        }
        switch (*ctx->p++) {
        case '"':
            if (!cc_sb_push(out, '"')) {
                goto fail;
            }
            break;
        case '\\':
            if (!cc_sb_push(out, '\\')) {
                goto fail;
            }
            break;
        case '/':
            if (!cc_sb_push(out, '/')) {
                goto fail;
            }
            break;
        case 'b':
            if (!cc_sb_push(out, '\b')) {
                goto fail;
            }
            break;
        case 'f':
            if (!cc_sb_push(out, '\f')) {
                goto fail;
            }
            break;
        case 'n':
            if (!cc_sb_push(out, '\n')) {
                goto fail;
            }
            break;
        case 'r':
            if (!cc_sb_push(out, '\r')) {
                goto fail;
            }
            break;
        case 't':
            if (!cc_sb_push(out, '\t')) {
                goto fail;
            }
            break;
        case 'u': {
            uint32_t cp;
            if (!cc_read_hex4(ctx, &cp)) {
                goto fail;
            }
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                uint32_t low = 0;
                if (ctx->end - ctx->p >= 6 && ctx->p[0] == '\\' && ctx->p[1] == 'u') {
                    const char *save = ctx->p;
                    ctx->p += 2;
                    if (cc_read_hex4(ctx, &low) && low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    } else {
                        ctx->p = save;
                        cp = 0xFFFD;
                    }
                } else {
                    cp = 0xFFFD;
                }
            }
            if (!cc_sb_codepoint(out, cp)) {
                goto fail;
            }
            break;
        }
        default:
            goto fail;
        }
    }
fail:
    ctx->failed = true;
    return false;
}

static cc_json_t *cc_parse_value(cc_parse_ctx_t *ctx);

static cc_json_t *cc_parse_number(cc_parse_ctx_t *ctx)
{
    const char *start = ctx->p;
    size_t len;
    char *tmp;
    double value;
    cc_json_t *node;

    if (ctx->p < ctx->end && *ctx->p == '-') {
        ctx->p++;
    }
    if (ctx->p >= ctx->end) {
        goto fail;
    }
    if (*ctx->p == '0') {
        ctx->p++;
    } else if (*ctx->p >= '1' && *ctx->p <= '9') {
        while (ctx->p < ctx->end && *ctx->p >= '0' && *ctx->p <= '9') {
            ctx->p++;
        }
    } else {
        goto fail;
    }
    if (ctx->p < ctx->end && *ctx->p == '.') {
        ctx->p++;
        if (ctx->p >= ctx->end || *ctx->p < '0' || *ctx->p > '9') {
            goto fail;
        }
        while (ctx->p < ctx->end && *ctx->p >= '0' && *ctx->p <= '9') {
            ctx->p++;
        }
    }
    if (ctx->p < ctx->end && (*ctx->p == 'e' || *ctx->p == 'E')) {
        ctx->p++;
        if (ctx->p < ctx->end && (*ctx->p == '+' || *ctx->p == '-')) {
            ctx->p++;
        }
        if (ctx->p >= ctx->end || *ctx->p < '0' || *ctx->p > '9') {
            goto fail;
        }
        while (ctx->p < ctx->end && *ctx->p >= '0' && *ctx->p <= '9') {
            ctx->p++;
        }
    }
    len = (size_t)(ctx->p - start);
    tmp = (char *)malloc(len + 1);
    if (tmp == NULL) {
        goto fail;
    }
    memcpy(tmp, start, len);
    tmp[len] = '\0';
    value = strtod(tmp, NULL);
    free(tmp);
    node = cc_node_new(ctx, CCJ_NUM);
    if (node == NULL) {
        return NULL;
    }
    node->u.num = value;
    return node;
fail:
    ctx->failed = true;
    return NULL;
}

static cc_json_t *cc_parse_literal(cc_parse_ctx_t *ctx, const char *word,
                                   cc_json_kind_t kind, bool value)
{
    size_t len = strlen(word);
    cc_json_t *node;

    if ((size_t)(ctx->end - ctx->p) < len || memcmp(ctx->p, word, len) != 0) {
        ctx->failed = true;
        return NULL;
    }
    ctx->p += len;
    node = cc_node_new(ctx, kind);
    if (node != NULL && kind == CCJ_BOOL) {
        node->u.b = value;
    }
    return node;
}

static cc_json_t *cc_parse_array(cc_parse_ctx_t *ctx)
{
    cc_json_t *node;

    if (ctx->p >= ctx->end || *ctx->p != '[') {
        ctx->failed = true;
        return NULL;
    }
    ctx->p++;
    node = cc_node_new(ctx, CCJ_ARR);
    if (node == NULL) {
        return NULL;
    }
    cc_skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == ']') {
        ctx->p++;
        return node;
    }
    for (;;) {
        cc_json_t *item;
        cc_skip_ws(ctx);
        item = cc_parse_value(ctx);
        if (item == NULL) {
            return NULL;
        }
        if (!cc_grow((void **)&node->u.arr.items, &node->u.arr.cap,
                     node->u.arr.count + 1, sizeof(*node->u.arr.items))) {
            ctx->failed = true;
            return NULL;
        }
        node->u.arr.items[node->u.arr.count++] = item;
        cc_skip_ws(ctx);
        if (ctx->p >= ctx->end) {
            ctx->failed = true;
            return NULL;
        }
        if (*ctx->p == ']') {
            ctx->p++;
            return node;
        }
        if (*ctx->p != ',') {
            ctx->failed = true;
            return NULL;
        }
        ctx->p++;
    }
}

static cc_json_t *cc_parse_object(cc_parse_ctx_t *ctx)
{
    cc_json_t *node;

    if (ctx->p >= ctx->end || *ctx->p != '{') {
        ctx->failed = true;
        return NULL;
    }
    ctx->p++;
    node = cc_node_new(ctx, CCJ_OBJ);
    if (node == NULL) {
        return NULL;
    }
    cc_skip_ws(ctx);
    if (ctx->p < ctx->end && *ctx->p == '}') {
        ctx->p++;
        return node;
    }
    for (;;) {
        cc_strbuf_t sb;
        cc_json_t *value;
        char *key;

        memset(&sb, 0, sizeof(sb));
        cc_skip_ws(ctx);
        if (!cc_parse_string_buf(ctx, &sb)) {
            free(sb.data);
            return NULL;
        }
        key = cc_sb_take(&sb);
        if (key == NULL) {
            free(sb.data);
            return NULL;
        }
        cc_skip_ws(ctx);
        if (ctx->p >= ctx->end || *ctx->p != ':') {
            free(key);
            ctx->failed = true;
            return NULL;
        }
        ctx->p++;
        value = cc_parse_value(ctx);
        if (value == NULL) {
            free(key);
            return NULL;
        }
        if (!cc_grow((void **)&node->u.obj.items, &node->u.obj.cap,
                     node->u.obj.count + 1, sizeof(*node->u.obj.items))) {
            free(key);
            ctx->failed = true;
            return NULL;
        }
        node->u.obj.items[node->u.obj.count].key = key;
        node->u.obj.items[node->u.obj.count].value = value;
        node->u.obj.count++;
        cc_skip_ws(ctx);
        if (ctx->p >= ctx->end) {
            ctx->failed = true;
            return NULL;
        }
        if (*ctx->p == '}') {
            ctx->p++;
            return node;
        }
        if (*ctx->p != ',') {
            ctx->failed = true;
            return NULL;
        }
        ctx->p++;
    }
}

static cc_json_t *cc_parse_value_inner(cc_parse_ctx_t *ctx)
{
    cc_skip_ws(ctx);
    if (ctx->p >= ctx->end) {
        ctx->failed = true;
        return NULL;
    }
    switch (*ctx->p) {
    case '{':
        return cc_parse_object(ctx);
    case '[':
        return cc_parse_array(ctx);
    case '"': {
        cc_strbuf_t sb;
        char *data;
        cc_json_t *node;

        memset(&sb, 0, sizeof(sb));
        if (!cc_parse_string_buf(ctx, &sb)) {
            free(sb.data);
            return NULL;
        }
        data = cc_sb_take(&sb);
        if (data == NULL) {
            free(sb.data);
            ctx->failed = true;
            return NULL;
        }
        node = cc_node_new(ctx, CCJ_STR);
        if (node == NULL) {
            free(data);
            return NULL;
        }
        node->u.str.data = data;
        node->u.str.len = sb.len;
        return node;
    }
    case 't':
        return cc_parse_literal(ctx, "true", CCJ_BOOL, true);
    case 'f':
        return cc_parse_literal(ctx, "false", CCJ_BOOL, false);
    case 'n':
        return cc_parse_literal(ctx, "null", CCJ_NULL, false);
    default:
        if (*ctx->p == '-' || (*ctx->p >= '0' && *ctx->p <= '9')) {
            return cc_parse_number(ctx);
        }
        ctx->failed = true;
        return NULL;
    }
}

static cc_json_t *cc_parse_value(cc_parse_ctx_t *ctx)
{
    cc_json_t *node;

    if (ctx->depth >= 128) {
        ctx->failed = true;
        return NULL;
    }
    ctx->depth++;
    node = cc_parse_value_inner(ctx);
    ctx->depth--;
    return node;
}

cc_json_t *cc_json_parse(const char *text, size_t len)
{
    cc_parse_ctx_t ctx;
    cc_json_t *root;

    if (text == NULL || len == 0) {
        return NULL;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.p = text;
    ctx.end = text + len;
    if (len >= 3 && (unsigned char)text[0] == 0xEF &&
        (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF) {
        ctx.p += 3;
    }
    root = cc_parse_value(&ctx);
    cc_skip_ws(&ctx);
    if (ctx.failed || root == NULL || ctx.p != ctx.end) {
        cc_json_free(ctx.all);
        return NULL;
    }
    return root;
}

cc_json_t *cc_json_parse_file(const wchar_t *path)
{
    HANDLE file;
    LARGE_INTEGER size;
    size_t capacity;
    DWORD done = 0;
    char *buf;
    cc_json_t *result;

    if (path == NULL) {
        return NULL;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
        size.QuadPart > 128LL * 1024LL * 1024LL) {
        CloseHandle(file);
        return NULL;
    }
    capacity = (size_t)size.QuadPart;
    buf = (char *)malloc(capacity + 1);
    if (buf == NULL) {
        CloseHandle(file);
        return NULL;
    }
    while ((size_t)done < capacity) {
        DWORD got = 0;
        if (!ReadFile(file, buf + done, (DWORD)(capacity - done), &got, NULL) || got == 0) {
            break;
        }
        done += got;
    }
    buf[done] = '\0';
    result = cc_json_parse(buf, done);
    free(buf);
    CloseHandle(file);
    return result;
}

void cc_json_free(cc_json_t *j)
{
    while (j != NULL) {
        cc_json_t *next = j->next_all;
        if (j->kind == CCJ_STR) {
            free(j->u.str.data);
        } else if (j->kind == CCJ_ARR) {
            free(j->u.arr.items);
        } else if (j->kind == CCJ_OBJ) {
            int i;
            for (i = 0; i < j->u.obj.count; i++) {
                free(j->u.obj.items[i].key);
            }
            free(j->u.obj.items);
        }
        free(j);
        j = next;
    }
}

const cc_json_t *cc_json_obj_get(const cc_json_t *j, const char *key)
{
    int i;

    if (j == NULL || j->kind != CCJ_OBJ || key == NULL) {
        return NULL;
    }
    for (i = 0; i < j->u.obj.count; i++) {
        if (strcmp(j->u.obj.items[i].key, key) == 0) {
            return j->u.obj.items[i].value;
        }
    }
    return NULL;
}

const cc_json_t *cc_json_arr_get(const cc_json_t *j, int index)
{
    if (j == NULL || j->kind != CCJ_ARR || index < 0 || index >= j->u.arr.count) {
        return NULL;
    }
    return j->u.arr.items[index];
}

int cc_json_arr_len(const cc_json_t *j)
{
    if (j == NULL || j->kind != CCJ_ARR) {
        return 0;
    }
    return j->u.arr.count;
}

bool cc_json_is_str(const cc_json_t *j, const char **out)
{
    if (j == NULL || j->kind != CCJ_STR) {
        return false;
    }
    if (out != NULL) {
        *out = j->u.str.data;
    }
    return true;
}

bool cc_json_is_num(const cc_json_t *j, double *out)
{
    if (j == NULL || j->kind != CCJ_NUM) {
        return false;
    }
    if (out != NULL) {
        *out = j->u.num;
    }
    return true;
}

bool cc_json_is_bool(const cc_json_t *j, bool *out)
{
    if (j == NULL || j->kind != CCJ_BOOL) {
        return false;
    }
    if (out != NULL) {
        *out = j->u.b;
    }
    return true;
}

bool cc_json_get_str(const cc_json_t *j, const char *key, char *out, size_t cap)
{
    const cc_json_t *value = cc_json_obj_get(j, key);
    const char *src;
    size_t n;

    if (!cc_json_is_str(value, &src) || out == NULL || cap == 0) {
        return false;
    }
    if (src == NULL) {
        src = "";
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(out, src, n);
    out[n] = '\0';
    return true;
}

bool cc_json_get_double(const cc_json_t *j, const char *key, double *out)
{
    return cc_json_is_num(cc_json_obj_get(j, key), out);
}

bool cc_json_get_uint(const cc_json_t *j, const char *key, uint32_t *out)
{
    double value;

    if (!cc_json_get_double(j, key, &value) || out == NULL) {
        return false;
    }
    if (value < 0.0 || value > (double)UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

bool cc_json_get_bool(const cc_json_t *j, const char *key, bool *out)
{
    return cc_json_is_bool(cc_json_obj_get(j, key), out);
}

void cc_utf8_to_wide(const char *src, wchar_t *dst, size_t cap)
{
    int written;

    if (dst == NULL || cap == 0) {
        return;
    }
    dst[0] = L'\0';
    if (src == NULL) {
        return;
    }
    if (cap > (size_t)INT_MAX) {
        cap = (size_t)INT_MAX;
    }
    written = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)cap);
    if (written == 0) {
        dst[0] = L'\0';
    }
}

void cc_wide_to_utf8(const wchar_t *src, char *dst, size_t cap)
{
    int written;

    if (dst == NULL || cap == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }
    if (cap > (size_t)INT_MAX) {
        cap = (size_t)INT_MAX;
    }
    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)cap, NULL, NULL);
    if (written == 0) {
        dst[0] = '\0';
    }
}
