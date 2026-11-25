#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ioc_internal.h"

typedef enum {
    CCJ_NULL = 0,
    CCJ_BOOL,
    CCJ_NUM,
    CCJ_STR,
    CCJ_ARR,
    CCJ_OBJ
} ccj_kind_t;

typedef struct {
    char *key;
    cc_json_t *value;
} ccj_pair_t;

struct ccj_node_s {
    ccj_kind_t kind;
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
            ccj_pair_t *items;
            int count;
            int cap;
        } obj;
    } u;
    cc_json_t *next_all;
};

static void wlower_copy(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t i = 0;
    if (dst == NULL || cap == 0) return;
    if (src != NULL) {
        while (i + 1 < cap && src[i] != L'\0') {
            dst[i] = (wchar_t)towlower((wint_t)src[i]);
            i++;
        }
    }
    dst[i] = L'\0';
}

static bool wcontains_i(const wchar_t *hay, const wchar_t *needle)
{
    wchar_t *hl = NULL;
    wchar_t *nl = NULL;
    size_t hlen, nlen;
    bool ok = false;
    if (hay == NULL || needle == NULL || needle[0] == L'\0') return false;
    hlen = wcslen(hay);
    nlen = wcslen(needle);
    hl = (wchar_t *)malloc((hlen + 1) * sizeof(wchar_t));
    nl = (wchar_t *)malloc((nlen + 1) * sizeof(wchar_t));
    if (hl == NULL || nl == NULL) goto done;
    wlower_copy(hl, hlen + 1, hay);
    wlower_copy(nl, nlen + 1, needle);
    ok = wcsstr(hl, nl) != NULL;
done:
    free(hl);
    free(nl);
    return ok;
}

static bool weq_i(const wchar_t *a, const wchar_t *b)
{
    size_t i = 0;
    if (a == NULL || b == NULL) return false;
    while (a[i] != L'\0' && b[i] != L'\0') {
        if (towlower((wint_t)a[i]) != towlower((wint_t)b[i])) return false;
        i++;
    }
    return a[i] == b[i];
}

static bool hash_eq_i(const char *a, const char *b)
{
    size_t i = 0;
    if (a == NULL || b == NULL) return false;
    while (a[i] != '\0' && b[i] != '\0') {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'F') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'F') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
        i++;
    }
    return a[i] == b[i];
}

static void load_names(const cc_json_t *arr, wchar_t dst[][CC_MAX_NAME], int maxn, int *out_n)
{
    int n = cc_json_arr_len(arr);
    int i;
    *out_n = 0;
    for (i = 0; i < n && *out_n < maxn; i++) {
        const cc_json_t *it = cc_json_arr_get(arr, i);
        const char *s = NULL;
        if (!cc_json_is_str(it, &s) || s == NULL) continue;
        cc_utf8_to_wide(s, dst[*out_n], CC_MAX_NAME);
        if (dst[*out_n][0] != L'\0') (*out_n)++;
    }
}

static void load_paths(const cc_json_t *arr, wchar_t dst[][CC_MAX_PATH_LEN], int maxn, int *out_n)
{
    int n = cc_json_arr_len(arr);
    int i;
    *out_n = 0;
    for (i = 0; i < n && *out_n < maxn; i++) {
        const cc_json_t *it = cc_json_arr_get(arr, i);
        const char *s = NULL;
        if (!cc_json_is_str(it, &s) || s == NULL) continue;
        cc_utf8_to_wide(s, dst[*out_n], CC_MAX_PATH_LEN);
        if (dst[*out_n][0] != L'\0') (*out_n)++;
    }
}

static void load_ipv4(const cc_json_t *arr, uint32_t dst[64], int maxn, int *out_n)
{
    int n = cc_json_arr_len(arr);
    int i;

    *out_n = 0;
    for (i = 0; i < n && *out_n < maxn; i++) {
        const cc_json_t *it = cc_json_arr_get(arr, i);
        const char *s = NULL;
        uint32_t addr = 0;
        if (!cc_json_is_str(it, &s) || s == NULL || s[0] == '\0') continue;
        if (InetPtonA(AF_INET, s, &addr) != 1) continue;
        dst[(*out_n)++] = addr;
    }
}

static void load_ports(const cc_json_t *arr, uint16_t dst[128], int maxn, int *out_n)
{
    int n = cc_json_arr_len(arr);
    int i;

    *out_n = 0;
    for (i = 0; i < n && *out_n < maxn; i++) {
        const cc_json_t *it = cc_json_arr_get(arr, i);
        const char *s = NULL;
        char *stop = NULL;
        unsigned long value = 0;
        double num = 0.0;

        if (cc_json_is_str(it, &s) && s != NULL && s[0] != '\0') {
            value = strtoul(s, &stop, 10);
            if (stop == s || *stop != '\0') continue;
        } else if (cc_json_is_num(it, &num)) {
            if (num < 1.0 || num > 65535.0) continue;
            value = (unsigned long)num;
        } else {
            continue;
        }
        if (value == 0 || value > 65535) continue;
        dst[(*out_n)++] = (uint16_t)value;
    }
}

cc_ioc_t *cc_ioc_load(const wchar_t *path)
{
    cc_json_t *root;
    cc_ioc_t *ioc;
    const cc_json_t *arr;
    const cc_json_t *sp;
    int i, n;

    if (path == NULL) return NULL;
    root = cc_json_parse_file(path);
    if (root == NULL) return NULL;
    ioc = (cc_ioc_t *)calloc(1, sizeof(*ioc));
    if (ioc == NULL) { cc_json_free(root); return NULL; }

    arr = cc_json_obj_get(root, "process_names");
    if (arr != NULL) load_names(arr, ioc->proc_names, 256, &ioc->proc_names_n);
    arr = cc_json_obj_get(root, "path_substrings");
    if (arr != NULL) load_paths(arr, ioc->path_subs, 128, &ioc->path_subs_n);
    arr = cc_json_obj_get(root, "hashes_sha256");
    if (arr != NULL) {
        n = cc_json_arr_len(arr);
        for (i = 0; i < n && ioc->hashes_n < 128; i++) {
            const cc_json_t *it = cc_json_arr_get(arr, i);
            const char *s = NULL;
            size_t j, k;
            if (!cc_json_is_str(it, &s) || s == NULL) continue;
            k = 0;
            for (j = 0; s[j] != '\0' && k < 64; j++) {
                char c = s[j];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                    if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
                    ioc->hashes[ioc->hashes_n][k++] = c;
                }
            }
            ioc->hashes[ioc->hashes_n][k] = '\0';
            if (k == 64) ioc->hashes_n++;
        }
    }
    arr = cc_json_obj_get(root, "service_names");
    if (arr != NULL) load_names(arr, ioc->svc_names, 128, &ioc->svc_names_n);
    arr = cc_json_obj_get(root, "service_path_substrings");
    if (arr != NULL) load_paths(arr, ioc->svc_path_subs, 64, &ioc->svc_path_subs_n);
    arr = cc_json_obj_get(root, "malicious_ips");
    if (arr != NULL) load_ipv4(arr, ioc->malicious_ipv4, 64, &ioc->malicious_ipv4_n);
    arr = cc_json_obj_get(root, "suspicious_ports");
    if (arr != NULL) load_ports(arr, ioc->suspicious_ports, 128, &ioc->suspicious_ports_n);

    sp = cc_json_obj_get(root, "suspicious_parents");
    if (sp != NULL) {
        const struct ccj_node_s *node = (const struct ccj_node_s *)sp;
        if (node->kind == CCJ_OBJ) {
            int pc = node->u.obj.count;
            for (i = 0; i < pc && ioc->parents_n < 64; i++) {
                const ccj_pair_t *pair = &node->u.obj.items[i];
                const struct ccj_node_s *val;
                int cn, j;
                if (pair->key == NULL || pair->value == NULL) continue;
                val = (const struct ccj_node_s *)pair->value;
                if (val->kind != CCJ_ARR) continue;
                cc_utf8_to_wide(pair->key, ioc->parents[ioc->parents_n].parent, CC_MAX_NAME);
                ioc->parents[ioc->parents_n].n = 0;
                cn = cc_json_arr_len(pair->value);
                for (j = 0; j < cn && ioc->parents[ioc->parents_n].n < 16; j++) {
                    const cc_json_t *cit = cc_json_arr_get(pair->value, j);
                    const char *cs = NULL;
                    if (!cc_json_is_str(cit, &cs) || cs == NULL) continue;
                    cc_utf8_to_wide(cs, ioc->parents[ioc->parents_n].children[ioc->parents[ioc->parents_n].n], CC_MAX_NAME);
                    if (ioc->parents[ioc->parents_n].children[ioc->parents[ioc->parents_n].n][0] != L'\0')
                        ioc->parents[ioc->parents_n].n++;
                }
                if (ioc->parents[ioc->parents_n].parent[0] != L'\0') ioc->parents_n++;
            }
        }
    }

    cc_json_free(root);
    return ioc;
}

void cc_ioc_free(cc_ioc_t *ioc)
{
    free(ioc);
}

int cc_ioc_count(const cc_ioc_t *ioc)
{
    if (ioc == NULL) return 0;
    return ioc->proc_names_n + ioc->path_subs_n + ioc->hashes_n + ioc->svc_names_n +
           ioc->svc_path_subs_n + ioc->malicious_ipv4_n + ioc->suspicious_ports_n + ioc->parents_n;
}

bool cc_ioc_match_proc(const cc_ioc_t *ioc, const wchar_t *name, const wchar_t *path, const char *sha256)
{
    int i;
    if (ioc == NULL) return false;
    if (name != NULL && name[0] != L'\0') {
        for (i = 0; i < ioc->proc_names_n; i++) {
            if (weq_i(name, ioc->proc_names[i])) return true;
        }
    }
    if (path != NULL && path[0] != L'\0') {
        for (i = 0; i < ioc->path_subs_n; i++) {
            if (wcontains_i(path, ioc->path_subs[i])) return true;
        }
    }
    if (sha256 != NULL && sha256[0] != '\0') {
        for (i = 0; i < ioc->hashes_n; i++) {
            if (hash_eq_i(sha256, ioc->hashes[i])) return true;
        }
    }
    return false;
}

bool cc_ioc_match_service(const cc_ioc_t *ioc, const wchar_t *service_name, const wchar_t *service_path)
{
    int i;
    if (ioc == NULL) return false;
    if (service_name != NULL && service_name[0] != L'\0') {
        for (i = 0; i < ioc->svc_names_n; i++) {
            if (weq_i(service_name, ioc->svc_names[i])) return true;
        }
    }
    if (service_path != NULL && service_path[0] != L'\0') {
        for (i = 0; i < ioc->svc_path_subs_n; i++) {
            if (wcontains_i(service_path, ioc->svc_path_subs[i])) return true;
        }
    }
    return false;
}

bool cc_ioc_is_malicious_ipv4(const cc_ioc_t *ioc, uint32_t addr)
{
    int i;

    if (ioc == NULL || addr == 0) return false;
    for (i = 0; i < ioc->malicious_ipv4_n; i++) {
        if (ioc->malicious_ipv4[i] == addr) return true;
    }
    return false;
}

bool cc_ioc_is_suspicious_port(const cc_ioc_t *ioc, uint16_t port)
{
    int i;

    if (ioc == NULL || port == 0) return false;
    for (i = 0; i < ioc->suspicious_ports_n; i++) {
        if (ioc->suspicious_ports[i] == port) return true;
    }
    return false;
}

bool cc_ioc_parent_child_match(const struct cc_ioc_s *ioc, const wchar_t *parent, const wchar_t *child)
{
    int i, j;
    if (ioc == NULL || parent == NULL || child == NULL) return false;
    for (i = 0; i < ioc->parents_n; i++) {
        if (!weq_i(parent, ioc->parents[i].parent)) continue;
        for (j = 0; j < ioc->parents[i].n; j++) {
            if (weq_i(child, ioc->parents[i].children[j])) return true;
        }
    }
    return false;
}

struct cc_publishers_s {
    wchar_t names[256][128];
    int count;
};

cc_publishers_t *cc_publishers_load(const wchar_t *path)
{
    cc_json_t *root;
    cc_publishers_t *p;
    const cc_json_t *arr;
    int i, n;
    if (path == NULL) return NULL;
    root = cc_json_parse_file(path);
    if (root == NULL) return NULL;
    p = (cc_publishers_t *)calloc(1, sizeof(*p));
    if (p == NULL) { cc_json_free(root); return NULL; }
    arr = cc_json_obj_get(root, "trusted_publishers");
    if (arr != NULL) {
        n = cc_json_arr_len(arr);
        for (i = 0; i < n && p->count < 256; i++) {
            const cc_json_t *it = cc_json_arr_get(arr, i);
            const char *s = NULL;
            if (!cc_json_is_str(it, &s) || s == NULL) continue;
            cc_utf8_to_wide(s, p->names[p->count], 128);
            if (p->names[p->count][0] != L'\0') p->count++;
        }
    }
    cc_json_free(root);
    return p;
}

void cc_publishers_free(cc_publishers_t *p)
{
    free(p);
}

bool cc_publishers_is_trusted(const cc_publishers_t *p, const wchar_t *publisher)
{
    int i;
    if (p == NULL || publisher == NULL || publisher[0] == L'\0') return false;
    for (i = 0; i < p->count; i++) {
        if (p->names[i][0] == L'\0') continue;
        if (weq_i(publisher, p->names[i])) return true;
    }
    return false;
}
