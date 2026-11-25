#include "detect.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcomment"
#include "config.h"
#pragma clang diagnostic pop
#include "ioc_internal.h"
#include "json.h"
#include "metrics.h"
#include "proc.h"
#include "trust.h"
#include "virustotal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

struct cc_trust_cache_s {
    struct {
        wchar_t path[CC_MAX_PATH_LEN];
        cc_trust_result_t r;
        bool used;
    } items[512];
    int count;
};

typedef struct {
    uint32_t pid;
    ULONGLONG first_tick;
    bool active;
} cc_cpu_sustain_t;

static cc_cpu_sustain_t g_cpu_sustain[4096];

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

static int find_pid_index(const cc_proc_info_t *procs, int n, uint32_t pid)
{
    int i;
    for (i = 0; i < n; i++) {
        if (procs[i].pid == pid) return i;
    }
    return -1;
}

static cc_cpu_sustain_t *cpu_entry(uint32_t pid)
{
    int i;
    int free_idx = -1;
    for (i = 0; i < 4096; i++) {
        if (g_cpu_sustain[i].active && g_cpu_sustain[i].pid == pid) return &g_cpu_sustain[i];
        if (!g_cpu_sustain[i].active && free_idx < 0) free_idx = i;
    }
    if (free_idx >= 0) {
        g_cpu_sustain[free_idx].pid = pid;
        g_cpu_sustain[free_idx].first_tick = 0;
        g_cpu_sustain[free_idx].active = true;
        return &g_cpu_sustain[free_idx];
    }
    return NULL;
}

static void cpu_mark_below(uint32_t pid)
{
    int i;
    for (i = 0; i < 4096; i++) {
        if (g_cpu_sustain[i].active && g_cpu_sustain[i].pid == pid) {
            g_cpu_sustain[i].first_tick = 0;
            return;
        }
    }
}

static bool push_alert(cc_alert_t *out, int cap, int *count, cc_risk_t risk, const char *category,
                       const wchar_t *target, uint32_t pid, const char *reason)
{
    cc_alert_t *a;
    if (out == NULL || count == NULL || cap <= 0) return false;
    if (*count >= cap) return false;
    a = &out[*count];
    memset(a, 0, sizeof(*a));
    a->risk = risk;
    a->pid = pid;
    if (category != NULL) {
        strncpy(a->category, category, sizeof(a->category) - 1);
        a->category[sizeof(a->category) - 1] = '\0';
    }
    if (reason != NULL) {
        strncpy(a->reason, reason, sizeof(a->reason) - 1);
        a->reason[sizeof(a->reason) - 1] = '\0';
    }
    if (target != NULL) {
        wcsncpy(a->target, target, CC_MAX_NAME - 1);
        a->target[CC_MAX_NAME - 1] = L'\0';
    }
    (*count)++;
    return true;
}

cc_trust_cache_t *cc_trust_cache_create(void)
{
    return (cc_trust_cache_t *)calloc(1, sizeof(cc_trust_cache_t));
}

void cc_trust_cache_free(cc_trust_cache_t *c)
{
    free(c);
}

static int trust_cache_find(cc_trust_cache_t *c, const wchar_t *path)
{
    int i;
    if (c == NULL || path == NULL) return -1;
    for (i = 0; i < c->count; i++) {
        if (c->items[i].used && weq_i(c->items[i].path, path)) return i;
    }
    return -1;
}

const cc_trust_result_t *cc_trust_cache_get(cc_trust_cache_t *c, const wchar_t *path,
                                            bool vt_live)
{
    int idx;
    cc_trust_result_t tr;
    if (c == NULL || path == NULL || path[0] == L'\0') return NULL;
    idx = trust_cache_find(c, path);
    if (idx >= 0) return &c->items[idx].r;
    if (c->count >= 512) return NULL;
    memset(&tr, 0, sizeof(tr));
    tr.virustotal_hits = -1;
    tr.virustotal_total = -1;
    (void)cc_trust_verify(path, &tr);
    if (tr.signature_valid && tr.hash_sha256[0] != '\0') {
        (void)cc_virustotal_lookup_ex(tr.hash_sha256, &tr, vt_live);
    }
    idx = c->count++;
    c->items[idx].used = true;
    wcsncpy(c->items[idx].path, path, CC_MAX_PATH_LEN - 1);
    c->items[idx].path[CC_MAX_PATH_LEN - 1] = L'\0';
    c->items[idx].r = tr;
    return &c->items[idx].r;
}

static bool path_suspicious_dir(const wchar_t *path)
{
    if (path == NULL || path[0] == L'\0') return false;
    return wcontains_i(path, L"\\temp\\") ||
           wcontains_i(path, L"\\users\\public\\") ||
           wcontains_i(path, L"\\$recycle.bin\\") ||
           wcontains_i(path, L"\\windows\\tasks\\");
}

static bool path_in_protected_dir(const wchar_t *path)
{
    if (path == NULL || path[0] == L'\0') return false;
    if (path_suspicious_dir(path)) return false;
    return wcontains_i(path, L"\\windows\\") ||
           wcontains_i(path, L"\\program files") ||
           wcontains_i(path, L"\\programdata\\microsoft\\");
}

static void format_target(wchar_t *dst, size_t cap, const wchar_t *name, const wchar_t *path)
{
    if (dst == NULL || cap == 0) return;
    dst[0] = L'\0';
    if (name != NULL && name[0] != L'\0') {
        wcsncpy(dst, name, cap - 1);
        dst[cap - 1] = L'\0';
        return;
    }
    if (path != NULL) {
        wcsncpy(dst, path, cap - 1);
        dst[cap - 1] = L'\0';
    }
}

static void add_resource_alerts(const cc_detect_ctx_t *ctx, cc_alert_t *out, int cap, int *count,
                                uint32_t pid, const wchar_t *target, const cc_proc_metrics_t *m)
{
    char reason[CC_MAX_REASON];
    ULONGLONG now;
    cc_cpu_sustain_t *ce;
    uint32_t sustain_s;
    uint64_t io_total;
    const cc_config_t *cfg;

    if (ctx == NULL || ctx->cfg == NULL || m == NULL) return;
    cfg = (const cc_config_t *)(const void *)ctx->cfg;
    if (m->cpu_percent >= cfg->cpu_percent_threshold) {
        now = GetTickCount64();
        ce = cpu_entry(pid);
        if (ce != NULL) {
            if (ce->first_tick == 0) ce->first_tick = now;
            sustain_s = (uint32_t)((now - ce->first_tick) / 1000ULL);
            if (sustain_s >= cfg->cpu_sustain_seconds) {
                snprintf(reason, sizeof(reason), "CPU %.1f%% sustained for %u seconds", m->cpu_percent, sustain_s);
                push_alert(out, cap, count, CC_RISK_HIGH, "resource", target, pid, reason);
            }
        }
    } else {
        cpu_mark_below(pid);
    }

    if (m->working_set >= cfg->ram_bytes_threshold) {
        snprintf(reason, sizeof(reason), "RAM usage %llu bytes exceeds threshold %llu bytes",
                 (unsigned long long)m->working_set, (unsigned long long)cfg->ram_bytes_threshold);
        push_alert(out, cap, count, CC_RISK_HIGH, "resource", target, pid, reason);
    }
    if (m->handle_count >= (uint64_t)cfg->handle_threshold) {
        snprintf(reason, sizeof(reason), "Handle count %llu exceeds threshold %u",
                 (unsigned long long)m->handle_count, cfg->handle_threshold);
        push_alert(out, cap, count, CC_RISK_MEDIUM, "resource", target, pid, reason);
    }
    io_total = m->io_read_bytes + m->io_write_bytes;
    if (io_total >= cfg->io_bytes_threshold) {
        snprintf(reason, sizeof(reason), "IO %llu bytes exceeds threshold %llu bytes",
                 (unsigned long long)io_total, (unsigned long long)cfg->io_bytes_threshold);
        push_alert(out, cap, count, CC_RISK_MEDIUM, "resource", target, pid, reason);
    }
}

int cc_detect_processes(const cc_detect_ctx_t *ctx, cc_alert_t *out, int cap,
                        ULONGLONG deadline)
{
    cc_proc_info_t *procs = NULL;
    cc_service_info_t *svcs = NULL;
    cc_trust_cache_t *local_cache = NULL;
    cc_trust_cache_t *cache;
    int proc_n = 0;
    int svc_n = 0;
    int count = 0;
    int live_budget;
    int i;
    int k;
    DWORD self_pid;

    if (ctx == NULL || out == NULL || cap <= 0 || ctx->cfg == NULL) return 0;
    procs = (cc_proc_info_t *)calloc(CC_MAX_PROCS, sizeof(cc_proc_info_t));
    if (procs == NULL) return 0;
    proc_n = cc_proc_list(procs, CC_MAX_PROCS);
    self_pid = GetCurrentProcessId();
    live_budget = ctx->vt_live_budget;
    cache = ctx->trust_cache;
    if (cache == NULL) {
        local_cache = cc_trust_cache_create();
        cache = local_cache;
    }

    for (i = 0; i < proc_n && count < cap && GetTickCount64() < deadline; i++) {
        cc_proc_info_t *p = &procs[i];
        cc_proc_metrics_t m;
        wchar_t target[CC_MAX_NAME];
        char reason[CC_MAX_REASON];
        const wchar_t *pname;
        int pidx;

        if (p->pid == 0 || p->pid == 4 || p->pid == (uint32_t)self_pid) continue;
        format_target(target, CC_MAX_NAME, p->name[0] ? p->name : NULL, p->path[0] ? p->path : NULL);

        memset(&m, 0, sizeof(m));
        if (ctx->metrics != NULL && cc_metrics_sample(ctx->metrics, p->pid, &m)) {
            add_resource_alerts(ctx, out, cap, &count, p->pid, target, &m);
            if (count >= cap) break;
        }

        if (ctx->ioc != NULL && cc_ioc_match_proc(ctx->ioc, p->name, p->path, NULL)) {
            char nbuf[CC_MAX_NAME];
            cc_wide_to_utf8(p->name, nbuf, sizeof(nbuf));
            snprintf(reason, sizeof(reason), "IOC process match: %s", nbuf[0] ? nbuf : "unknown");
            push_alert(out, cap, &count, CC_RISK_CRITICAL, "ioc", target, p->pid, reason);
            if (count >= cap) break;
        }

        if (ctx->ioc != NULL) {
            pidx = find_pid_index(procs, proc_n, p->parent_pid);
            if (pidx >= 0) {
                pname = procs[pidx].name;
                if (cc_ioc_parent_child_match(ctx->ioc, pname, p->name)) {
                    char pbuf[CC_MAX_NAME], cbuf[CC_MAX_NAME];
                    cc_wide_to_utf8(pname, pbuf, sizeof(pbuf));
                    cc_wide_to_utf8(p->name, cbuf, sizeof(cbuf));
                    snprintf(reason, sizeof(reason), "Suspicious parent-child: %s -> %s", pbuf, cbuf);
                    push_alert(out, cap, &count, CC_RISK_HIGH, "anomaly", target, p->pid, reason);
                    if (count >= cap) break;
                }
            }
        }

        if (p->path[0] != L'\0') {
            if (path_suspicious_dir(p->path)) {
                char pbuf[CC_MAX_PATH_LEN];
                cc_wide_to_utf8(p->path, pbuf, sizeof(pbuf));
                snprintf(reason, sizeof(reason), "Suspicious process path: %s", pbuf);
                push_alert(out, cap, &count, CC_RISK_MEDIUM, "anomaly", target, p->pid, reason);
                if (count >= cap) break;
            }
        }

        if (p->path[0] != L'\0' && cache != NULL && GetTickCount64() < deadline &&
            !path_in_protected_dir(p->path)) {
            bool allow_live = ctx->vt_live && live_budget > 0;
            const cc_trust_result_t *tr;
            if (allow_live) {
                live_budget--;
            }
            tr = cc_trust_cache_get(cache, p->path, allow_live);
            if (tr != NULL) {
                bool trusted_pub = tr->publisher[0] != L'\0' && ctx->pubs != NULL && cc_publishers_is_trusted(ctx->pubs, tr->publisher);
                if (!tr->signature_valid && !path_in_protected_dir(p->path)) {
                    push_alert(out, cap, &count, CC_RISK_HIGH, "signature", target, p->pid, "unsigned or invalid signature");
                    if (count >= cap) break;
                } else if (!trusted_pub && tr->publisher[0] != L'\0') {
                    char pub[256];
                    cc_wide_to_utf8(tr->publisher, pub, sizeof(pub));
                    snprintf(reason, sizeof(reason), "untrusted publisher: %s", pub);
                    push_alert(out, cap, &count, CC_RISK_MEDIUM, "signature", target, p->pid, reason);
                    if (count >= cap) break;
                }
                if (tr->virustotal_hits > 0) {
                    snprintf(reason, sizeof(reason), "VirusTotal: %d/%d", (int)tr->virustotal_hits, (int)tr->virustotal_total);
                    push_alert(out, cap, &count, CC_RISK_CRITICAL, "signature", target, p->pid, reason);
                    if (count >= cap) break;
                }
            }
        }
    }

    svcs = (cc_service_info_t *)calloc(CC_MAX_SERVICES, sizeof(cc_service_info_t));
    if (svcs != NULL) {
        svc_n = cc_service_list(svcs, CC_MAX_SERVICES);
        if (svc_n < 0) svc_n = 0;
        for (i = 0; i < svc_n && count < cap && GetTickCount64() < deadline; i++) {
            cc_service_info_t *s = &svcs[i];
            wchar_t target[CC_MAX_NAME];
            char reason[CC_MAX_REASON];
            cc_proc_metrics_t m;
            format_target(target, CC_MAX_NAME, s->name[0] ? s->name : NULL, s->path[0] ? s->path : NULL);

            if (ctx->ioc != NULL && cc_ioc_match_service(ctx->ioc, s->name, s->path)) {
                char nbuf[CC_MAX_NAME];
                cc_wide_to_utf8(s->name, nbuf, sizeof(nbuf));
                snprintf(reason, sizeof(reason), "IOC service match: %s", nbuf[0] ? nbuf : "unknown");
                push_alert(out, cap, &count, CC_RISK_CRITICAL, "ioc", target, s->pid, reason);
                if (count >= cap) break;
            }

            if (s->path[0] != L'\0' && path_suspicious_dir(s->path)) {
                char pbuf[CC_MAX_PATH_LEN];
                cc_wide_to_utf8(s->path, pbuf, sizeof(pbuf));
                snprintf(reason, sizeof(reason), "Suspicious service path: %s", pbuf);
                push_alert(out, cap, &count, CC_RISK_HIGH, "anomaly", target, s->pid, reason);
                if (count >= cap) break;
            }

            if (s->pid != 0 && ctx->metrics != NULL && cc_metrics_sample(ctx->metrics, s->pid, &m)) {
                bool duplicate = false;
                for (k = 0; k < count; k++) {
                    if (out[k].pid == s->pid && strcmp(out[k].category, "resource") == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    add_resource_alerts(ctx, out, cap, &count, s->pid, target, &m);
                    if (count >= cap) break;
                }
            }
        }
    }

    cc_trust_cache_free(local_cache);
    free(svcs);
    free(procs);
    return count;
}

int cc_alert_score(cc_risk_t risk, const char *category)
{
    int score = 0;
    switch (risk) {
    case CC_RISK_NONE: score = 0; break;
    case CC_RISK_LOW: score = 25; break;
    case CC_RISK_MEDIUM: score = 50; break;
    case CC_RISK_HIGH: score = 75; break;
    case CC_RISK_CRITICAL: score = 100; break;
    default: score = 0; break;
    }
    if (category != NULL) {
        if (strcmp(category, "ioc") == 0 || strcmp(category, "signature") == 0 ||
            strcmp(category, "network") == 0) score += 5;
    }
    if (score > 100) score = 100;
    return score;
}
