#include <stdio.h>

extern const char *test_json_parse_object(void);
extern const char *test_json_accessors(void);
extern const char *test_json_utf8(void);
extern const char *test_ioc_load_match(void);
extern const char *test_ioc_publishers(void);
extern const char *test_ioc_network(void);
extern const char *test_response_denylist(void);
extern const char *test_response_ip_denylist(void);
extern const char *test_config_defaults(void);
extern const char *test_network_scan_snapshot(void);

#define ASSERT_TRUE(cond, msg) \
    do { \
        if (!(cond)) { \
            return (msg); \
        } \
    } while (0)

#define ASSERT_EQ_INT(a, b) \
    do { \
        if ((long)(a) != (long)(b)) { \
            return "ASSERT_EQ_INT failed: " #a " != " #b; \
        } \
    } while (0)

typedef const char *(*cc_test_fn_t)(void);

static int run_one(const char *name, cc_test_fn_t fn)
{
    const char *err = fn();
    if (err != NULL) {
        printf("FAIL %s: %s\n", name, err);
        return 1;
    }
    printf("PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failed = 0;
    failed += run_one("test_json_parse_object", test_json_parse_object);
    failed += run_one("test_json_accessors", test_json_accessors);
    failed += run_one("test_json_utf8", test_json_utf8);
    failed += run_one("test_ioc_load_match", test_ioc_load_match);
    failed += run_one("test_ioc_publishers", test_ioc_publishers);
    failed += run_one("test_ioc_network", test_ioc_network);
    failed += run_one("test_response_denylist", test_response_denylist);
    failed += run_one("test_response_ip_denylist", test_response_ip_denylist);
    failed += run_one("test_config_defaults", test_config_defaults);
    failed += run_one("test_network_scan_snapshot", test_network_scan_snapshot);
    if (failed != 0) {
        printf("%d test(s) failed\n", failed);
    }
    return failed != 0;
}
