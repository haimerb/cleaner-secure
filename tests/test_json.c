#include "json.h"

#include <string.h>
#include <wchar.h>

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

const char *test_json_parse_object(void)
{
    static const char src[] =
        "{\"name\":\"xmrig.exe\",\"count\":42,\"ratio\":1.5,"
        "\"enabled\":true,\"disabled\":false,"
        "\"paths\":[\"C:\\\\Windows\\\\a.exe\",\"b.exe\"],"
        "\"nested\":{\"key\":\"val\"}}";
    cc_json_t *j = cc_json_parse(src, strlen(src));
    ASSERT_TRUE(j != NULL, "cc_json_parse returned NULL");

    const cc_json_t *name = cc_json_obj_get(j, "name");
    ASSERT_TRUE(name != NULL, "obj_get name");
    ASSERT_TRUE(cc_json_obj_get(j, "paths") != NULL, "obj_get paths");
    ASSERT_TRUE(cc_json_obj_get(j, "nested") != NULL, "obj_get nested");
    ASSERT_TRUE(cc_json_obj_get(j, "missing_key") == NULL, "obj_get missing_key");

    const cc_json_t *paths = cc_json_obj_get(j, "paths");
    ASSERT_EQ_INT(cc_json_arr_len(paths), 2);

    const cc_json_t *first = cc_json_arr_get(paths, 0);
    ASSERT_TRUE(first != NULL, "arr_get 0");
    const char *s = NULL;
    ASSERT_TRUE(cc_json_is_str(first, &s), "is_str first path");
    ASSERT_TRUE(s != NULL && strcmp(s, "C:\\Windows\\a.exe") == 0, "first path value");

    const cc_json_t *last = cc_json_arr_get(paths, 1);
    ASSERT_TRUE(last != NULL, "arr_get 1");
    ASSERT_TRUE(cc_json_is_str(last, &s), "is_str second path");
    ASSERT_TRUE(s != NULL && strcmp(s, "b.exe") == 0, "second path value");

    const cc_json_t *nested = cc_json_obj_get(j, "nested");
    const cc_json_t *key = cc_json_obj_get(nested, "key");
    ASSERT_TRUE(key != NULL, "obj_get nested.key");
    ASSERT_TRUE(cc_json_is_str(key, &s), "is_str nested.key");
    ASSERT_TRUE(s != NULL && strcmp(s, "val") == 0, "nested.key value");

    cc_json_free(j);
    return NULL;
}

const char *test_json_accessors(void)
{
    static const char src[] =
        "{\"name\":\"xmrig.exe\",\"count\":42,\"ratio\":1.5,"
        "\"enabled\":true,\"disabled\":false}";
    cc_json_t *j = cc_json_parse(src, strlen(src));
    ASSERT_TRUE(j != NULL, "cc_json_parse returned NULL");

    char buf[64];
    ASSERT_TRUE(cc_json_get_str(j, "name", buf, sizeof buf), "get_str name");
    ASSERT_TRUE(strcmp(buf, "xmrig.exe") == 0, "get_str name value");

    double d = 0.0;
    ASSERT_TRUE(cc_json_get_double(j, "ratio", &d), "get_double ratio");
    ASSERT_TRUE(d > 1.49 && d < 1.51, "get_double ratio value");

    uint32_t u = 0;
    ASSERT_TRUE(cc_json_get_uint(j, "count", &u), "get_uint count");
    ASSERT_EQ_INT((int)u, 42);

    bool b = false;
    ASSERT_TRUE(cc_json_get_bool(j, "enabled", &b), "get_bool enabled");
    ASSERT_TRUE(b, "enabled is not true");
    b = true;
    ASSERT_TRUE(cc_json_get_bool(j, "disabled", &b), "get_bool disabled");
    ASSERT_TRUE(!b, "disabled is not false");

    cc_json_free(j);
    return NULL;
}

const char *test_json_utf8(void)
{
    wchar_t wide[64];
    char utf8[64];

    cc_utf8_to_wide("hello", wide, 64);
    ASSERT_TRUE(wcscmp(wide, L"hello") == 0, "cc_utf8_to_wide ascii");

    cc_wide_to_utf8(L"hello", utf8, 64);
    ASSERT_TRUE(strcmp(utf8, "hello") == 0, "cc_wide_to_utf8 ascii");

    cc_utf8_to_wide("caf\xc3\xa9", wide, 64);
    ASSERT_TRUE(wide[0] == L'c' && wide[3] == 0x00E9 && wide[4] == 0,
                "cc_utf8_to_wide multi-byte");

    cc_wide_to_utf8(wide, utf8, 64);
    ASSERT_TRUE(strcmp(utf8, "caf\xc3\xa9") == 0, "utf8 roundtrip");
    return NULL;
}
