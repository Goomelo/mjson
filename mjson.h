#ifndef MJSON_H__
#define MJSON_H__

#include <stddef.h> /* size_t */

typedef enum { MJSON_NULL, MJSON_FALSE, MJSON_TRUE, MJSON_NUMBER, MJSON_STRING, MJSON_ARRAY, MJSON_OBJECT } mjson_type;

typedef struct mjson_value mjson_value;
typedef struct mjson_member mjson_member;

struct mjson_value {
    union {
        struct { mjson_member* m; size_t size; }o;   /* object: members, member count */
        struct { mjson_value* e; size_t size; }a;    /* array:  elements, element count */
        struct { char* s; size_t len; }s;           /* string: null-terminated string, string length */
        double n;                                   /* number */
    }u;
    mjson_type type;
};

struct mjson_member {
    char* k; size_t klen;   /* member key string, key string length */
    mjson_value v;           /* member value */
};

enum {
    MJSON_PARSE_OK = 0,
    MJSON_PARSE_EXPECT_VALUE,
    MJSON_PARSE_INVALID_VALUE,
    MJSON_PARSE_ROOT_NOT_SINGULAR,
    MJSON_PARSE_NUMBER_TOO_BIG,
    MJSON_PARSE_MISS_QUOTATION_MARK,
    MJSON_PARSE_INVALID_STRING_ESCAPE,
    MJSON_PARSE_INVALID_STRING_CHAR,
    MJSON_PARSE_INVALID_UNICODE_HEX,
    MJSON_PARSE_INVALID_UNICODE_SURROGATE,
    MJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
    MJSON_PARSE_MISS_KEY,
    MJSON_PARSE_MISS_COLON,
    MJSON_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};

#define mjson_init(v) do { (v)->type = MJSON_NULL; } while(0)

int mjson_parse(mjson_value* v, const char* json);
char* mjson_stringify(const mjson_value* v, size_t* length);

void mjson_free(mjson_value* v);

mjson_type mjson_get_type(const mjson_value* v);

#define mjson_set_null(v) mjson_free(v)

int mjson_get_boolean(const mjson_value* v);
void mjson_set_boolean(mjson_value* v, int b);

double mjson_get_number(const mjson_value* v);
void mjson_set_number(mjson_value* v, double n);

const char* mjson_get_string(const mjson_value* v);
size_t mjson_get_string_length(const mjson_value* v);
void mjson_set_string(mjson_value* v, const char* s, size_t len);

size_t mjson_get_array_size(const mjson_value* v);
mjson_value* mjson_get_array_element(const mjson_value* v, size_t index);

size_t mjson_get_object_size(const mjson_value* v);
const char* mjson_get_object_key(const mjson_value* v, size_t index);
size_t mjson_get_object_key_length(const mjson_value* v, size_t index);
mjson_value* mjson_get_object_value(const mjson_value* v, size_t index);

#endif /* MJSONJSON_H__ */
