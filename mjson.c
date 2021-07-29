#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "mjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#ifndef MJSON_PARSE_STACK_INIT_SIZE
#define MJSON_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)mjson_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}mjson_context;


static int mjson_parse_value(mjson_context* c, mjson_value* v);

static void* mjson_context_push(mjson_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = MJSON_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* mjson_context_pop(mjson_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void mjson_parse_whitespace(mjson_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int mjson_parse_literal(mjson_context* c, mjson_value* v, const char* literal, mjson_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return MJSON_PARSE_INVALID_VALUE;
    c->json += i;
    v->type = type;
    return MJSON_PARSE_OK;
}

static int mjson_parse_number(mjson_context* c, mjson_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return MJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return MJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return MJSON_PARSE_INVALID_VALUE;
        for (p++; ISDIGIT(*p); p++);
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return MJSON_PARSE_NUMBER_TOO_BIG;
    v->type = MJSON_NUMBER;
    c->json = p;
    return MJSON_PARSE_OK;
}

static const char* mjson_parse_hex4(const char* p, unsigned* u) {
    int i;
    *u = 0;
    for (i = 0; i < 4; i++) {
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9')  *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void mjson_encode_utf8(mjson_context* c, unsigned u) {
    if (u <= 0x7F)
        PUTC(c, u & 0xFF);
    else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6) & 0xFF));
        PUTC(c, 0x80 | ( u       & 0x3F));
    }
    else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
    else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int mjson_parse_string(mjson_context* c, mjson_value* v) {
    size_t head = c->top, len;
    unsigned u, u2;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                mjson_set_string(v, (const char*)mjson_context_pop(c, len), len);
                c->json = p;
                return MJSON_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = mjson_parse_hex4(p, &u)))
                            STRING_ERROR(MJSON_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) { /* surrogate pair */
                            if (*p++ != '\\')
                                STRING_ERROR(MJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(MJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = mjson_parse_hex4(p, &u2)))
                                STRING_ERROR(MJSON_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(MJSON_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        mjson_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(MJSON_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(MJSON_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(MJSON_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int mjson_parse_array( mjson_context* c, mjson_value* v) {
    size_t size = 0;
    int ret;
    EXPECT(c, '[');
    if (*c->json == ']') {
        c->json ++;
        v->type = MJSON_ARRAY;
        v->u.a.e = NULL;
        v->u.a.size = 0;
        return MJSON_PARSE_OK;
    }
    for (;;) {
        mjson_value e;
        mjson_init(&e);
        if ((ret = mjson_parse_value(c, &e)) != MJSON_PARSE_OK)
            return ret;
        memcpy(mjson_context_push(c, sizeof(mjson_value)), &e, sizeof(mjson_value));
        size++;
        if (*c->json == ','){
            c->json++;
        } else if( *c->json == ']') {
            c->json ++;
            v->type = MJSON_ARRAY;
            v->u.a.size = size;
            size *= sizeof(mjson_value);
            memcpy(v->u.a.e = (mjson_value*) malloc(size), mjson_context_pop(c, size),size);
            return MJSON_PARSE_OK;
        }
        else return MJSON_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
    }
}

static int mjson_parse_value(mjson_context* c, mjson_value* v) {
    switch (*c->json) {
        case 't':  return mjson_parse_literal(c, v, "true", MJSON_TRUE);
        case 'f':  return mjson_parse_literal(c, v, "false", MJSON_FALSE);
        case 'n':  return mjson_parse_literal(c, v, "null", MJSON_NULL);
        default:   return mjson_parse_number(c, v);
        case '"':  return mjson_parse_string(c, v);
        case '[':  return mjson_parse_array(c, v);
        case '\0': return MJSON_PARSE_EXPECT_VALUE;
    }
}

int mjson_parse(mjson_value* v, const char* json) {
    mjson_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    mjson_init(v);
    mjson_parse_whitespace(&c);
    if ((ret = mjson_parse_value(&c, v)) == MJSON_PARSE_OK) {
        mjson_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = MJSON_NULL;
            ret = MJSON_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

void mjson_free(mjson_value* v) {
    assert(v != NULL);
    if (v->type == MJSON_STRING)
        free(v->u.s.s);
    v->type = MJSON_NULL;
}

mjson_type mjson_get_type(const mjson_value* v) {
    assert(v != NULL);
    return v->type;
}

int mjson_get_boolean(const mjson_value* v) {
    assert(v != NULL && (v->type == MJSON_TRUE || v->type == MJSON_FALSE));
    return v->type == MJSON_TRUE;
}

void mjson_set_boolean(mjson_value* v, int b) {
    mjson_free(v);
    v->type = b ? MJSON_TRUE : MJSON_FALSE;
}

double mjson_get_number(const mjson_value* v) {
    assert(v != NULL && v->type == MJSON_NUMBER);
    return v->u.n;
}

void mjson_set_number(mjson_value* v, double n) {
    mjson_free(v);
    v->u.n = n;
    v->type = MJSON_NUMBER;
}

const char* mjson_get_string(const mjson_value* v) {
    assert(v != NULL && v->type == MJSON_STRING);
    return v->u.s.s;
}

size_t mjson_get_string_length(const mjson_value* v) {
    assert(v != NULL && v->type == MJSON_STRING);
    return v->u.s.len;
}

size_t mjson_get_array_size(const mjson_value* v) {
    assert( v!= NULL && v->type == MJSON_ARRAY);
    return v->u.a.size;
}

mjson_value* mjson_get_array_element(const mjson_value* v, size_t index) {
    assert(v != NULL && v->type == MJSON_ARRAY);
    assert(index <= v->u.a.size);
    return &v->u.a.e[index];
}

void mjson_set_string(mjson_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    mjson_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = MJSON_STRING;
}
