#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)

#define ISWHITESPACE(ch)    ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
} lept_context;

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;

    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0) {
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        }
        while (c->top + size >= c->size) {
            c->size += c->size >> 1;  /* c->size * 1.5 */
        }
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;

    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    c->top -= size;

    return c->stack + c->top;
}

static void lept_parse_whitespace(lept_context* c) 
{
    const char *p = c->json;

    while (ISWHITESPACE(*p)) {
        p++;
    }
    c->json = p;
}

static int lept_parse_null(lept_context* c, lept_value* v)
{
    EXPECT(c, 'n');
    if (c->json[0] != 'u' || c->json[1] != 'l' || c->json[2] != 'l') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 3;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
}

static int lept_parse_false(lept_context* c, lept_value* v)
{
    EXPECT(c, 'f');
    if (c->json[0] != 'a' || c->json[1] != 'l' || c->json[2] != 's' || c->json[3] != 'e') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 4;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
}

static int lept_parse_true(lept_context* c, lept_value* v)
{
    EXPECT(c, 't');
    if (c->json[0] != 'r' || c->json[1] != 'u' || c->json[2] != 'e') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 3;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v)
{
    const char* p = c->json;

    /* nagetive */
    if (*p == '-') p++;
    /* int */
    if (*p == '0') p++;
    else {
        if (!ISDIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }
    /* frac */
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }
    /* exp */
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!ISDIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        while (ISDIGIT(*p)) p++;
    }

    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) {
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned int* u) 
{
    *u = 0;
    for (int i = 0; i < 4; i++) {
        const char ch = *p++;
        unsigned int d;
        switch (ch) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9': 
                d = ch - '0'; break;
            case 'a': case 'A': d = 10; break;
            case 'b': case 'B': d = 11; break;
            case 'c': case 'C': d = 12; break;
            case 'd': case 'D': d = 13; break;
            case 'e': case 'E': d = 14; break;
            case 'f': case 'F': d = 15; break;
            default: return NULL;
        }
        (*u) = (*u) * 16 + d;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned int u) 
{
    assert(u >= 0x0000 && u <= 0x10FFFF);
    if (u < 0x007F) {
        PUTC(c, (0x00 | ( u        & 0x7F))); /* 0x00 = 00000000 */
    }
    else if (u <= 0x07FF) {
        PUTC(c, (0xC0 | ((u >>  6) & 0x1F))); /* 0xC0 = 11000000 */
        PUTC(c, (0x80 | ( u        & 0x3F))); /* 0x80 = 10000000 */
    }
    else if (u <= 0xFFFF) {
        PUTC(c, (0xE0 | ((u >> 12) & 0x0F))); /* 0xE0 = 11100000 */
        PUTC(c, (0x80 | ((u >>  6) & 0x3F))); 
        PUTC(c, (0x80 | ( u        & 0x3F))); 
    }
    else {
        PUTC(c, (0xF0 | ((u >> 18) & 0x07))); /* 0xF0 = 11110000 */
        PUTC(c, (0x80 | ((u >> 12) & 0x3F))); 
        PUTC(c, (0x80 | ((u >>  6) & 0x3F))); 
        PUTC(c, (0x80 | ( u        & 0x3F))); 
    }
}

#define RETURN_STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_string(lept_context* c, lept_value* v)
{
    size_t head = c->top, len;
    const char* p;
    unsigned int u; /* store unicode hex4 */

    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                lept_set_string(v, lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                RETURN_STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/');  break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u))) {
                            RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        /* surrogate handling */
                        if (u >= 0xD800 && u <= 0xDBFF) {
                            if (*p == '\\' && *(p+1) == 'u') {
                                p += 2;
                                unsigned int ul;
                                if (!(p = lept_parse_hex4(p, &ul))) {
                                    RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                                }
                                if (ul < 0xDC00 || ul > 0xDFFF) {
                                    RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                                }
                                u = 0x10000 + (u-0xD800)*0x400 + (ul-0xDC00);
                            }
                            else {
                                RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        RETURN_STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            default:
                if ((unsigned char)ch <= 0x1F) {
                    RETURN_STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
                PUTC(c, ch);
        }
    }
}

static int lept_parse_value(lept_context* c, lept_value* v) 
{
    switch (*c->json) {
        case 'n':  return lept_parse_null(c, v);
        case 'f':  return lept_parse_false(c, v);
        case 't':  return lept_parse_true(c, v);
        default:   return lept_parse_number(c, v);
        case '"':  return lept_parse_string(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) 
{
    lept_context c;
    int ret;

    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret =  LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);

    return ret;
}

void lept_free(lept_value* v) 
{
    assert(v != NULL);
    if (v->type == LEPT_STRING) {
        free(v->u.s.s);
    }
    v->type = LEPT_NULL;
}

int lept_get_boolean(const lept_value* v)
{
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b)
{
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

lept_type lept_get_type(const lept_value* v) 
{
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) 
{
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n)
{
    lept_free(v);
    v->type = LEPT_NUMBER;
    v->u.n = n;
}

const char* lept_get_string(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len)
{
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->type = LEPT_STRING;
    v->u.s.s = (char*)malloc(len+1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
}

