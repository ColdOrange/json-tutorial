#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdio.h>   /* sprintf() */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy(), memmove() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)

#define ISWHITESPACE(ch)    ((ch) == ' ' || (ch) == '\t' || (ch) == '\n' || (ch) == '\r')

#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')

#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)
#define PUTS(c, s, len)     memcpy(lept_context_push(c, len), s, len)

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
    while (ISWHITESPACE(*c->json)) {
        c->json++;
    }
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
        char ch = *p++;
        *u <<= 4;
        if      (ch >= '0' && ch <= '9')  *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F')  *u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'f')  *u |= ch - ('a' - 10);
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned int u) 
{
    assert(u >= 0x0000 && u <= 0x10FFFF);
    if (u < 0x007F) {
        PUTC(c, (0x00 | ( u        & 0xFF))); /* 0x00 = 00000000 */
    }
    else if (u <= 0x07FF) {
        PUTC(c, (0xC0 | ((u >>  6) & 0xFF))); /* 0xC0 = 11000000 */
        PUTC(c, (0x80 | ( u        & 0x3F))); /* 0x80 = 10000000 */
    }
    else if (u <= 0xFFFF) {
        PUTC(c, (0xE0 | ((u >> 12) & 0xFF))); /* 0xE0 = 11100000 */
        PUTC(c, (0x80 | ((u >>  6) & 0x3F))); 
        PUTC(c, (0x80 | ( u        & 0x3F))); 
    }
    else {
        PUTC(c, (0xF0 | ((u >> 18) & 0xFF))); /* 0xF0 = 11110000 */
        PUTC(c, (0x80 | ((u >> 12) & 0x3F))); 
        PUTC(c, (0x80 | ((u >>  6) & 0x3F))); 
        PUTC(c, (0x80 | ( u        & 0x3F))); 
    }
}

#define RETURN_STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

/* for parsing key of json objects, using lept_parse_string() directley will cause waste (lept_type unused) */
static int lept_parse_string_raw(lept_context* c, char** s, size_t* l)
{
    size_t head = c->top;
    const char* p;
    unsigned int u; /* store unicode hex4 */

    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *l = c->top - head;
                *s = lept_context_pop(c, *l);
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
                            if (*p == '\\' && *(p + 1) == 'u') {
                                p += 2;
                                unsigned int ul;
                                if (!(p = lept_parse_hex4(p, &ul))) {
                                    RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                                }
                                if (ul < 0xDC00 || ul > 0xDFFF) {
                                    RETURN_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                                }
                                u = (((u - 0xD800) << 10) | (ul - 0xDC00)) + 0x10000;
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

static int lept_parse_string(lept_context* c, lept_value* v)
{
    int ret;
    char* s;
    size_t len;

    if ((ret = lept_parse_string_raw(c, &s, &len)) == LEPT_PARSE_OK) {
        lept_set_string(v, s, len);
    }
    return ret;
}

/* forward declaration */
static int lept_parse_value(lept_context* c, lept_value* v);

static int lept_parse_array(lept_context* c, lept_value* v)
{
    size_t size = 0;
    int ret;

    EXPECT(c, '[');
    lept_parse_whitespace(c);       /* parse whitespace around */
    if (*c->json == ']') {
        c->json++;
        lept_set_array(v, 0);
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        lept_parse_whitespace(c);   /* parse whitespace around */
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            break;
        }
        lept_parse_whitespace(c);   /* parse whitespace around */
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        if (*c->json == ',') {
            c->json++;
        }
        else if (*c->json == ']') {
            c->json++;
            lept_set_array(v, size);
            v->u.a.size = size;
            memcpy(v->u.a.e, lept_context_pop(c, size * sizeof(lept_value)), size * sizeof(lept_value));
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    /* clear stack and free elements when failed in parsing array */
    for (size_t i = 0; i < size; i++) {
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    }
    return ret;
}

static int lept_parse_object(lept_context* c, lept_value* v)
{
    size_t size = 0;
    lept_member m;
    int ret;

    EXPECT(c, '{');
    lept_parse_whitespace(c);       /* parse whitespace around */
    if (*c->json == '}') {
        c->json++;
        lept_set_object(v, 0);
        return LEPT_PARSE_OK;
    }
    m.k = NULL;  /* for free(m.k), free NULL is OK */
    for (;;) {
        char* s;
        lept_init(&m.v);
        /* parse key */
        lept_parse_whitespace(c);   /* parse whitespace around */
        if (*c->json != '"') {
            ret = LEPT_PARSE_MISS_KEY;
            break;
        }
        if ((ret = lept_parse_string_raw(c, &s, &m.klen)) != LEPT_PARSE_OK) {
            break;
        }
        m.k= (char*)malloc(m.klen + 1);
        memcpy(m.k, s, m.klen);
        m.k[m.klen] = '\0';
        lept_parse_whitespace(c);   /* parse whitespace around */
        if (*c->json != ':') {
            ret = LEPT_PARSE_MISS_COLON;
            break;
        }
        c->json++;
        lept_parse_whitespace(c);   /* parse whitespace around */
        /* parse value */
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            break;
        }
        lept_parse_whitespace(c);   /* parse whitespace around */
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        /* parse [comma | right-curly-brace] */
        if (*c->json == ',') {
            c->json++;
        }
        else if (*c->json == '}') {
            c->json++;
            lept_set_object(v, size);
            v->u.o.size = size;
            memcpy(v->u.o.m, lept_context_pop(c, size * sizeof(lept_member)), size * sizeof(lept_member));
            return LEPT_PARSE_OK;
        }
        else {
            ret = LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    /* clear stack and free members when failed in parsing object */
    free(m.k);
    for (size_t i = 0; i < size; i++) {
        lept_member* m = (lept_member*)lept_context_pop(c, sizeof(lept_member));
        free(m->k);
        lept_free(&m->v);
    }
    v->type = LEPT_NULL;
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v) 
{
    switch (*c->json) {
        case 'n':  return lept_parse_null(c, v);
        case 'f':  return lept_parse_false(c, v);
        case 't':  return lept_parse_true(c, v);
        default:   return lept_parse_number(c, v);
        case '"':  return lept_parse_string(c, v);
        case '[':  return lept_parse_array(c, v);
        case '{':  return lept_parse_object(c, v);
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

static void lept_stringify_string(lept_context* c, const char* s, size_t len)
{
    assert(s != NULL);
    static const char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t size = len * 6 + 2; /* "\u00xx...", max possible length */
    char* head = lept_context_push(c, size); /* allocate only once to speed up  */
    char* p = head;
    *p++ = '"';
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\"': *p++ = '\\'; *p++ = '\"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\b': *p++ = '\\'; *p++ = 'b';  break;
            case '\f': *p++ = '\\'; *p++ = 'f';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (ch < 0x20) {
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex_digits[ch >> 4];
                    *p++ = hex_digits[ch & 15];
                }
                else {
                    *p++ = s[i];
                }
        }
    }
    *p++ = '"';
    c->top -= size - (p - head); /* shrink to real size */
}

static void lept_stringify_number(lept_context*c, double n)
{
    size_t size = 32; /* max possible length */
    char* head = lept_context_push(c, size);
    size_t len = sprintf(head, "%.17g", n);
    c->top -= size - len; /* shrink to real size */
}

static void lept_stringify_value(lept_context* c, const lept_value* v)
{
    switch (v->type) {
        case LEPT_NULL:   PUTS(c, "null",  4); break;
        case LEPT_FALSE:  PUTS(c, "false", 5); break;
        case LEPT_TRUE:   PUTS(c, "true",  4); break;
        case LEPT_NUMBER: lept_stringify_number(c, v->u.n); break;
        case LEPT_STRING: lept_stringify_string(c, v->u.s.s, v->u.s.len); break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (size_t i = 0; i < v->u.a.size; i++) {
                if (i > 0) PUTC(c, ',');
                lept_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
            PUTC(c, '{');
            for (size_t i = 0; i < v->u.o.size; i++) {
                if (i > 0) PUTC(c, ',');
                lept_stringify_string(c, v->u.o.m[i].k, v->u.o.m[i].klen);
                PUTC(c, ':');
                lept_stringify_value(c, &v->u.o.m[i].v);
            }
            PUTC(c, '}');
            break;
        default: assert(0 && "invalid type");
    }
}

char* lept_stringify(const lept_value* v, size_t* len)
{
    lept_context c;
    assert(v != NULL);
    c.stack = (char*)malloc(LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE;
    c.top = 0;
    lept_stringify_value(&c, v);
    if (len != NULL) *len = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

void lept_copy(lept_value* dst, const lept_value* src)
{

    assert(src != NULL && dst != NULL && src != dst);
    switch (src->type) {
        case LEPT_STRING:
            lept_set_string(dst, src->u.s.s, src->u.s.len);
            break;
        case LEPT_ARRAY:
            lept_set_array(dst, src->u.a.size);
            dst->u.a.size = src->u.a.size;
            for (size_t i = 0; i < src->u.a.size; i++) {
                lept_init(&dst->u.a.e[i]);
                lept_copy(&dst->u.a.e[i], &src->u.a.e[i]);
            }
            break;
        case LEPT_OBJECT:
            lept_set_object(dst, src->u.o.size);
            dst->u.o.size = src->u.o.size;
            for (size_t i = 0; i < src->u.o.size; i++) {
                dst->u.o.m[i].k = (char*)malloc(src->u.o.m[i].klen + 1);
                memcpy(dst->u.o.m[i].k, src->u.o.m[i].k, src->u.o.m[i].klen);
                dst->u.o.m[i].k[src->u.o.m[i].klen] = '\0';
                dst->u.o.m[i].klen = src->u.o.m[i].klen;
                lept_init(&dst->u.o.m[i].v);
                lept_copy(&dst->u.o.m[i].v, &src->u.o.m[i].v);
            }
            break;
        default:
            lept_free(dst);
            memcpy(dst, src, sizeof(lept_value));
            break;
    }
}

void lept_move(lept_value* dst, lept_value* src)
{
    assert(dst != NULL && src != NULL && src != dst);
    lept_free(dst);
    memcpy(dst, src, sizeof(lept_value));
    lept_init(src);
}

void lept_swap(lept_value* lhs, lept_value* rhs)
{
    assert(lhs != NULL && rhs != NULL);
    if (lhs != rhs) {
        lept_value temp;
        memcpy(&temp, lhs, sizeof(lept_value)); /* use memcpy() can speed up, by reducing the de-reference */
        memcpy(lhs,   rhs, sizeof(lept_value));
        memcpy(rhs, &temp, sizeof(lept_value));
    }
}

void lept_free(lept_value* v) 
{
    assert(v != NULL);
    switch (v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (size_t i = 0; i < v->u.a.size; i++) {
                lept_free(&v->u.a.e[i]);
            }
            free(v->u.a.e);
            break;
        case LEPT_OBJECT:
            for (size_t i = 0; i < v->u.o.size; i++) {
                free(v->u.o.m[i].k);
                lept_free(&v->u.o.m[i].v);
            }
            free(v->u.o.m);
            break;
        default: 
            break;
    }
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v)
{
    assert(v != NULL);
    return v->type;
}

int lept_is_equal(const lept_value* lhs, const lept_value* rhs)
{
    assert(lhs != NULL && rhs != NULL);
    if (lhs->type != rhs->type) {
        return 0;
    }
    switch (lhs->type) {
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len && memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len) == 0;
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size) {
                return 0;
            }
            for (size_t i = 0; i < lhs->u.a.size; i++) {
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i])) {
                    return 0;
                }
            }
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for (size_t i = 0; i < lhs->u.o.size; i++) {
                size_t j = lept_find_object_index(rhs, lhs->u.o.m[i].k, lhs->u.o.m[i].klen);
                if (j == LEPT_KEY_NOT_EXIST || !lept_is_equal(&lhs->u.o.m[i].v, &rhs->u.o.m[j].v)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
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
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
}

void lept_set_array(lept_value* v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_ARRAY;
    v->u.a.size = 0;
    v->u.a.capacity = capacity;
    v->u.a.e = capacity > 0 ? (lept_value*)malloc(capacity * sizeof(lept_value)) : NULL;
}

size_t lept_get_array_size(const lept_value* v) 
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

size_t lept_get_array_capacity(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.capacity;
}

void lept_reserve_array(lept_value* v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity < capacity) {
        v->u.a.capacity = capacity;
        v->u.a.e = (lept_value*)realloc(v->u.a.e, v->u.a.capacity * sizeof(lept_value));
    }
}

void lept_shrink_array(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.capacity > v->u.a.size) {
        v->u.a.capacity = v->u.a.size;
        v->u.a.e = (lept_value*)realloc(v->u.a.e, v->u.a.capacity * sizeof(lept_value));
    }
}

void lept_clear_array(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    lept_erase_array_element(v, 0, v->u.a.size);
}

lept_value* lept_get_array_element(lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

lept_value* lept_pushback_array_element(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY);
    if (v->u.a.size == v->u.a.capacity) {
        lept_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    }
    lept_init(&v->u.a.e[v->u.a.size]);
    return &v->u.a.e[v->u.a.size++];
}

void lept_popback_array_element(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_ARRAY && v->u.a.size > 0);
    lept_free(&v->u.a.e[--v->u.a.size]);
}

lept_value* lept_insert_array_element(lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_ARRAY && index <= v->u.a.size);
    if (v->u.a.size == v->u.a.capacity) {
        lept_reserve_array(v, v->u.a.capacity == 0 ? 1 : v->u.a.capacity * 2);
    }
    memmove(&v->u.a.e[index + 1], &v->u.a.e[index], (v->u.a.size - index) * sizeof(lept_value));
    v->u.a.size++;
    lept_init(&v->u.a.e[index]);
    return &v->u.a.e[index];
}

void lept_erase_array_element(lept_value* v, size_t index, size_t count)
{
    assert(v != NULL && v->type == LEPT_ARRAY && index + count <= v->u.a.size);
    for (size_t i = index; i < index + count; i++) {
        lept_free(&v->u.a.e[i]);
    }
    memmove(&v->u.a.e[index], &v->u.a.e[index + count], (v->u.a.size - index - count) * sizeof(lept_value));
    v->u.a.size -= count;
    //lept_shrink_array(v);
}

void lept_set_object(lept_value* v, size_t capacity)
{
    assert(v != NULL);
    lept_free(v);
    v->type = LEPT_OBJECT;
    v->u.o.size = 0;
    v->u.o.capacity = capacity;
    v->u.o.m = capacity > 0 ? (lept_member*)malloc(capacity * sizeof(lept_member)) : NULL;
}

size_t lept_get_object_size(const lept_value* v) 
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

size_t lept_get_object_capacity(const lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.capacity;
}

void lept_reserve_object(lept_value* v, size_t capacity)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity < capacity) {
        v->u.o.capacity = capacity;
        v->u.o.m = (lept_member*)realloc(v->u.o.m, v->u.o.capacity * sizeof(lept_member));
    }
}

void lept_shrink_object(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    if (v->u.o.capacity > v->u.o.size) {
        v->u.o.capacity = v->u.o.size;
        v->u.o.m = (lept_member*)realloc(v->u.o.m, v->u.o.capacity * sizeof(lept_member));
    }
}

//void lept_clear_object(lept_value* v)
//{
//    assert(v != NULL && v->type == LEPT_OBJECT);
//    for (size_t i = 0; i < v->u.o.size; i++) {
//        free(v->u.o.m[i].k);
//        lept_free(&v->u.o.m[i].v);
//    }
//    v->u.o.size = 0;
//}

void lept_clear_object(lept_value* v)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    lept_remove_object_value(v, 0, v->u.o.size);
}

const char* lept_get_object_key(const lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value* lept_get_object_value(lept_value* v, size_t index)
{
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

size_t lept_find_object_index(const lept_value* v, const char* key, size_t klen)
{
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (size_t i = 0; i < v->u.o.size; i++) {
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0) {
            return i;
        }
    }
    return LEPT_KEY_NOT_EXIST;
}

lept_value* lept_find_object_value(lept_value* v, const char* key, size_t klen)
{
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

lept_value* lept_set_object_value(lept_value* v, const char* key, size_t klen)
{
    lept_value* r = lept_find_object_value(v, key, klen);
    if (r == NULL) {
        lept_reserve_object(v, v->u.o.size + 1);
        v->u.o.m[v->u.o.size].k = (char*)malloc(klen + 1);
        memcpy(v->u.o.m[v->u.o.size].k, key, klen);
        v->u.o.m[v->u.o.size].k[klen] = '\0';
        v->u.o.m[v->u.o.size].klen = klen;
        r = &v->u.o.m[v->u.o.size].v;
        v->u.o.size++;
    }
    lept_init(r);
    return r;
}

//void lept_remove_object_value(lept_value* v, size_t index)
//{
//    assert(v != NULL && v->type == LEPT_OBJECT && index < v->u.o.size);
//    free(v->u.o.m[i].k);
//    lept_free(&v->u.o.m[i].v);
//    memmove(&v->u.o.m[index], &v->u.o.m[index + 1], (v->u.o.size - index - 1) * sizeof(lept_member));
//    v->u.a.size--;
//    //lept_shrink_object(v);
//}

void lept_remove_object_value(lept_value* v, size_t index, size_t count)
{
    assert(v != NULL && v->type == LEPT_OBJECT && index + count <= v->u.o.size);
    for (size_t i = index; i < index + count; i++) {
        free(v->u.o.m[i].k);
        lept_free(&v->u.o.m[i].v);
    }
    memmove(&v->u.o.m[index], &v->u.o.m[index + count], (v->u.o.size - index - count) * sizeof(lept_member));
    v->u.a.size -= count;
    //lept_shrink_object(v);
}
