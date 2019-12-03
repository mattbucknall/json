/*
 * JSON reader/writer & DOM
 * <https://github.com/mattbucknall/json>
 *
 * Copyright (c) 2019 Matthew T. Bucknall
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "json.h"


#define READ_BUFFER_SIZE        16


typedef enum
{
    JSON_TOKEN_TYPE_UNDEFINED,
    JSON_TOKEN_TYPE_END_OF_INPUT,
    JSON_TOKEN_TYPE_KEY_VAL_SEPARATOR,
    JSON_TOKEN_TYPE_COMMA,
    JSON_TOKEN_TYPE_OBJECT_OPEN,
    JSON_TOKEN_TYPE_OBJECT_CLOSE,
    JSON_TOKEN_TYPE_ARRAY_OPEN,
    JSON_TOKEN_TYPE_ARRAY_CLOSE,
    JSON_TOKEN_TYPE_LITERAL

} json_token_type_t;


typedef unsigned long unichar_t;


typedef struct
{
    json_t header;

} json_null_node_t;


typedef struct
{
    json_t header;
    json_bool_t value;

} json_bool_node_t;


typedef struct
{
    json_t header;
    json_number_t value;

} json_number_node_t;


typedef struct
{
    json_t header;
    char* value;

} json_string_node_t;


typedef struct
{
    json_t header;
    json_t** members;
    size_t n_members;
    size_t space;

} json_array_node_t;


typedef struct json_object_member
{
    struct json_object_member* next;
    char* key;
    json_t* value;

} json_object_member_t;


typedef struct
{
    json_t header;
    json_object_member_t* members;

} json_object_node_t;


typedef struct
{
    json_read_func_t read_func;
    void* user_data;
    size_t depth;
    size_t max_string_length;
    unsigned char buffer[READ_BUFFER_SIZE];
    unsigned char* buffer_i;
    unsigned char* buffer_e;
    unichar_t prev_char;
    json_t* token_value;
    json_result_t result;

} json_read_context_t;


typedef struct
{
    json_write_func_t write_func;
    void* user_data;

} json_write_context_t;


static json_t* parse_value(json_read_context_t* ctx);


/* ============================ UTF-8 Decoder ============================ */

// Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.

#define UTF8_ACCEPT 0
#define UTF8_REJECT 1

static const unsigned char utf8d[] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5f
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7f
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9f
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // a0..bf
        8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // c0..df
        0xa,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // e0..ef
        0xb,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // f0..ff
        0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0..s0
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
        1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
        1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
        1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
};

static unsigned long decode_utf8(unsigned long* state, unichar_t* codep, unsigned long byte)
{
    unsigned long type = utf8d[byte];

    *codep = (*state != UTF8_ACCEPT) ?
             (byte & 0x3fu) | (*codep << 6u) :
             (0xffu >> type) & (byte);

    *state = utf8d[256 + *state*16 + type];
    return *state;
}

/* ======================================================================= */

static int encode_utf8(char* buffer, unichar_t code_point)
{
    unsigned char* buffer_ptr = (unsigned char*) buffer;
    unsigned char bits;
    int len;

    if ( code_point < 0x80UL )              { bits = 0x00;  len = 1; }
    else if ( code_point < 0x800UL )        { bits = 0xC0;  len = 2; }
    else if ( code_point < 0x10000UL )      { bits = 0xE0;  len = 3; }
    else if ( code_point < 0x200000UL )     { bits = 0xF0;  len = 4; }
    else if ( code_point < 0x4000000UL )    { bits = 0xF8;  len = 5; }
    else                                    { bits = 0xFC;  len = 6; }

    for (int i = len - 1; i > 0; --i)
    {
        buffer_ptr[i] = (code_point & 0x3Ful) | 0x80UL;
        code_point >>= 6U;
    }

    buffer_ptr[0] = code_point | bits;

    return len;
}


const char* json_result_to_string(json_result_t result)
{
    switch(result)
    {
    case JSON_RESULT_OK:                        return "ok";
    case JSON_RESULT_OUT_OF_MEMORY:             return "out of memory";
    case JSON_RESULT_NOT_AN_ARRAY:              return "not an array";
    case JSON_RESULT_NOT_AN_OBJECT:             return "not an object";
    case JSON_RESULT_INDEX_OUT_OF_BOUNDS:       return "index out-of-bounds";
    case JSON_RESULT_TIMEOUT:                   return "timeout";
    case JSON_RESULT_IO_ERROR:                  return "io error";
    case JSON_RESULT_INVALID_NODE:              return "invalid node";
    case JSON_RESULT_INVALID_UTF8:              return "invalid UTF-8";
    case JSON_RESULT_UNEXPECTED_END_OF_INPUT:   return "unexpected end-of-input";
    case JSON_RESULT_ILLEGAL_CHARACTER:         return "illegal character";
    case JSON_RESULT_MAX_DEPTH_EXCEEDED:        return "maximum depth exceeded";
    case JSON_RESULT_UNKNOWN_KEYWORD:           return "unknown keyword";
    case JSON_RESULT_INVALID_NUMBER:            return "invalid number";
    case JSON_RESULT_STRING_TOO_LONG:           return "string too long";
    case JSON_RESULT_INVALID_ESCAPE_SEQUENCE:   return "invalid escape sequence";
    default:                                    return "undefined";
    }
}


const char* json_type_to_string(json_type_t type)
{
    switch(type)
    {
    case JSON_TYPE_NONE:        return "none";
    case JSON_TYPE_NULL:        return "null";
    case JSON_TYPE_BOOL:        return "bool";
    case JSON_TYPE_NUMBER:      return "number";
    case JSON_TYPE_STRING:      return "string";
    case JSON_TYPE_ARRAY:       return "array";
    case JSON_TYPE_OBJECT:      return "object";
    default:                    return "undefined";
    }
}


static json_t* alloc_node(json_type_t type, size_t size)
{
    json_t* node;

    node = (json_t*) malloc(size);

    if ( node )
    {
        node->ref_count = 1;
        node->type = type;
    }

    return node;
}


json_t* json_new_null(void)
{
    return alloc_node(JSON_TYPE_NULL, sizeof(json_null_node_t));
}


json_t* json_new_bool(json_bool_t value)
{
    json_bool_node_t* node;

    node = (json_bool_node_t*) alloc_node(JSON_TYPE_BOOL, sizeof(json_bool_node_t));
    if ( node ) node->value = value;

    return (json_t*) node;
}


json_t* json_new_number(json_number_t value)
{
    json_number_node_t* node;

    node = (json_number_node_t*) alloc_node(JSON_TYPE_NUMBER, sizeof(json_number_node_t));
    if ( node ) node->value = value;

    return (json_t*) node;
}


json_t* json_new_string_take(char* value)
{
    json_string_node_t* node;

    assert(value);

    node = (json_string_node_t*) alloc_node(JSON_TYPE_STRING, sizeof(json_string_node_t));
    if ( node ) node->value = value;

    return (json_t*) node;
}


json_t* json_new_string_with_length(const char* value, size_t length)
{
    json_t* result;
    json_string_node_t* node;
    size_t len;
    char* str;

    assert(value);

    length = (length + 1) * sizeof(char);
    str = (char*) malloc(length);

    if ( str ) memcpy(str, value, length);
    else return NULL;

    result = json_new_string_take(str);
    if ( !result ) free(str);

    return result;
}


json_t* json_new_string(const char* value)
{
    return json_new_string_with_length(value, strlen(value));
}


json_t* json_new_array(void)
{
    json_array_node_t* node;

    node = (json_array_node_t*) alloc_node(JSON_TYPE_ARRAY, sizeof(json_array_node_t));

    if ( node )
    {
        node->members = NULL;
        node->n_members = 0;
        node->space = 0;
    }

    return (json_t*) node;
}


json_t* json_new_object(void)
{
    json_object_node_t* node;

    node = (json_object_node_t*) alloc_node(JSON_TYPE_OBJECT, sizeof(json_object_node_t));
    if ( node ) node->members = NULL;

    return (json_t*) node;
}


json_t* json_ref(json_t* value)
{
    assert(value);
    value->ref_count++;
    return value;
}


void json_unref(json_t* value)
{
    assert(value);

    if ( value->ref_count <= 1 )
    {
        if ( value->type == JSON_TYPE_STRING )
        {
            json_string_node_t* string = (json_string_node_t*) value;
            free(string->value);
        }
        else if ( value->type == JSON_TYPE_ARRAY )
        {
            json_array_node_t* array = (json_array_node_t*) value;
            json_t** members_i = array->members;
            json_t** members_e = members_i + array->n_members;

            while (members_i < members_e)
            {
                json_unref(*members_i);
                members_i++;
            }

            free(array->members);
        }
        else if ( value->type == JSON_TYPE_OBJECT )
        {
            json_object_node_t* object = (json_object_node_t*) value;
            json_object_member_t* child = object->members;

            while (child)
            {
                json_object_member_t* next = child->next;

                free(child->key);
                json_unref(child->value);

                free(child);

                child = next;
            }
        }

        printf("\nfreeing %s\n", json_type_to_string(value->type));

        free(value);
    }
    else
    {
        value->ref_count--;
    }
}


json_type_t json_type(const json_t* value)
{
    assert(value);
    return value->type;
}


json_bool_t json_is_null(const json_t* value)
{
    assert(value);
    return value->type == JSON_TYPE_NULL ? JSON_BOOL_TRUE : JSON_BOOL_FALSE;
}


json_bool_t json_get_bool(const json_t* value)
{
    assert(value);
    return value->type == JSON_TYPE_BOOL ? ((const json_bool_node_t*) value)->value : JSON_BOOL_FALSE;
}


json_number_t json_get_number(const json_t* value)
{
    assert(value);
    return value->type == JSON_TYPE_NUMBER ? ((const json_number_node_t*) value)->value : (json_number_t) 0;
}


const char* json_get_string(const json_t* value)
{
    assert(value);
    return value->type == JSON_TYPE_STRING ? ((const json_string_node_t*) value)->value : NULL;
}


size_t json_length(const json_t* value)
{
    assert(value);

    if ( value->type == JSON_TYPE_STRING )
    {
        return strlen(((const json_string_node_t*) value)->value);
    }
    else if ( value->type == JSON_TYPE_ARRAY )
    {
        return ((const json_array_node_t*) value)->n_members;
    }
    else
    {
        return 0;
    }
}


json_result_t json_append(json_t* array, json_t* value)
{
    json_array_node_t* _array;

    assert(array);

    if ( array->type != JSON_TYPE_ARRAY ) return JSON_RESULT_NOT_AN_ARRAY;

    _array = (json_array_node_t*) array;

    if ( _array->n_members >= _array->space )
    {
        size_t new_space = _array->space + 8;
        json_t** new_members;

        new_members = (json_t**) realloc(_array->members, new_space * sizeof(json_t*));
        if ( !new_members ) return JSON_RESULT_OUT_OF_MEMORY;

        _array->members = new_members;
        _array->space = new_space;
    }

    _array->members[_array->n_members++] = json_ref(value);

    return JSON_RESULT_OK;
}


json_result_t json_set_with_index(json_t* array, size_t index, json_t* value)
{
    json_array_node_t* _array;

    assert(array);
    assert(value);

    if ( array->type != JSON_TYPE_ARRAY ) return JSON_RESULT_NOT_AN_ARRAY;

    _array = (json_array_node_t*) array;

    if ( index >= _array->n_members ) return JSON_RESULT_INDEX_OUT_OF_BOUNDS;

    json_ref(value);
    json_unref(_array->members[index]);
    _array->members[index] = value;

    return JSON_RESULT_OK;
}


json_t* json_get_with_index(const json_t* array, size_t index)
{
    const json_array_node_t* _array;

    assert(array);

    if ( array->type != JSON_TYPE_ARRAY ) return NULL;

    _array = (const json_array_node_t*) array;
    if ( index >= _array->n_members ) return NULL;

    return _array->members[index];
}


static json_object_member_t* find_member(json_object_node_t* object, const char* key)
{
    json_object_member_t* member = object->members;

    while (member)
    {
        if ( strcmp(member->key, key) == 0 ) break;
        member = member->next;
    }

    return member;
}


static const json_object_member_t* const_find_member(const json_object_node_t* object, const char* key)
{
    const json_object_member_t* member = object->members;

    while (member)
    {
        if ( strcmp(member->key, key) == 0 ) break;
        member = member->next;
    }

    return member;
}


json_result_t json_set_with_key_length(json_t* object, const char* key, size_t key_length, json_t* value)
{
    json_object_node_t* _object;
    json_object_member_t* member;

    assert(object);
    assert(key);
    assert(value);

    if ( object->type != JSON_TYPE_OBJECT ) return JSON_RESULT_NOT_AN_OBJECT;

    _object = (json_object_node_t*) object;

    member = find_member(_object, key);

    if ( member )
    {
        json_ref(value);
        json_unref(member->value);
        member->value = value;
    }
    else
    {
        char* key_str;

        key_length = (key_length + 1) * sizeof(char);
        key_str = (char*) malloc(key_length);

        if ( key_str ) memcpy(key_str, key, key_length);
        else return JSON_RESULT_OUT_OF_MEMORY;

        member = (json_object_member_t*) malloc(sizeof(json_object_member_t));

        if ( member )
        {
            member->next = _object->members;
            member->key = key_str;
            member->value = json_ref(value);

            _object->members = member;
        }
        else
        {
            free(key_str);
            return JSON_RESULT_OUT_OF_MEMORY;
        }
    }

    return JSON_RESULT_OK;
}


json_result_t json_set_with_key(json_t* object, const char* key, json_t* value)
{
    return json_set_with_key_length(object, key, strlen(key), value);
}


json_result_t json_set_take_key(json_t* object, char* key, json_t* value)
{
    json_object_node_t* _object;
    json_object_member_t* member;

    assert(object);
    assert(key);
    assert(value);

    if ( object->type != JSON_TYPE_OBJECT ) return JSON_RESULT_NOT_AN_OBJECT;

    _object = (json_object_node_t*) object;

    member = find_member(_object, key);

    if ( member )
    {
        json_ref(value);
        json_unref(member->value);
        member->value = value;
        free(key);
    }
    else
    {
        member = (json_object_member_t*) malloc(sizeof(json_object_member_t));

        if ( member )
        {
            member->next = _object->members;
            member->key = key;
            member->value = json_ref(value);

            _object->members = member;
        }
        else
        {
            return JSON_RESULT_OUT_OF_MEMORY;
        }
    }

    return JSON_RESULT_OK;
}


json_t* json_get_with_key(const json_t* object, const char* key)
{
    const json_object_node_t* _object;
    const json_object_member_t* member;

    assert(object);
    assert(key);

    _object = (json_object_node_t*) object;

    member = const_find_member(_object, key);

    if ( member ) return member->value;
    else return NULL;
}


static unsigned char read_char(json_read_context_t* ctx)
{
    if ( ctx->buffer_i >= ctx->buffer_e )
    {
        int result;
        size_t n_read = 0;

        result = ctx->read_func(ctx->buffer, READ_BUFFER_SIZE, &n_read, ctx->user_data);

        if ( result != JSON_RESULT_OK )
        {
            ctx->result = result;
            return 0;
        }

        ctx->buffer_i = ctx->buffer;
        ctx->buffer_e = ctx->buffer + n_read;

        if ( ctx->buffer_i == ctx->buffer_e ) return 0;
    }

    return *(ctx->buffer_i++);
}


static unichar_t read_unichar(json_read_context_t* ctx)
{
    unsigned char c;
    unsigned long state = 0;
    unichar_t unichar;

    if ( ctx->prev_char )
    {
        unichar = ctx->prev_char;
        ctx->prev_char = 0;

        return unichar;
    }

    for (;;)
    {
        c = read_char(ctx);
        if ( ctx->result != JSON_RESULT_OK || c == 0 ) return 0;

        decode_utf8(&state, &unichar, c);

        if ( state == UTF8_REJECT )
        {
            ctx->result = JSON_RESULT_INVALID_UTF8;
            return 0;
        }

        if ( state == UTF8_ACCEPT ) return unichar;
    }
}


static void putback_unichar(json_read_context_t* ctx, unichar_t c)
{
    ctx->prev_char = c;
}


static int is_end_of_input(unichar_t c)
{
    return ( c == (unichar_t) '\0' );
}


static int is_whitespace(unichar_t c)
{
    return (c == 0x20ul) || (c == 0x0Aul) || (c == 0x0Dul) || (c == 0x09ul);
}


static int is_control(unichar_t c)
{
    return ( c < (unichar_t) ' ' );
}


static int is_newline(unichar_t c)
{
    return ( c == (unichar_t) '\n' );
}


static int is_key_val_separator(unichar_t c)
{
    return ( c == (unichar_t) ':' );
}


static int is_comma(unichar_t c)
{
    return ( c == (unichar_t) ',' );
}


static int is_object_open(unichar_t c)
{
    return ( c == (unichar_t) '{' );
}


static int is_object_close(unichar_t c)
{
    return ( c == (unichar_t) '}' );
}


static int is_array_open(unichar_t c)
{
    return ( c == (unichar_t) '[' );
}


static int is_array_close(unichar_t c)
{
    return ( c == (unichar_t) ']' );
}


static int is_quote(unichar_t c)
{
    return ( c == (unichar_t) '"' );
}


static int is_escape(unichar_t c)
{
    return ( c == (unichar_t) '\\' );
}


static int is_digit(unichar_t c)
{
    return ( c >= (unichar_t) '0' && c <= (unichar_t) '9' );
}


static int is_zero(unichar_t c)
{
    return (c == (unichar_t) '0' );
}


static int is_digit_1_to_9(unichar_t c)
{
    return ( c >= (unichar_t) '1' && c <= (unichar_t) '9' );
}


static int is_lower_hex(unichar_t c)
{
    return ( c >= (unichar_t) 'a' && c <= (unichar_t) 'f' );
}


static int is_upper_hex(unichar_t c)
{
    return ( c >= (unichar_t) 'A' && c <= (unichar_t) 'F' );
}


static int is_minus(unichar_t c)
{
    return ( c == (unichar_t) '-' );
}


static int is_plus(unichar_t c)
{
    return ( c == (unichar_t) '+' );
}


static int is_exponent_delimiter(unichar_t c)
{
    return ( c == (unichar_t) 'e' ) || ( c == (unichar_t) 'E' );
}


static int is_decimal_point(unichar_t c)
{
    return ( c == (unichar_t) '.' );
}


static int match_chars(json_read_context_t* ctx, const char* chars, size_t n_chars)
{
    const char* chars_i = chars;
    const char* chars_e = chars + n_chars;

    while ( chars_i < chars_e )
    {
        unichar_t c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) return 0;

        if ( c != (unichar_t) (*chars_i) )
        {
            ctx->result = JSON_RESULT_UNKNOWN_KEYWORD;
            return 0;
        }

        chars_i++;
    }

    return 1;
}


static unichar_t escape(json_read_context_t* ctx)
{
    unichar_t c;

    c = read_unichar(ctx);
    if ( ctx->result != JSON_RESULT_OK ) return 0;

    if ( c == (unichar_t) '"' ) return (unichar_t) '"';
    else if ( c == (unichar_t) '\\' ) return (unichar_t) '\\';
    else if ( c == (unichar_t) '/' ) return (unichar_t) '/';
    else if ( c == (unichar_t) 'b' ) return (unichar_t) '\b';
    else if ( c == (unichar_t) 'f' ) return (unichar_t) '\f';
    else if ( c == (unichar_t) 'n' ) return (unichar_t) '\n';
    else if ( c == (unichar_t) 'r' ) return (unichar_t) '\r';
    else if ( c == (unichar_t) 't' ) return (unichar_t) '\t';
    else if ( c == (unichar_t) 'u' )
    {
        int i = 0;
        unichar_t code_point = 0;

        for (;;)
        {
            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return 0;

            if ( is_digit(c) ) code_point = (code_point << 4U) | (c - (unichar_t) '0');
            else if ( is_lower_hex(c) ) code_point = (code_point << 4U) | (c - (unichar_t) 'a' + 10);
            else if ( is_upper_hex(c) ) code_point = (code_point << 4U) | (c - (unichar_t) 'A' + 10);
            else break;

            if ( ++i == 4 ) return code_point;
        }
    }

    ctx->result = JSON_RESULT_INVALID_ESCAPE_SEQUENCE;
    return 0;
}


static json_token_type_t lex_string(json_read_context_t* ctx)
{
    unichar_t c;
    char* str;
    size_t str_index = 0;
    size_t str_size = 16;
    char utf8_buffer[6];
    int utf8_len;

    str = (char*) malloc(str_size * sizeof(char));

    if ( !str )
    {
        ctx->result = JSON_RESULT_OUT_OF_MEMORY;
        return JSON_TOKEN_TYPE_UNDEFINED;
    }

    for (;;)
    {
        c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        if ( is_end_of_input(c) )
        {
            ctx->result = JSON_RESULT_UNEXPECTED_END_OF_INPUT;
            break;
        }
        else if ( is_control(c) )
        {
            ctx->result = JSON_RESULT_ILLEGAL_CHARACTER;
            break;
        }
        else if ( is_quote(c) )
        {
            ctx->token_value = json_new_string_take(str);

            if ( !ctx->token_value )
            {
                ctx->result = JSON_RESULT_OUT_OF_MEMORY;
                break;
            }

            return JSON_TOKEN_TYPE_LITERAL;
        }
        else
        {
            size_t new_len;

            if ( is_escape(c) )
            {
                c = escape(ctx);
                if ( ctx->result != JSON_RESULT_OK ) break;
            }

            utf8_len = encode_utf8(utf8_buffer, c);
            new_len = str_index + utf8_len;

            if ( new_len > ctx->max_string_length )
            {
                ctx->result = JSON_RESULT_STRING_TOO_LONG;
                break;
            }

            if ( new_len >= (str_size - 1) )
            {
                char* new_str;

                str_size += 16;
                new_str = realloc(str, str_size);

                if ( new_str ) str = new_str;
                else
                {
                    ctx->result = JSON_RESULT_OUT_OF_MEMORY;
                    break;
                }
            }

            if ( ctx->result != JSON_RESULT_OK ) break;

            memcpy(str + str_index, utf8_buffer, utf8_len * sizeof(char));
            str_index = new_len;
        }
    }

    free(str);

    return JSON_TOKEN_TYPE_UNDEFINED;
}


static json_token_type_t lex_number(json_read_context_t* ctx)
{
    unichar_t c;
    int is_negative = 0;
    json_number_t value = (json_number_t) 0;
    long exp = 0;
    json_number_t power;

    c = read_unichar(ctx);
    if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

    if ( is_minus(c) )
    {
        is_negative = 1;
        c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;
    }

    if ( is_digit_1_to_9(c) )
    {
        do
        {
            value = (value * (json_number_t) 10.0) + (json_number_t) c - (json_number_t) '0';
            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        } while ( is_digit(c) );
    }
    else if ( !is_zero(c) )
    {
        ctx->result = JSON_RESULT_INVALID_NUMBER;
        return JSON_TOKEN_TYPE_UNDEFINED;
    }

    if ( is_decimal_point(c) )
    {
        c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        if ( !is_digit(c) )
        {
            ctx->result = JSON_RESULT_INVALID_NUMBER;
            return JSON_TOKEN_TYPE_UNDEFINED;
        }

        do
        {
            value = (value * (json_number_t) 10.0) + (json_number_t) c - (json_number_t) '0';
            exp--;

            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        } while ( is_digit(c) );
    }

    if ( is_exponent_delimiter(c) )
    {
        long exp_part = 0;
        int exp_negative = 0;

        c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        if ( is_plus(c) )
        {
            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;
        }
        else if ( is_minus(c) )
        {
            exp_negative = 1;

            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;
        }

        if ( !is_digit(c) )
        {
            ctx->result = JSON_RESULT_INVALID_NUMBER;
            return JSON_TOKEN_TYPE_UNDEFINED;
        }

        do
        {
            exp_part = (exp_part * 10) + (long) c - (long) '0';

            c = read_unichar(ctx);
            if ( ctx->result != JSON_RESULT_OK ) return JSON_TOKEN_TYPE_UNDEFINED;

        } while ( is_digit(c) );

        if ( exp_negative ) exp -= exp_part;
        else exp += exp_part;
    }

    putback_unichar(ctx, c);

    power = (json_number_t) 10.0;

    if ( exp < 0 )
    {
        exp = -exp;

        while (exp)
        {
            if ( exp & 1 ) value /= power;
            exp >>= 1;
            power *= power;
        }
    }
    else
    {
        while (exp)
        {
            if ( exp & 1 ) value *= power;
            exp >>= 1;
            power *= power;
        }
    }

    if ( is_negative ) value = -value;

    ctx->token_value = json_new_number(value);

    if ( !ctx->token_value )
    {
        ctx->result = JSON_RESULT_OUT_OF_MEMORY;
        return JSON_TOKEN_TYPE_UNDEFINED;
    }

    return JSON_TOKEN_TYPE_LITERAL;
}


static json_token_type_t next(json_read_context_t* ctx)
{
    if ( ctx->token_value )
    {
        json_unref(ctx->token_value);
        ctx->token_value = NULL;
    }

    for (;;)
    {
        unichar_t c = read_unichar(ctx);
        if ( ctx->result != JSON_RESULT_OK ) break;

        if ( is_whitespace(c) )
        {
            continue;
        }
        else if ( is_end_of_input(c) )
        {
            return JSON_TOKEN_TYPE_END_OF_INPUT;
        }
        else if ( is_key_val_separator(c) )
        {
            return JSON_TOKEN_TYPE_KEY_VAL_SEPARATOR;
        }
        else if ( is_comma(c) )
        {
            return JSON_TOKEN_TYPE_COMMA;
        }
        else if ( is_object_open(c) )
        {
            return JSON_TOKEN_TYPE_OBJECT_OPEN;
        }
        else if ( is_object_close(c) )
        {
            return JSON_TOKEN_TYPE_OBJECT_CLOSE;
        }
        else if ( is_array_open(c) )
        {
            return JSON_TOKEN_TYPE_ARRAY_OPEN;
        }
        else if ( is_array_close(c) )
        {
            return JSON_TOKEN_TYPE_ARRAY_CLOSE;
        }
        else if ( is_quote(c) )
        {
            return lex_string(ctx);
        }
        else if ( is_digit(c) || is_minus(c) )
        {
            putback_unichar(ctx, c);
            return lex_number(ctx);
        }
        else if ( c == (unichar_t) 'n' )
        {
            if ( !match_chars(ctx, "ull", 3) ) break;

            ctx->token_value = json_new_null();

            if ( !ctx->token_value )
            {
                ctx->result = JSON_RESULT_OUT_OF_MEMORY;
                break;
            }

            return JSON_TOKEN_TYPE_LITERAL;
        }
        else if ( c == (unichar_t) 'f' )
        {
            if ( !match_chars(ctx, "alse", 4) ) break;

            ctx->token_value = json_new_bool(JSON_BOOL_FALSE);

            if ( !ctx->token_value )
            {
                ctx->result = JSON_RESULT_OUT_OF_MEMORY;
                break;
            }

            return JSON_TOKEN_TYPE_LITERAL;
        }
        else if ( c == (unichar_t) 't' )
        {
            if ( !match_chars(ctx, "rue", 3) ) break;

            ctx->token_value = json_new_bool(JSON_BOOL_TRUE);

            if ( !ctx->token_value )
            {
                ctx->result = JSON_RESULT_OUT_OF_MEMORY;
                break;
            }

            return JSON_TOKEN_TYPE_LITERAL;
        }
        else
        {
            ctx->result = JSON_RESULT_ILLEGAL_CHARACTER;
        }
    }

    return JSON_TOKEN_TYPE_UNDEFINED;
}


json_t* json_read(json_read_func_t read_func, void* user_data, size_t max_depth,
        size_t max_string_length, json_result_t* result)
{
    json_read_context_t ctx;
    json_t* root;

    assert(read_func);
    assert(max_depth > 0);

    ctx.read_func = read_func;
    ctx.user_data = user_data;
    ctx.depth = max_depth;
    ctx.max_string_length = max_string_length;
    ctx.buffer_i = ctx.buffer;
    ctx.buffer_e = ctx.buffer;
    ctx.token_value = NULL;
    ctx.result = JSON_RESULT_OK;

    root = parse_value(&ctx);

    if ( result ) *result = ctx.result;

    if ( result != JSON_RESULT_OK )
    {
        if ( root )
        {
            json_unref(root);
            root = NULL;
        }
    }

    if ( ctx.token_value ) json_unref(ctx.token_value);

    return root;
}


static json_result_t encode_number(json_number_t value, json_write_func_t write_func, void* user_data)
{
    char buffer[28];
    int len;

    len = snprintf(buffer, 28, "%.9g", value);
    return write_func(buffer, len, user_data);
}


static char nibble_to_hex(char c)
{
    static const char LUT[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9','A', 'B', 'C', 'D', 'E', 'F'};
    return LUT[(unsigned) c & 0xFU];
}


static json_result_t encode_string(const char* value, size_t len, json_write_func_t write_func, void* user_data)
{
    json_result_t result;
    const char* str_i = value;
    const char* str_e = str_i + len;
    const char* str_n = str_i;

    result = write_func("\"", 1, user_data);
    if ( result != JSON_RESULT_OK ) return result;

    while (str_i < str_e)
    {
        do
        {
            if ( *str_n >= ' ' && *str_n <= '~' ) str_n++;
            else break;

        } while (str_n < str_e);

        if ( str_i < str_n )
        {
            result = write_func(str_i, str_n - str_i, user_data);
            if (result != JSON_RESULT_OK) return result;
        }

        str_i = str_n;

        if ( str_i < str_e )
        {
            unsigned char c = (unsigned char) (*str_i);

            switch(c)
            {
            case '"':       result = write_func("\\\"", 2, user_data);      break;
            case '\\':      result = write_func("\\\\", 2, user_data);      break;
            case '/':       result = write_func("\\/", 2, user_data);       break;
            case '\b':      result = write_func("\\b", 2, user_data);       break;
            case '\f':      result = write_func("\\f", 2, user_data);       break;
            case '\n':      result = write_func("\\n", 2, user_data);       break;
            case '\r':      result = write_func("\\r", 2, user_data);       break;
            case '\t':      result = write_func("\\t", 2, user_data);       break;

            default:
                {
                    unsigned long state = 0;
                    unichar_t code_point = 0;

                    for (;;)
                    {
                        decode_utf8(&state, &code_point, c);

                        if ( state == UTF8_ACCEPT )
                        {
                            char buffer[6];

                            if ( code_point > 0xFFFFul ) return JSON_RESULT_INVALID_UTF8;

                            buffer[0] = '\\';
                            buffer[1] = 'u';
                            buffer[2] = nibble_to_hex(code_point >> 12);
                            buffer[3] = nibble_to_hex(code_point >> 8);
                            buffer[4] = nibble_to_hex(code_point >> 4);
                            buffer[5] = nibble_to_hex(code_point);

                            result = write_func(buffer, 6, user_data);
                            if ( result != JSON_RESULT_OK ) return result;

                            break;
                        }
                        else if ( state == UTF8_REJECT )
                        {
                            return JSON_RESULT_INVALID_UTF8;
                        }

                        ++str_i;
                        c = *str_i;
                    }
                }
            }

            str_i++;
        }

        str_n = str_i;
    }

    result = write_func("\"", 1, user_data);
    if ( result != JSON_RESULT_OK ) return result;

    return JSON_RESULT_OK;
}


static json_result_t write_value(json_write_context_t* ctx, const json_t* value)
{
    json_result_t result;

    if ( value->type == JSON_TYPE_NULL )
    {
        return ctx->write_func("null", 4, ctx->user_data);
    }
    else if ( value->type == JSON_TYPE_BOOL )
    {
        json_bool_t b = json_get_bool(value);

        if ( b ) return ctx->write_func("true", 4, ctx->user_data);
        else return ctx->write_func("false", 5, ctx->user_data);
    }
    else if ( value->type == JSON_TYPE_NUMBER )
    {
        result = encode_number(((const json_number_node_t*) value)->value, ctx->write_func, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;
    }
    else if ( value->type == JSON_TYPE_STRING )
    {
        const char* str = ((const json_string_node_t*) value)->value;
        size_t str_len = strlen(str);

        result = encode_string(str, str_len, ctx->write_func, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;
    }
    else if ( value->type == JSON_TYPE_ARRAY )
    {
        json_array_node_t* array = (json_array_node_t*) value;
        json_t** array_i = array->members;
        json_t** array_e = array_i + array->n_members;

        result = ctx->write_func("[", 1, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;

        if ( array_i < array_e )
        {
            result = json_write(*array_i, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            array_i++;
        }

        while ( array_i < array_e )
        {
            result = ctx->write_func(", ", 2, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = json_write(*array_i, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            array_i++;
        }

        result = ctx->write_func("]", 1, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;
    }
    else if ( value->type == JSON_TYPE_OBJECT )
    {
        json_object_node_t* object = (json_object_node_t*) value;
        json_object_member_t* member = object->members;

        result = ctx->write_func("{", 1, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;

        if ( member )
        {
            const char* key = member->key;
            size_t key_len = strlen(key);

            result = encode_string(key, key_len, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = ctx->write_func(": ", 2, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = json_write(member->value, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            member = member->next;
        }

        while ( member )
        {
            const char* key = member->key;
            size_t key_len = strlen(key);

            result = ctx->write_func(", ", 2, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = encode_string(key, key_len, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = ctx->write_func(": ", 2, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            result = json_write(member->value, ctx->write_func, ctx->user_data);
            if ( result != JSON_RESULT_OK ) return result;

            member = member->next;
        }

        result = ctx->write_func("}", 1, ctx->user_data);
        if ( result != JSON_RESULT_OK ) return result;
    }
    else
    {
        return JSON_RESULT_INVALID_NODE;
    }

    return JSON_RESULT_OK;
}


json_result_t json_write(const json_t* root, json_write_func_t write_func, void* user_data)
{
    json_write_context_t ctx;

    assert(root);
    assert(write_func);

    ctx.write_func = write_func;
    ctx.user_data = user_data;

    return write_value(&ctx, root);
}
