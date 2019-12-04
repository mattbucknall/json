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

#ifndef _JSON_H_
#define _JSON_H_

#include <stddef.h>


typedef enum
{
    JSON_RESULT_OK,
    JSON_RESULT_OUT_OF_MEMORY,
    JSON_RESULT_NOT_AN_ARRAY,
    JSON_RESULT_NOT_AN_OBJECT,
    JSON_RESULT_INDEX_OUT_OF_BOUNDS,
    JSON_RESULT_TIMEOUT,
    JSON_RESULT_IO_ERROR,
    JSON_RESULT_INVALID_NODE,
    JSON_RESULT_INVALID_UTF8,
    JSON_RESULT_UNEXPECTED_END_OF_INPUT,
    JSON_RESULT_ILLEGAL_CHARACTER,
    JSON_RESULT_MAX_DEPTH_EXCEEDED,
    JSON_RESULT_UNKNOWN_KEYWORD,
    JSON_RESULT_INVALID_NUMBER,
    JSON_RESULT_STRING_TOO_LONG,
    JSON_RESULT_INVALID_ESCAPE_SEQUENCE,
    JSON_RESULT_SYNTAX_ERROR

} json_result_t;


typedef enum
{
    JSON_TYPE_NONE,
    JSON_TYPE_NULL,
    JSON_TYPE_BOOL,
    JSON_TYPE_NUMBER,
    JSON_TYPE_STRING,
    JSON_TYPE_ARRAY,
    JSON_TYPE_OBJECT

} json_type_t;


typedef enum
{
    JSON_BOOL_FALSE,
    JSON_BOOL_TRUE

} json_bool_t;


typedef float json_number_t;


typedef json_result_t (*json_read_func_t) (void* buffer, size_t size, size_t* n_read, void* user_data);

typedef json_result_t (*json_write_func_t) (const void* buffer, size_t size, void* user_data);


typedef struct json
{
    volatile int ref_count;
    json_type_t type;

} json_t;


const char* json_result_to_string(json_result_t result);

const char* json_type_to_string(json_type_t type);

json_t* json_new_null(void);

json_t* json_new_bool(json_bool_t value);

json_t* json_new_number(json_number_t value);

json_t* json_new_string(const char* value);

json_t* json_new_string_with_length(const char* value, size_t length);

json_t* json_new_string_take(char* value);

json_t* json_new_array(void);

json_t* json_new_object(void);

json_t* json_ref(json_t* value);

void json_unref(json_t* value);

json_type_t json_type(const json_t* value);

json_bool_t json_is_null(const json_t* value);

json_bool_t json_get_bool(const json_t* value);

json_number_t json_get_number(const json_t* value);

const char* json_get_string(const json_t* value);

size_t json_length(const json_t* value);

json_result_t json_append(json_t* array, json_t* value);

json_result_t json_set_with_index(json_t* array, size_t index, json_t* value);

json_t* json_get_with_index(const json_t* array, size_t index);

json_result_t json_set_with_key(json_t* object, const char* key, json_t* value);

json_result_t json_set_with_key_length(json_t* object, const char* key, size_t key_length, json_t* value);

json_result_t json_set_take_key(json_t* object, char* key, json_t* value);

json_t* json_get_with_key(const json_t* object, const char* key);

json_t* json_read(json_read_func_t read_func, void* user_data, size_t max_depth,
        size_t max_string_length, json_result_t* result);

json_result_t json_write(const json_t* root, json_write_func_t write_func, void* user_data);

#endif /* _JSON_H_ */
