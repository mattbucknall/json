#include <stdio.h>
#include <string.h>

#include <json.h>


static const char* DOC = "{\"key1\": 123, \"key2\": \"value\\u00a6\", \"key1\": 92}";
static const char* doc_i;
static const char* doc_e;


static json_result_t read_func(void* buffer, size_t length, size_t* n_read, void* user_data)
{
    size_t available = doc_e - doc_i;

    if ( length > available ) length = available;
    if ( n_read ) *n_read = length;

    memcpy(buffer, doc_i, length);
    doc_i += length;

    return JSON_RESULT_OK;
}


static json_result_t write_func(const void* buffer, size_t length, void* user_data)
{
    const char* i = buffer;
    const char* e = i + length;

    while (i < e)
    {
        putc(*i++, stdout);
    }

    return JSON_RESULT_OK;
}


int main(int argc, char* argv[])
{
    json_result_t result;
    json_t* value;

    doc_i = DOC;
    doc_e = doc_i + strlen(DOC);

    value = json_read(read_func, NULL, 4, 256, &result);

    if ( result != JSON_RESULT_OK )
    {
        printf("%s\n", json_result_to_string(result));
    }
    else
    {
        json_write(value, write_func, NULL);
        json_unref(value);
    }

    printf("\n");

    return 0;
}
