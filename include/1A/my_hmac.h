#include "1A/1A.h"

/* 消息签名 */
int my_hmac(const char *algorithm, const unsigned char *key, const char *input,
            const char *output, const char *format);
