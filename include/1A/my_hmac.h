#include "1A/1A.h"

/* 创建签名和验证密钥 */
/* int make_keys(const char *algorithm, EVP_PKEY** skey,EVP_PKEY** vkey); */

/* 消息签名 */
int my_hmac(const char *algorithm, const char *input,
            const char *output, const char *format);
