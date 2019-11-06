#include "3A/3A_main.h"

/* 从pkeyfile文件中读取公钥或私钥 */
EVP_PKEY *load_key(int seal, const char *pkeyfile);
