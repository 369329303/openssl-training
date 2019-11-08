#include "1B/1B_helper.hpp"

// hmac 实现
int my_hmac(const char *algorithm, const unsigned char *key, int keylen,
            const char *infile, const char *outfile, const char *format);
