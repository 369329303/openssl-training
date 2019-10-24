#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;

/* 错误处理 */
void handleErrors(void);

/* 打印帮助信息 */
void show_help();

/* Print hexdecimal of s */
void print_hex(FILE *fp, const unsigned char *s, int len);

/* Print base64 encoded data */
void print_b64(FILE *fp, const unsigned char *s, int len);

