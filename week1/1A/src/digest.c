#include "1A/1A.h"
#include "1A/helper.h"

/* 摘要实现 */
int digest(const char *algorithm, const char *input, const char *output,
           const char *format) {
  /* 以二进制的形式读写文件 */
  FILE *in = fopen(input, "rb"), *out = fopen(output, "wb");
  if (!(in || out)) {
    fprintf(stderr, "ERROR: fopen: %s\n", strerror(errno));
    exit(1);
  }
  int inlen = 0;
  unsigned char inbuf[1024] = {0};

  /* 创建摘要算法 */
  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  if (!md) {
    fprintf(stderr, "ERROR, EVP_get_digestbyname %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建摘要上下文 */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    fprintf(stderr, "ERROR: EVP_MD_CTX_new %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 初始化mdctx */
  if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
    fprintf(stderr, "ERROR: EVP_DigestInit_ex %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 计算目标的摘要值 */
  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0)
      break;
    if (!EVP_DigestUpdate(mdctx, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_DigestUpdate %s.\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  }

  /* 读取文件遇到错误 */
  if (ferror(in)) {
    fprintf(stderr, "ERROR: ferror: %s", strerror(errno));
    exit(1);
  }

  /* 为摘要结果分配足够大的空间 */
  unsigned char *digest = (unsigned char *)malloc(BUFSIZE);
  unsigned int digest_len = 0;

  /* 将摘要结果写入到digest变量中 */
  if (!EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
    fprintf(stderr, "ERROR: EVP_DigestFinal_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  unsigned char *nbuf = (unsigned char *)malloc(BUFSIZE);
  int nlen = 0;
  if (0 == strncmp(format, "HEX", 3)) {
    /* 转换为hex编码 */
    bin2hex(nbuf, &nlen, digest, digest_len);
  } else if (0 == strncmp(format, "BASE64", 6)) {
    /* 转换为base64编码 */
    EVP_EncodeBlock(nbuf, digest, digest_len);
    /* base64编码后的字节数 */
    nlen = (digest_len / 3 + 1) * 4;
  } else if (0 == strncmp(format, "BINARY", 6)) {
    nbuf = digest;
    nlen = digest_len;
  } else {    
    fprintf(stderr, "ERROR: WRONG FORMAT!\n");
    exit(1);
  }

  /* 将digest写入到文件中 */
  fwrite(nbuf, 1, nlen, out);

  /* 释放内存 */
  free(digest);
  free(nbuf);
  EVP_MD_CTX_free(mdctx);
  fclose(in);
  fclose(out);
  return 0;
}
