#include "1A/1A.h"
#include "1A/helper.h"


/* 错误处理 */
void digest_handleError(EVP_MD_CTX *mdctx, FILE *in, FILE *out) {
  if (!mdctx)
    EVP_MD_CTX_free(mdctx);
  if (!in)
    fclose(in);
  if (!out)
    fclose(out);
  exit(1);
}

/* 摘要实现 */
int digest(const char *algorithm, const char *input, const char *output, const char *format) {
  /* 以二进制的形式读写文件 */
  FILE *in = fopen(input, "rb"), *out = fopen(output, "wb");
  if (!(in || out))
    digest_handleError(NULL, in, out);
  int inlen;
  unsigned char inbuf[1024];

  /* 创建摘要算法 */
  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  if (!md) {
    fprintf(stderr, "ERROR, EVP_get_digestbyname %s.\n", ERR_error_string(ERR_get_error(), NULL));
    digest_handleError(NULL, in, out);
  }

  /* 创建摘要上下文 */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    fprintf(stderr, "ERROR: EVP_MD_CTX_new %s.\n", ERR_error_string(ERR_get_error(), NULL));
    digest_handleError(mdctx, in, out);
  }

  /* 标准摘要算法处理流程 */
  if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
    fprintf(stderr, "ERROR: EVP_DigestInit_ex %s.\n", ERR_error_string(ERR_get_error(), NULL));
    digest_handleError(mdctx, in, out);
  }
  
  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0) {
         break;
    }
    if (!EVP_DigestUpdate(mdctx, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_DigestUpdate %s.\n", ERR_error_string(ERR_get_error(), NULL));
      digest_handleError(mdctx, in, out);
    }
  }

  /* 读取遇到错误 */
  if (ferror(in)) {
    digest_handleError(mdctx, in, out);
  }

  /* 为摘要结果分配足够大的空间 */
  unsigned char *digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(md));
  unsigned int digest_len;
  if (!digest) {
    fprintf(stderr, "ERROR: OPENSSL_malloc %s\n", ERR_error_string(ERR_get_error(), NULL));
    digest_handleError(mdctx, in, out);
  }

  /* 将摘要结果写入到digest变量中 */
  if (!EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
    OPENSSL_free(digest);
    fprintf(stderr, "ERROR: EVP_DigestFinal_ex %s\n", ERR_error_string(ERR_get_error(), NULL));
    digest_handleError(mdctx, in, out);
  }
  // bin2other(digest, (int *)&digest_len, format);
  fwrite(digest, 1, digest_len, out);

  /* 释放内存 */
  OPENSSL_free(digest);
  EVP_MD_CTX_free(mdctx);
  fclose(in);
  fclose(out);
  return 0;
}
