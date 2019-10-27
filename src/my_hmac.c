#include "1A/my_hmac.h"
#include "1A/helper.h"

/* 消息签名 */
int my_hmac(const char *algorithm, const unsigned char *key, const char *input,
            const char *output, const char *format) {
  /* 以二进制的形式打开文件 */
  FILE *in = fopen(input, "rb"), *out = fopen(output, "wb");
  if (!(in || out)) {
    fprintf(stderr, "ERROR: fopen %s\n", strerror(errno));
    exit(1);
  }

  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, 5);
  if (!pkey) {
    fprintf(stderr, "ERROR: EVP_PKEY_new_raw_private_key: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  int inlen;
  unsigned char inbuf[1024];

  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  if (!md) {
    fprintf(stderr, "ERROR: EVP_get_digestbyname %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 初始化摘要和签名 */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    fprintf(stderr, "ERROR: EVP_MD_CTX_new %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 初始化 mdctx */
  if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
    fprintf(stderr, "ERROR: EVP_DigestInit_ex %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 向mdctx中添加pkey信息 */
  if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)) {
    fprintf(stderr, "ERROR: EVP_DigestSignInit %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 对文件内容进行hmac */
  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0)
      break;
    if (!EVP_DigestSignUpdate(mdctx, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_DigestSignUpdate %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  }

  if (ferror(in)) {
    fprintf(stderr, "ERROR: ferror %s", strerror(errno));
    exit(1);
  }

  unsigned char *sig;
  size_t req, sigl;

  /* 获取签名的最大长度 */
  if (!EVP_DigestSignFinal(mdctx, NULL, &req)) {
    fprintf(stderr, "ERROR: EVP_DigestSignFinal %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  sig = OPENSSL_malloc(req);
  if (!sig) {
    fprintf(stderr, "ERROR: OPENSSL_malloc %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 获取签名及其长度 */
  if (!EVP_DigestSignFinal(mdctx, sig, &sigl)) {
    fprintf(stderr, "ERROR: EVP_DigestSignFinal %s.\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  unsigned char *nbuf = (unsigned char *)malloc(BUFSIZE);
  int nlen = 0;
  if (0 == strncmp(format, "HEX", 3)) {
    /* 转换为hex编码 */
    bin2hex(nbuf, &nlen, sig, sigl);
  } else if (0 == strncmp(format, "BASE64", 6)) {
    /* 转换为base64编码 */
    EVP_EncodeBlock(nbuf, sig, sigl);
    /* base64编码后的字节数 */
    nlen = (sigl / 3 + 1) * 4;
  } else if (0 == strncmp(format, "BINARY", 6)) {
    nbuf = sig;
    nlen = sigl;
  } else {
    fprintf(stderr, "ERROR: WRONG FORMAT!\n");
    exit(1);
  }
  /* 将签名写入到文件中 */
  fwrite(nbuf, 1, nlen, out);

  /* 释放内存 */
  free(nbuf);
  fclose(in);
  fclose(out);
  EVP_MD_CTX_free(mdctx);
  return 0;
}
