#include "1A/my_hmac.h"

/* 错误处理 */
void my_hmac_handleError(EVP_MD_CTX *mdctx, FILE *in, FILE *out) {
  if (!mdctx)
    EVP_MD_CTX_free(mdctx);
  if (!in)
    fclose(in);
  if (!out)
    fclose(out);
  exit(1);
}

/* 创建hmac的公私钥 */
int make_keys(const char *algorithm, EVP_PKEY **skey, EVP_PKEY **vkey) {
  /* HMAC key */
  byte hkey[EVP_MAX_MD_SIZE];

  int result = -1;

  if (*skey != NULL) {
    EVP_PKEY_free(*skey);
    *skey = NULL;
  }

  if (*vkey != NULL) {
    EVP_PKEY_free(*vkey);
    *vkey = NULL;
  }

  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  int size = EVP_MD_size(md);

  int rc = RAND_bytes(hkey, size);
  if (rc != 1) {
    printf("RAND_bytes failed, error 0x%lx\n", ERR_get_error());
  }

  *skey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, size);
  *vkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, hkey, size);

  return 0;

  OPENSSL_cleanse(hkey, sizeof(hkey));

  /* Convert to 0/1 result */
  return !!result;
}

/* 消息签名 */
int sign(const char *algorithm, const char *input,
                    const char *output, const char *format) {
  /* 以二进制的形式打开文件 */
  FILE *in = fopen(input, "rb"), *out = fopen(output, "wb");
  if (!(in || out))
    my_hmac_handleError(NULL, in, out);

  /* hmac 的公私钥 */
  EVP_PKEY *skey, *vkey;
  if (!make_keys(algorithm, &skey, &vkey)) {
    fprintf(stderr, "ERROR: make_keys failed.\n ");
    exit(1);
  }

  int inlen;
  unsigned char inbuf[1024];

  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  if (!md) {
    fprintf(stderr, "ERROR: EVP_get_digestbyname failed.\n");
    exit(1);
  }

  /* 初始化摘要和签名 */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!EVP_DigestInit_ex(mdctx, md, NULL))
    my_hmac_handleError(mdctx, in, out);
  if (!EVP_DigestSignInit(mdctx, NULL, md, NULL, skey))
    my_hmac_handleError(mdctx, in, out);

  /* 对文件内容进行hmac */
  for (;;) {
    inlen = fread(inbuf, 1, 1024, in);
    if (inlen <= 0) {
      if (ferror(in)) {
        my_hmac_handleError(mdctx, in, out);
      } else {
        break;
      }
    }
    
    if (!EVP_DigestSignUpdate(mdctx, inbuf, inlen))
      my_hmac_handleError(mdctx, in, out);
  }

  unsigned char *sig;
  size_t req, sigl;
  /* 获取签名的长度 */
  if (!EVP_DigestSignFinal(mdctx, NULL, &req))
    my_hmac_handleError(mdctx, in, out);
  sig = OPENSSL_malloc(req);
  if (!sig) {
    fprintf(stderr, "ERROR: OPENSSL_malloc failed.\n");
    my_hmac_handleError(mdctx, in, out);
  }
  /* 将签名写入到文件中 */
  EVP_DigestSignFinal(mdctx, sig, &sigl);
  fwrite(sig, 1, sigl, out);

  /* 释放内存 */
  fclose(in);
  fclose(out);
  EVP_MD_CTX_free(mdctx);
  return 0;
}

int my_hmac(const char *algorithm, const char *input,
            const char *output, const char *format) {
  return sign(algorithm, input, output, format);
}
