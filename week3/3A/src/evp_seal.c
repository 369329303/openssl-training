#include "3A/evp_seal.h"
#include "3A/evp_helper.h"

/* 数字信封加密 */
int evp_seal(const char *pkeyfile, const char *infile, const char *outfile) {
  unsigned char *encrypted_key = NULL, *iv = NULL, *inbuf = NULL,
                *outbuf = NULL;
  int encrypted_key_len = 0, inlen = 0, outlen = 0;
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *in = NULL, *out = NULL;

  /* 从文件中读取私钥 */
  pkey = load_key(EVP_SEAL, pkeyfile);

  /* 以BIO结构打开文件进行读入和写出 */
  in = BIO_new_file(infile, "rb");
  if (!in) {
    fprintf(stderr, "ERROR: BIO_new_file %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  out = BIO_new_file(outfile, "wb");
  if (!out) {
    fprintf(stderr, "ERROR: BIO_new_file %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建一个加密算法上下文 */
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* malloc on demand */
  encrypted_key = OPENSSL_malloc(BUFSIZE);
  iv = OPENSSL_malloc(BUFSIZE);
  /* 初始化信封 */
  if (1 != EVP_SealInit(ctx, EVP_aes_128_cbc(), &encrypted_key,
                        &encrypted_key_len, iv, &pkey, 1)) {
    fprintf(stderr, "ERROR: EVP_SealInit %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 写入 encrypted_key_len */
  if (0 > BIO_write(out, &encrypted_key_len, sizeof encrypted_key_len)) {
    fprintf(stderr, "ERROR: BIO_write %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 写入 encrypted_key */
  if (0 > BIO_write(out, encrypted_key, encrypted_key_len)) {
    fprintf(stderr, "ERROR: BIO_write %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 写入 iv */
  if (0 > BIO_write(out, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()))) {
    fprintf(stderr, "ERROR: BIO_write %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* malloc on demand */
  inbuf = OPENSSL_malloc(BUFSIZE);
  outbuf = OPENSSL_malloc(BUFSIZE);
  for (;;) {
    /* 循环从输入文件中读取数据 */
    inlen = BIO_read(in, inbuf, BUFSIZE);
    if (inlen <= 0)
      break;

    /* 将数据加密,放入到信封内 */
    if (1 != EVP_SealUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_SealUpdate %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }

    /* 写入加密数据 */
    if (0 > BIO_write(out, outbuf, outlen)) {
      fprintf(stderr, "ERROR: BIO_write %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  }

  /* 读取文件遇到错误 */
  if (0 > inlen) {
    fprintf(stderr, "ERROR: BIO_read %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 处理最后的一块数据 */
  if (1 != EVP_SealFinal(ctx, outbuf, &outlen)) {
    fprintf(stderr, "ERROR: EVP_SealFinal %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 写入最后一块加密数据到输出文件中 */
  if (0 > BIO_write(out, outbuf, outlen)) {
    fprintf(stderr, "ERROR: BIO_write %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 释放内存 */
  OPENSSL_free(encrypted_key);
  OPENSSL_free(iv);
  OPENSSL_free(inbuf);
  OPENSSL_free(outbuf);
  EVP_CIPHER_CTX_free(ctx);
  BIO_free(in);
  BIO_free(out);

  return 0;
}
