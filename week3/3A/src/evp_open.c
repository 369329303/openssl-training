#include "3A/evp_open.h"
#include "3A/evp_helper.h"

/* 解开数字信封 */
int evp_open(const char *pkeyfile, const char *infile, const char *outfile) {
  unsigned char *encrypted_key = NULL, *iv = NULL, *inbuf = NULL, *outbuf = NULL;
  int encrypted_key_len = 0, inlen = 0, outlen = 0;
  EVP_CIPHER_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *in = NULL, *out = NULL;

  /* 从文件中读取公钥 */
  pkey = load_key(EVP_OPEN, pkeyfile);

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

  /* 读入 encrypted_key_len */
  if (0 > BIO_read(in, &encrypted_key_len, sizeof(int))) {
    fprintf(stderr, "ERROR: BIO_read %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 读入 encrypted_key */
  encrypted_key = OPENSSL_malloc(BUFSIZE);
  if (0 > BIO_read(in, encrypted_key, encrypted_key_len)) {
    fprintf(stderr, "ERROR: BIO_read %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 读入 iv */
  iv = OPENSSL_malloc(BUFSIZE);
  if (0 > BIO_read(in, iv, EVP_CIPHER_iv_length(EVP_aes_128_cbc()))) {
    fprintf(stderr, "ERROR: BIO_read %s\n",
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

  /* 初始化创建信封 */
  if (1 != EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key,
                        encrypted_key_len, iv, pkey)) {
    fprintf(stderr, "ERROR: EVP_OpenInit %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 循环从文件中读取数据 */
  inbuf = OPENSSL_malloc(BUFSIZE);
  outbuf = OPENSSL_malloc(BUFSIZE);
  for (;;) {
    inlen = BIO_read(in, inbuf, BUFSIZE);
    if (inlen <= 0)
      break;

    /* 解密信封中的数据 */
    if (1 != EVP_OpenUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_OpenUpdate %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }

    /* 将解密的数据写入到文件中 */
    if (0 > BIO_write(out, outbuf, outlen)) {
      fprintf(stderr, "ERROR: BIO_write %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }
  }

  if (0 > inlen) {
      fprintf(stderr, "ERROR: BIO_read %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
  }

  /* 处理最后的一块数据 */
  if (1 != EVP_OpenFinal(ctx, outbuf, &outlen)) {
    fprintf(stderr, "ERROR: EVP_OpenFinal %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  /*将最后一块解密的数据写入到文件中*/
  if (0 > BIO_write(out, outbuf, outlen)) {
    fprintf(stderr, "ERROR: BIO_write %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 释放内存 */
  EVP_CIPHER_CTX_free(ctx);
  OPENSSL_free(encrypted_key);
  OPENSSL_free(iv);
  OPENSSL_free(inbuf);
  OPENSSL_free(outbuf);
  BIO_free(in);
  BIO_free(out);

  return 0;
}
