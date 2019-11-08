#include "1B/my_hmac.hpp"

// hmac 实现
int my_hmac(const char *algorithm, const unsigned char *key, int keylen, const char *infile,
            const char *outfile, const char *format) {
  BIO *in = NULL, *out = NULL;
  EVP_PKEY *pkey = NULL;
  MY_Digest md;
  unsigned char *inbuf = NULL, *sig = NULL, *nbuf = NULL;
  size_t sig_len = 0;
  int inlen = 0, nlen = 0;

  // 读入文件
  in = BIO_new_file(infile, "rb");
  if (!in) {
    fprintf(stderr, "ERROR: BIO_new_file: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  // 写出文件
  out = BIO_new_file(outfile, "wb");
  if (!out) {
    fprintf(stderr, "ERROR: BIO_new_file: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  // "签名"的私钥, 这个地方有点问题,key的长度应该和 HMAC 的 Hash 算法相关
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keylen);
  if (!pkey) {
    fprintf(stderr, "ERROR: EVP_PKEY_new_raw_private_key: %s",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  // 初始化 hmac
  md.SignInit(algorithm, pkey);

  // 更新 hmac
  inbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  for (;;) {
    inlen = BIO_read(in, inbuf, BUFSIZE);
    if (0 >= inlen)
      break;

    md.SignUpdate(inbuf, inlen);
  }

  // 结束 hmac
  sig = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  md.SignFinal(sig, &sig_len);

  // hmac 编码转换
  nbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  if (0 == strncmp(format, "HEX", 3)) {
    /* 转换为hex编码 */
    bin2hex(nbuf, &nlen, sig, sig_len);
  } else if (0 == strncmp(format, "BASE64", 6)) {
    /* 转换为base64编码 */
    EVP_EncodeBlock(nbuf, sig, sig_len);
    /* base64编码后的字节数 */
    nlen = (sig_len / 3 + 1) * 4;
  } else if (0 == strncmp(format, "BINARY", 6)) {
    nlen = sig_len;
    memcpy(nbuf, sig, sig_len);
  } else {
    fprintf(stderr, "ERROR: WRONG FORMAT!\n");
    exit(1);
  }

  // 写入签名
  BIO_write(out, nbuf, nlen);

  // 释放内存,关闭文件
  OPENSSL_free(inbuf);
  OPENSSL_free(sig);
  OPENSSL_free(nbuf);
  BIO_free(in);
  BIO_free(out);
  return 0;
}
