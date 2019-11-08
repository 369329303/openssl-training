#include "1B/encrypt.hpp"
#include <string.h>

int my_encrypt(int enc, const char *algorithm, const unsigned char *key,
               const unsigned char *iv, const char *infile, const char *outfile,
               const char *format) {
  MY_Cipher mc;
  BIO *in = NULL, *out = NULL, *b64 = NULL, *post_in = NULL, *pre_out = NULL;
  unsigned char *inbuf = NULL, *dst = NULL, *outbuf = 0;
  int inlen = 0, outlen = 0, d = 0;

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

  dst = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  inbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  // post_in 用来存储解编码后的数据
  post_in = BIO_new(BIO_s_mem());
  if (0 == enc) {
    // 解密之前,需要解编码
    if (0 == strncmp(format, "BASE64", 6)) {
      // base64 解码
      b64 = BIO_new(BIO_f_base64());
      in = BIO_push(b64, in);
      while ((inlen = BIO_read(in, inbuf, BUFSIZE)) > 0)
        BIO_write(post_in, inbuf, inlen);
    } else if (0 == strncmp(format, "HEX", 3)) {
      // hex 解码
      while ((inlen = BIO_read(in, inbuf, BUFSIZE)) > 0) {
        hex2bin(dst, &d, inbuf, inlen);
        BIO_write(post_in, dst, d);
      }
    } else if (0 == strncmp(format, "BINARY", 6)) {
      // binary 编码,无需解码,直接复制
      while ((inlen = BIO_read(in, inbuf, BUFSIZE)) > 0)
        BIO_write(post_in, inbuf, inlen);
    }
  } else {
    // 加密操作,无需解编码,直接复制
    while ((inlen = BIO_read(in, inbuf, BUFSIZE)) > 0)
      BIO_write(post_in, inbuf, inlen);
  }

  // 加解密初始化
  mc.Init(enc, algorithm, key, iv);

  // 对数据进行加解密, pre_out 用来存储加密后的数据
  pre_out = BIO_new(BIO_s_mem());
  outbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  for (;;) {
    inlen = BIO_read(post_in, inbuf, BUFSIZE);
    if (0 >= inlen)
      break;
    mc.Update(outbuf, &outlen, inbuf, inlen);
    BIO_write(pre_out, outbuf, outlen);
  }

  // 加解密结束
  mc.Final(outbuf, &outlen);
  BIO_write(pre_out, outbuf, outlen);

  if (1 == enc) {
    // 加密后,需要编码
    if (0 == strncmp(format, "BASE64", 6)) {
      // base64 编码
      pre_out = BIO_push(pre_out, b64);
      while ((outlen = BIO_read(pre_out, outbuf, BUFSIZE)) > 0)
        BIO_write(out, outbuf, outlen);
    } else if (0 == strncmp(format, "HEX", 3)) {
      // hex 编码
      while ((outlen = BIO_read(pre_out, outbuf, BUFSIZE)) > 0) {
        bin2hex(dst, &d, outbuf, outlen);
        BIO_write(out, dst, d);
      }
    } else if (0 == strncmp(format, "BINARY", 6)) {
      // binary 编码,无需转码,直接复制
      while ((outlen = BIO_read(pre_out, outbuf, BUFSIZE)) > 0) {
        BIO_write(out, outbuf, outlen);
      }
    }
  } else {
    // 解密操作,无需转码,直接复制
    while ((outlen = BIO_read(pre_out, outbuf, BUFSIZE)) > 0) {
      BIO_write(out, outbuf, outlen);
    }
  }

  // 释放内存,关闭文件
  OPENSSL_free(inbuf);
  OPENSSL_free(dst);
  OPENSSL_free(outbuf);

  BIO_free_all(in);
  BIO_free_all(post_in);
  BIO_free_all(pre_out);
  BIO_free_all(out);
  BIO_free_all(b64);

  return 0;
}
