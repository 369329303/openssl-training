#include "1B/digest.hpp"

// 摘要处理
int digest(char *algorithm, const char *infile, const char *outfile,
           const char *format) {
  MY_Digest md;
  BIO *in = NULL, *out = NULL;
  unsigned char *inbuf = NULL, *dgst = NULL,  *nbuf = NULL;
  int inlen = 0, dgst_len = 0, nlen = 0;

  // 文件读入
  in = BIO_new_file(infile, "rb");
  if (!in) {
    fprintf(stderr, "ERROR: BIO_new_file %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }
  // 文件写出
  out = BIO_new_file(outfile, "wb");
  if (!out) {
    fprintf(stderr, "ERROR: BIO_new_file %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  // 创建摘要
  md.Init(algorithm);

  inbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);

  // 对文件进行摘要处理
  for (;;) {
    inlen = BIO_read(in, inbuf, BUFSIZE);
    if (0 >= inlen)
      break;
    md.Update(inbuf, inlen);
  }

  // 获取摘要值
  dgst = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  md.Final(dgst, &dgst_len);


  // 对文件进行编码转换
  nbuf = (unsigned char *)OPENSSL_malloc(BUFSIZE);
  if (0 == strncmp(format, "HEX", 3)) {
    /* 转换为hex编码 */
    bin2hex(nbuf, &nlen, dgst, dgst_len);
  } else if (0 == strncmp(format, "BASE64", 6)) {
    /* 转换为base64编码 */
    EVP_EncodeBlock(nbuf, dgst, dgst_len);
    /* base64编码后的字节数 */
    nlen = (dgst_len / 3 + 1) * 4;
  } else if (0 == strncmp(format, "BINARY", 6)) {
    nbuf = dgst;
    nlen = dgst_len;
  } else {
    fprintf(stderr, "ERROR: WRONG FORMAT!\n");
    exit(1);
  }


  // 将进行编码转换后的摘要值写入到文件中
  BIO_write(out, nbuf, nlen);

  // 释放内存，关闭文件
  OPENSSL_free(inbuf);
  OPENSSL_free(dgst);
  OPENSSL_free(nbuf);
  BIO_free(in);
  BIO_free(out);

  return 0;
}
