#include "2B/sign.h"
#include "2B/sign_helper.h"

int sign(const char *algorithm, const char *keyfile, const char *infile,
         const char *outfile, const char *format) {
  FILE *keystm = fopen(keyfile, "rb"), *in = fopen(infile, "rb"),
       *out = fopen(outfile, "wb");
  if (!(keystm || in || out)) {
    fprintf(stderr, "ERROR: fopen %s\n", strerror(errno));
    exit(1);
  }

  /* 创建一个摘要 */
  const EVP_MD *md = EVP_get_digestbyname(algorithm);
  /* 读取私钥 */
  EVP_PKEY *key = PEM_read_PrivateKey(keystm, NULL, NULL, NULL);
  if (!key) {
    fprintf(stderr, "ERROR: PEM_read_PrivateKey %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 创建一个摘要上下文 */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    fprintf(stderr, "ERROR: EVP_MD_CTX %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 初始化摘要上下文 */
  if (1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, key)) {
    fprintf(stderr, "ERROR: EVP_DigestSignInit %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  int inlen = 0;
  unsigned char *inbuf[BUFSIZE] = {0};
  for (;;) {
    inlen = fread(inbuf, 1, BUFSIZE, in);
    if (inlen <= 0)
      break;
    /* 处理待签名的数据 */
    if (1 != EVP_DigestSignUpdate(mdctx, inbuf, inlen)) {
      fprintf(stderr, "ERROR: EVP_DigestSignUpdate %s\n",
              ERR_error_string(ERR_get_error(), NULL));
      exit(1);
    }

    if (ferror(in)) {
      fprintf(stderr, "ERROR: ferror %s\n", strerror(errno));
      exit(1);
    }
  }
  size_t sigl = 0;
  /* 获取签名的最大空间 */
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &sigl)) {
    fprintf(stderr, "ERROR: EVP_DigestSignFinal %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  unsigned char *sig = OPENSSL_malloc(sigl);
  if (!sig) {
    fprintf(stderr, "ERROR: OPENSSL_malloc %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    exit(1);
  }

  /* 获取签名 */
  if (1 != EVP_DigestSignFinal(mdctx, sig, &sigl)) {
    fprintf(stderr, "ERROR: EVP_DigestSignFinal %s\n",
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

  /* 将digest写入到文件中 */
  fwrite(nbuf, 1, nlen, out);

  OPENSSL_free(sig);
  fclose(keystm);
  fclose(in);
  fclose(out);
  return 0;
}
